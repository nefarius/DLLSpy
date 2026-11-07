#include "Utils.h"

#include <cctype>
#include <cstring>
#include <set>

string sBadChar = "';:@[]()^\"$&?! ,`~=";

TCHAR* GetBinaryPath(TCHAR* cBinaryPath, const TCHAR* cPhrase)
{
    TCHAR* temp = cBinaryPath;
    cPhrase++;
    while (*cPhrase != '"' && *cPhrase != '\0')
    {
        *cBinaryPath++ = *cPhrase++;
    }

    return temp;
}

void GetDllFromToken(string& token)
{
    string sLowerCaseToken = token;
    transform(sLowerCaseToken.begin(), sLowerCaseToken.end(), sLowerCaseToken.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    const size_t index = sLowerCaseToken.find(".dll");

    //Ignore DLL, if it is in the form of  api-ms-win-eventing-provider-l1-1-0.dll, weird Microsoft rerouting to original dll
    //Ignore DLL, if it is in the form of  esi*.dll, too many options
    if (index == string::npos ||
        (count(sLowerCaseToken.begin(), sLowerCaseToken.end(), '-') > 3) ||
        (count(sLowerCaseToken.begin(), sLowerCaseToken.end(), '\\') == 1) ||
        (sLowerCaseToken.find('*') != string::npos) ||
        (sLowerCaseToken.find("% ") != string::npos) ||
        (sLowerCaseToken.find(".text") != string::npos) ||
        (sLowerCaseToken.find(".library") != string::npos)
    )
    {
        token = "";

        return;
    }
    token = token.substr(0, (index + strlen(".dll")));
    GetCanonicalDllName(token);
    token = ExpandPath(token);
    if (token.find('%') != string::npos)
        token = "";
}

void GetCanonicalDllName(string& token)
{
    const size_t index = token.find("%s");

    if ((count(token.begin(), token.end(), '\\') > 1) && index != string::npos)
        token = token.substr(0, index + 1);
    TrimString(token);
}

string ExpandPath(const string& sPath)
{
    TCHAR sCanonicalPath[FULL_PATH_SIZE] = {0};
    const DWORD dwSize = ExpandEnvironmentStrings(sPath.c_str(), sCanonicalPath, FULL_PATH_SIZE);

    return dwSize < FULL_PATH_SIZE ? string(sCanonicalPath) : sPath;
}

void TrimString(string& token)
{
    for (int rIndex = static_cast<int>(token.length()) - 1; rIndex >= 0; rIndex--)
    {
        for (const char j : sBadChar)
        {
            if (token[rIndex] == j)
            {
                token = token.substr(rIndex + 1);
                return;
            }
        }
    }
}


string GetDirPath(const string& fullPath)
{
    const size_t uLastIndex = fullPath.rfind('\\');

    return string::npos != uLastIndex ? fullPath.substr(0, uLastIndex) : string();
}

string BaseName(const string& sFullPath)
{
    const auto index = sFullPath.find_last_of("\\/");
    return index == string::npos ? sFullPath : sFullPath.substr(index + 1);
}

string ToLowerCopy(const string& sValue)
{
    string sLower = sValue;
    transform(sLower.begin(), sLower.end(), sLower.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return sLower;
}

static bool EndsWithDll(const string& sLowerName)
{
    return sLowerName.size() >= 4 && sLowerName.compare(sLowerName.size() - 4, 4, ".dll") == 0;
}

bool IsPlausibleDllName(const string& sName)
{
    const string sBaseName = BaseName(sName);
    if (sBaseName.size() < 6 || sBaseName.size() > 250)
        return false;

    const string sLowerName = ToLowerCopy(sBaseName);
    if (sLowerName == "dll.dll" || !EndsWithDll(sLowerName))
        return false;

    const string sStem = sBaseName.substr(0, sBaseName.size() - 4);
    if (sStem.size() < 2 || !isalnum(static_cast<unsigned char>(sStem[0])))
        return false;

    for (const char ch : sStem)
    {
        const auto c = static_cast<unsigned char>(ch);
        if (!isalnum(c) && c != '_' && c != '.' && c != '-')
            return false;
    }

    return true;
}

static const set<string>& KnownDllNames()
{
    static set<string> names;
    static bool bLoaded = false;
    if (bLoaded)
        return names;

    bLoaded = true;
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            R"(SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs)",
            0,
            KEY_READ,
            &hKey) != ERROR_SUCCESS)
        return names;

    for (DWORD dwIndex = 0;;)
    {
        char cValueName[256];
        BYTE data[512];
        DWORD dwNameSize = sizeof(cValueName);
        DWORD dwDataSize = sizeof(data);
        DWORD dwType = 0;
        const LONG lResult = RegEnumValueA(hKey, dwIndex, cValueName, &dwNameSize, nullptr, &dwType, data, &dwDataSize);
        if (lResult == ERROR_MORE_DATA)
        {
            ++dwIndex;
            continue;
        }
        if (lResult != ERROR_SUCCESS)
            break;

        ++dwIndex;
        if (dwType != REG_SZ || dwDataSize == 0)
            continue;

        const auto text = reinterpret_cast<const char*>(data);
        const string sLowerName = ToLowerCopy(string(text, strnlen(text, dwDataSize)));
        if (EndsWithDll(sLowerName))
            names.insert(sLowerName);
    }

    RegCloseKey(hKey);
    return names;
}

bool IsIgnoredDll(const string& sName)
{
    const string sLowerName = ToLowerCopy(BaseName(sName));
    if (sLowerName.rfind("api-ms-", 0) == 0 || sLowerName.rfind("ext-ms-", 0) == 0)
        return true;

    const set<string>& known = KnownDllNames();
    return known.find(sLowerName) != known.end();
}

bool CompareStrings(const string& s1, const string& s2)
{
    if (s1.size() != s2.size())
        return false;
    for (unsigned int i = 0; i < s1.size(); ++i)
    {
        if (tolower(static_cast<unsigned char>(s1[i])) != tolower(static_cast<unsigned char>(s2[i])))
            return false;
    }
    return true;
}
