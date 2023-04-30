#include "Utils.h"

string sBadChar = "';:@[]()^\"$&?! ";

TCHAR* GetBinaryPath(TCHAR* cBinaryPath, const TCHAR* cPhrase)
{
    TCHAR* temp = cBinaryPath;
    size_t length = 0;
    cPhrase++;
    while (*cPhrase != '"' && *cPhrase != '\0')
    {
        length++;
        *cBinaryPath++ = *cPhrase++;
    }

    return temp;
}

void GetDllFromToken(string& token)
{
    string sLowerCaseToken = token;
    transform(sLowerCaseToken.begin(), sLowerCaseToken.end(), sLowerCaseToken.begin(), tolower);
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

bool CompareStrings(const string& s1, const string& s2)
{
    if (s1.size() != s2.size())
        return false;
    for (unsigned int i = 0; i < s1.size(); ++i)
    {
        if (tolower(s1[i]) != tolower(s2[i]))
            return false;
    }
    return true;
}
