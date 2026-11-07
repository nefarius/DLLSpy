#include "DLLSpy.h"
#include "Impersonation.h"
#include "Utils.h"
#include "ServiceRegistry.h"
#include "general.h"
#include "StringsExtractor.h"
#include "PeImports.h"

#include <cctype>
#include <cstdlib>
#include <utility>


string sSystemPaths[] = {"C:\\Windows\\System32", "C:\\Windows\\System", "C:\\Windows"};

unsigned char READABLE_CHARACTERS[90] =
    "'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+=-`{}[]:;,.? ";

static string TrimTrailingSeparators(string sPath)
{
    while (!sPath.empty() && (sPath.back() == '\\' || sPath.back() == '/'))
        sPath.pop_back();
    return sPath;
}

static int ContextRank(const ProcessContext& context)
{
    if (!context.bSameUser)
        return 2;
    if (context.bElevated)
        return 1;
    return 0;
}

static string ContextKey(const string& sPath)
{
    return ToLowerCopy(sPath);
}

void RememberBinaryContext(PProcessContainer p, const string& sPath, const ProcessContext& context)
{
    const string key = ContextKey(sPath);
    const auto it = p->mBinaryContext.find(key);
    if (it == p->mBinaryContext.end() || ContextRank(context) > ContextRank(it->second))
        p->mBinaryContext[key] = context;
}

static ProcessContext LookupBinaryContext(PProcessContainer p, const string& sPath)
{
    const auto it = p->mBinaryContext.find(ContextKey(sPath));
    if (it != p->mBinaryContext.end())
        return it->second;

    ProcessContext context;
    context.bElevated = true;
    context.bSameUser = false;
    context.sUserName = "unknown";
    return context;
}

static bool SkipProcess(PProcessContainer p, const ProcessContext& context)
{
    return !p->bIncludeAll && IsUnprivilegedContext(context);
}

static void MergeProcessData(PProcessContainer p, ProcessData& pData)
{
    if (pData.vsDLLs.empty())
        return;

    auto it = BinaryExists(p, pData.sBinaryPath);
    if (it == p->vProcessData.end())
    {
        p->vProcessData.push_back(pData);
        return;
    }

    it->vsDLLs.insert(pData.vsDLLs.begin(), pData.vsDLLs.end());

    ProcessContext existing;
    existing.bElevated = it->bElevated;
    existing.bSameUser = it->bSameUser;
    ProcessContext incoming;
    incoming.bElevated = pData.bElevated;
    incoming.bSameUser = pData.bSameUser;
    if (ContextRank(incoming) > ContextRank(existing))
    {
        it->sUserName = pData.sUserName;
        it->sDomainName = pData.sDomainName;
        it->bElevated = pData.bElevated;
        it->bSameUser = pData.bSameUser;
    }
}

static string SourceName(DllRefSource eSource)
{
    switch (eSource)
    {
    case DllRefSource::DelayImport:
        return "delay-import";
    case DllRefSource::String:
        return "string";
    case DllRefSource::Import:
    default:
        return "import";
    }
}

static bool IsAbsolutePath(const string& sPath)
{
    if (sPath.size() >= 3 && isalpha(static_cast<unsigned char>(sPath[0])) != 0 && sPath[1] == ':' &&
        (sPath[2] == '\\' || sPath[2] == '/'))
        return true;

    return sPath.rfind("\\\\", 0) == 0;
}

static bool ExistsInSystemPaths(const string& sDllName)
{
    for (auto& sSystemPath : sSystemPaths)
    {
        const string sSystemDll = string(sSystemPath) + "\\" + sDllName;
        if (PathFileExistsA(sSystemDll.c_str()))
            return true;
    }
    return false;
}

class WritabilityCache
{
public:
    explicit WritabilityCache(HANDLE token) : hToken(token)
    {
    }

    bool IsWritable(const string& sDirectory)
    {
        const string key = ToLowerCopy(TrimTrailingSeparators(sDirectory));
        const auto it = cache.find(key);
        if (it != cache.end())
            return it->second;

        BOOL bAllowed = FALSE;
        if (!key.empty())
            CanAccessDirectory(sDirectory.c_str(), GENERIC_WRITE, &hToken, &bAllowed);

        const bool bWritable = bAllowed == TRUE;
        cache[key] = bWritable;
        return bWritable;
    }

private:
    HANDLE hToken;
    map<string, bool> cache;
};

static vector<string> GetMachinePathDirectories()
{
    vector<string> directories;
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            R"(SYSTEM\CurrentControlSet\Control\Session Manager\Environment)",
            0,
            KEY_READ,
            &hKey) != ERROR_SUCCESS)
        return directories;

    DWORD dwType = 0;
    DWORD dwSize = 0;
    const LONG lSizeResult = RegQueryValueExA(hKey, "Path", nullptr, &dwType, nullptr, &dwSize);
    if ((lSizeResult != ERROR_SUCCESS && lSizeResult != ERROR_MORE_DATA) || dwSize == 0)
    {
        RegCloseKey(hKey);
        return directories;
    }

    string buffer(dwSize, '\0');
    if (RegQueryValueExA(hKey, "Path", nullptr, &dwType, reinterpret_cast<LPBYTE>(buffer.data()), &dwSize) ==
        ERROR_SUCCESS)
    {
        const auto end = buffer.find('\0');
        if (end != string::npos)
            buffer.resize(end);

        buffer = ExpandPath(buffer);
        string directory;
        for (const char ch : buffer)
        {
            if (ch == ';')
            {
                directory = TrimTrailingSeparators(directory);
                if (!directory.empty())
                    directories.push_back(directory);
                directory.clear();
            }
            else
                directory.push_back(ch);
        }

        directory = TrimTrailingSeparators(directory);
        if (!directory.empty())
            directories.push_back(directory);
    }

    RegCloseKey(hKey);
    return directories;
}

// Search PATH in order. An earlier non-writable directory that already contains the DLL wins.
static string FindPlantablePathDirectory(const string& sDllName, const vector<string>& pathDirs, WritabilityCache& cache)
{
    for (const auto& directory : pathDirs)
    {
        if (cache.IsWritable(directory))
            return directory;

        const string candidate = directory + "\\" + sDllName;
        if (PathFileExistsA(candidate.c_str()))
            return {};
    }
    return {};
}

static void AddReference(vector<ImportRef>& refs, const string& sName, DllRefSource eSource)
{
    if (sName.empty() || !IsPlausibleDllName(sName) || IsIgnoredDll(sName))
        return;

    for (const auto& existing : refs)
    {
        if (_stricmp(existing.sName.c_str(), sName.c_str()) == 0)
            return;
    }

    refs.push_back(ImportRef{sName, eSource});
}

static void CollectStringReferences(const string& sBinary, vector<ImportRef>& refs)
{
    StringsExtractor extractor;
    long lOutputSize = 0;
    string sRawOutput;
    char* extracted = extractor.GenerateStrings(READABLE_CHARACTERS, sBinary.c_str(), 6, "\n", &lOutputSize, sRawOutput);
    if (extracted == nullptr)
        return;

    sRawOutput.assign(extracted, extracted + lOutputSize);
    free(extracted);

    string token;
    istringstream tokenStream(sRawOutput);
    while (getline(tokenStream, token, '\n'))
    {
        GetDllFromToken(token);
        GetDllFromToken(token);
        if (!token.empty())
            AddReference(refs, token, DllRefSource::String);
    }
}

int _tmain(int argc, TCHAR* argv[])
{
    ESTATUS eReturn = ESTATUS_INVALID;

    if (!IsUserAnAdmin())
    {
        cerr << "DLLSpy must be activated with elevated privileges, shutting down." << endl;
        goto lblCleanup;
    }
    eReturn = ParseCommandLineArguments(argc, argv);

lblCleanup:
    if (ESTATUS_FAILED(eReturn) && eReturn != ESTATS_MISSING_ARGUMENTS)
        cerr << "DLLSpy exited with error: " << eReturn << endl;
    return 0;
}

ESTATUS ParseCommandLineArguments(int argc, TCHAR* argv[])
{
    string sOutputPath;
    bool bDynamic = false;
    bool bStatic = false;
    bool bRecursive = false;
    bool bIncludeAll = false;
    bool bStrings = false;
    DWORD dwRecursionLevel = 0;
    ESTATUS eReturn = ESTATS_MISSING_ARGUMENTS;

    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            if (!_stricmp(argv[i], "-o"))
            {
                if (argv[i + 1] != nullptr)
                    sOutputPath = string(argv[i + 1]);
                else
                {
                    eReturn = ESTATS_MISSING_ARGUMENTS;
                    goto lblCleanup;
                }
            }

            else if (!_stricmp(argv[i], "-s"))
                bStatic = true;
            else if (!_stricmp(argv[i], "-d"))
                bDynamic = true;
            else if (!_stricmp(argv[i], "-a"))
                bIncludeAll = true;
            else if (!_stricmp(argv[i], "-t"))
                bStrings = true;

            else if (!_stricmp(argv[i], "-r"))
            {
                if (argv[i + 1] != nullptr)
                {
                    int command_level = *argv[i + 1];
                    if (!isdigit(command_level))
                        goto lblCleanup;
                    bRecursive = true;
                    dwRecursionLevel = command_level - 0x30;
                }
                else
                    goto lblCleanup;
            }
        }
        if (!bDynamic || (bStrings && !bStatic))
        {
            eReturn = ESTATS_MISSING_ARGUMENTS;
            goto lblCleanup;
        }

        eReturn = FindDllHijacking(sOutputPath, bStatic, bRecursive, dwRecursionLevel, bIncludeAll, bStrings);
    }

lblCleanup:
    if (eReturn == ESTATS_MISSING_ARGUMENTS)
    {
        cerr << "Usage: DLLSPY.exe" << endl;
        cerr << "-d [mandatory] Find DLL hijacking in all running processes and services." << endl;
        cerr << "-s [optional] Read import and delay-import tables of running processes and services." << endl;
        cerr << "-t [optional] Also scan binaries for DLL name strings. Requires -s." << endl;
        cerr << "-a [optional] Include processes running unelevated as the current user." << endl;
        cerr << "-r n [optional] Recursion search for DLL references in found DLL files previous scan." << endl <<
            "   n is the number is the level of the recursion" << endl;
    }
    return eReturn;
}

ESTATUS FindDllHijacking([[maybe_unused]] string OutputPath, bool bStatic, bool bRecrusive, DWORD level,
                         bool bIncludeAll, bool bStrings)
{
    ESTATUS eReturn = ESTATUS_INVALID;
    auto p = ProcessContainer();
    p.bIncludeAll = bIncludeAll;
    p.bStrings = bStrings;

    cerr << "Start analyzing processes dynamically" << endl;

    eReturn = EnumerateRunningProcesses(&p);

    cerr << endl;
    cerr << "Done looking for dynamic processes hijacking" << endl;
    cerr << "======================================================================================" << endl;

    if (bStatic)
    {
        cerr << "Start analyzing processes executables, static analysis" << endl;

        eReturn = EnumerateProcessesBinaries(&p);

        cerr << endl;
        cerr << "Done looking for static executables hijacking" << endl;
        cerr << "=================================================================================" << endl;
    }

    if (bRecrusive && level < 5)
    {
        cerr << "Start Recursive search" << endl;

        eReturn = RecursiveEnumeration(&p, level);

        cerr << endl;
        cerr << "Done looking for Recursive Extraction" << endl;
        cerr << "=================================================================================" << endl;
    }

    printAsJSON(&p);

    return eReturn;
}

ESTATUS EnumerateRunningProcesses(PProcessContainer p)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry;
    MODULEENTRY32 moduleEntry;
    HANDLE hImpersonatedToken = nullptr;
    const TCHAR* processName = _T("explorer.exe");
    ESTATUS eReturn = ESTATUS_INVALID;
    string sUserName;
    string sDomainName;

    eReturn = GetImpersonatedToken(&hImpersonatedToken, processName);
    if (hImpersonatedToken == nullptr || ESTATUS_FAILED(eReturn))
        goto lblCleanup;

    eReturn = GetLogonFromToken(hImpersonatedToken, sUserName, sDomainName);
    p->sReferenceUser = sUserName;
    p->sReferenceDomain = sDomainName;

    processEntry.dwSize = sizeof(PROCESSENTRY32);
    if (hSnapshot == INVALID_HANDLE_VALUE || !Process32First(hSnapshot, &processEntry))
        goto lblCleanup;

    while (Process32Next(hSnapshot, &processEntry))
    {
        HANDLE moduleSnapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processEntry.th32ProcessID);
        if (moduleSnapshot == INVALID_HANDLE_VALUE)
            continue;

        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(moduleSnapshot, &moduleEntry))
        {
            CloseHandle(moduleSnapshot);
            continue;
        }

        ProcessContext context;
        if (ESTATUS_FAILED(GetProcessContext(processEntry.th32ProcessID, hImpersonatedToken, context)))
        {
            context.bSameUser = false;
            context.bElevated = true;
            if (context.sUserName.empty())
                context.sUserName = "unknown";
        }

        const string sProcessPath = moduleEntry.szExePath;
        RememberBinaryContext(p, sProcessPath, context);

        if (SkipProcess(p, context))
        {
            CloseHandle(moduleSnapshot);
            continue;
        }

        const string sProcessName = processEntry.szExeFile;
        p->vsProcessBinary.insert(sProcessPath);
        auto pData = ProcessData(sProcessPath, context);

        while (Module32Next(moduleSnapshot, &moduleEntry))
        {
            eReturn = ESTATUS_SUCCESS;
            const auto sModuleName = string(moduleEntry.szExePath);
            if (!IsPlausibleDllName(sModuleName) || IsIgnoredDll(sModuleName))
                continue;

            const string sExeDirPath = GetDirPath(sModuleName);
            bool isSecureDir = false;

            for (auto& sSystemPath : sSystemPaths)
            {
                if (CompareStrings(sExeDirPath, sSystemPath))
                {
                    isSecureDir = true;
                    break;
                }
            }
            if (!isSecureDir)
            {
                BOOL bDirAccessAllowed = FALSE;
                BOOL bFileAllowed = FALSE;

                CanAccessDirectory(sExeDirPath.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bDirAccessAllowed);
                CanAccessDirectory(sModuleName.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bFileAllowed);

                if (bDirAccessAllowed && bFileAllowed)
                {
                    auto dData = DLLData(sModuleName, "high", "low", true, "loaded", sExeDirPath);
                    pData.vsDLLs.insert(dData);
                    if (DEBUG_PRINT)
                    {
                        cerr << "high Severity in process: " << sProcessName.c_str() << "\tDLL: " << sModuleName.c_str()
                            << endl;
                    }
                }
            }
        }

        CloseHandle(moduleSnapshot);
        MergeProcessData(p, pData);
    }

lblCleanup:
    if (hSnapshot != nullptr && hSnapshot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapshot);
    if (hImpersonatedToken != nullptr)
        CloseHandle(hImpersonatedToken);

    return eReturn;
}

ESTATUS EnumerateProcessesBinaries(PProcessContainer p)
{
    ESTATUS eReturn = ESTATUS_INVALID;
    eReturn = EnumerateServicesFromRegistry(p);
    if (eReturn != ESTATUS_SUCCESS)
        goto lblCleanup;
    eReturn = GetServicesDLLs(p);
    if (eReturn != ESTATUS_SUCCESS)
        goto lblCleanup;
    eReturn = GetHijackedDirectories(p);

    p->sGlobalBinaries.insert(p->vsProcessBinary.begin(), p->vsProcessBinary.end());


lblCleanup:

    return eReturn;
}

ESTATUS RecursiveEnumeration(PProcessContainer p, DWORD level)
{
    ESTATUS eReturn = ESTATUS_INVALID;

    for (size_t i = 0; i < level; ++i)
    {
        RecursiveChecking(p);
        p->msvStaticProcessMap.clear();

        eReturn = GetServicesDLLs(p);
        if (eReturn != ESTATUS_SUCCESS)
            goto lblCleanup;

        eReturn = GetHijackedDirectories(p);
        p->sGlobalBinaries.insert(p->vsProcessBinary.begin(), p->vsProcessBinary.end());
    }

lblCleanup:
    return eReturn;
}

ESTATUS GetServicesDLLs(PProcessContainer p)
{
    for (const auto& sBinary : p->vsProcessBinary)
    {
        vector<ImportRef> parsed;
        GetPeImports(sBinary, parsed);

        vector<ImportRef> accepted;
        for (const auto& ref : parsed)
            AddReference(accepted, ref.sName, ref.eSource);

        if (p->bStrings)
            CollectStringReferences(sBinary, accepted);

        if (!accepted.empty())
            p->msvStaticProcessMap[sBinary] = std::move(accepted);
    }

    return ESTATUS_SUCCESS;
}

ESTATUS GetHijackedDirectories(PProcessContainer p)
{
    HANDLE hImpersonatedToken = nullptr;
    const TCHAR* sProcessName = _T("explorer.exe");
    ESTATUS eReturn = GetImpersonatedToken(&hImpersonatedToken, sProcessName);
    if (ESTATUS_FAILED(eReturn) || hImpersonatedToken == nullptr)
    {
        if (hImpersonatedToken != nullptr)
            CloseHandle(hImpersonatedToken);
        return eReturn;
    }

    string sUserName;
    string sDomainName;
    eReturn = GetLogonFromToken(hImpersonatedToken, sUserName, sDomainName);
    if (p->sReferenceUser.empty())
    {
        p->sReferenceUser = sUserName;
        p->sReferenceDomain = sDomainName;
    }

    WritabilityCache cache(hImpersonatedToken);
    const vector<string> pathDirs = GetMachinePathDirectories();

    eReturn = ESTATUS_SUCCESS;
    for (auto& map_iter : p->msvStaticProcessMap)
    {
        const string ProcessPath = map_iter.first;
        const ProcessContext context = LookupBinaryContext(p, ProcessPath);
        if (SkipProcess(p, context))
            continue;

        const string sAppDir = TrimTrailingSeparators(GetDirPath(ProcessPath));
        auto pData = ProcessData(ProcessPath, context);

        for (const auto& ref : map_iter.second)
        {
            const string& sDllName = ref.sName;
            if (sDllName.empty())
                continue;

            const string sSource = SourceName(ref.eSource);
            string sWritableDir;
            string sSeverity;
            bool bExist = false;

            if (IsAbsolutePath(sDllName))
            {
                if (PathFileExistsA(sDllName.c_str()))
                    continue;

                const string directory = GetDirPath(sDllName);
                if (directory.empty() || !cache.IsWritable(directory))
                    continue;

                sWritableDir = directory;
                sSeverity = "high";
            }
            else if (!sAppDir.empty() && PathFileExistsA((sAppDir + "\\" + sDllName).c_str()))
            {
                if (!cache.IsWritable(sAppDir))
                    continue;

                sWritableDir = sAppDir;
                sSeverity = "high";
                bExist = true;
            }
            else if (ExistsInSystemPaths(sDllName))
            {
                continue;
            }
            else if (!sAppDir.empty() && cache.IsWritable(sAppDir))
            {
                sWritableDir = sAppDir;
                sSeverity = "high";
            }
            else
            {
                sWritableDir = FindPlantablePathDirectory(sDllName, pathDirs, cache);
                if (sWritableDir.empty())
                    continue;
                sSeverity = "medium";
            }

            pData.vsDLLs.insert(DLLData(sDllName, sSeverity, "low", bExist, sSource, sWritableDir));
        }

        MergeProcessData(p, pData);
    }

    CloseHandle(hImpersonatedToken);
    return eReturn;
}

void RecursiveChecking(PProcessContainer p)
{
    p->vsProcessBinary.clear();

    for (auto& map_iter : p->msvStaticProcessMap)
    {
        const string ProcessPath = map_iter.first;
        const string sAppDir = TrimTrailingSeparators(GetDirPath(ProcessPath));
        const ProcessContext parent = LookupBinaryContext(p, ProcessPath);

        for (const auto& ref : map_iter.second)
        {
            const string& sDllName = ref.sName;
            string sDefinedDLLPath;

            if (PathFileExistsA(sDllName.c_str()))
                sDefinedDLLPath = sDllName;
            else if (!sAppDir.empty() && PathFileExistsA((sAppDir + "\\" + sDllName).c_str()))
                sDefinedDLLPath = sAppDir + "\\" + sDllName;
            else
            {
                for (auto& sSystemPath : sSystemPaths)
                {
                    const string sSystemDll = string(sSystemPath) + "\\" + sDllName;
                    if (PathFileExistsA(sSystemDll.c_str()))
                    {
                        sDefinedDLLPath = sSystemDll;
                        break;
                    }
                }
            }

            if (!sDefinedDLLPath.empty() && p->sGlobalBinaries.find(sDefinedDLLPath) == p->sGlobalBinaries.end())
            {
                p->vsProcessBinary.insert(sDefinedDLLPath);
                RememberBinaryContext(p, sDefinedDLLPath, parent);
            }
        }
    }
}

vector<ProcessData>::iterator BinaryExists(PProcessContainer p, string sBinaryPath)
{
    for (auto it = p->vProcessData.begin(); it != p->vProcessData.end(); ++it)
    {
        if (_stricmp((*it).sBinaryPath.c_str(), sBinaryPath.c_str()) == 0)
            return it;
    }

    return p->vProcessData.end();
}

void printAsJSON(PProcessContainer p)
{
    Json::Value entry;

    BeautifyAsJSON(entry, p);

    Json::StyledWriter styledWriter;
    std::cout << styledWriter.write(entry);
}

string GetFilename(string sFullPath)
{
    const auto index = sFullPath.rfind('\\');
    if (index != string::npos)
        sFullPath = sFullPath.substr(index + 1, sFullPath.length());
    return sFullPath;
}

void BeautifyAsJSON(Json::Value& node, PProcessContainer p)
{
    for (auto& it : p->vProcessData)
    {
        Json::Value entry;

        const string sFileName = GetFilename(it.sBinaryPath);

        entry["application"] = sFileName;
        entry["path"] = it.sBinaryPath;
        entry["user"] = it.sUserName;
        entry["elevated"] = it.bElevated;
        entry["sameUser"] = it.bSameUser;

        for (const auto& j : it.vsDLLs)
        {
            Json::Value module;
            module["path"] = j.sBinaryPath;
            module["severity"] = j.sServirity;
            module["source"] = j.sSource;
            if (!j.sWritableDir.empty())
                module["writableDir"] = j.sWritableDir;

            entry["modules"].append(module);
        }

        node.append(entry);
    }
}
