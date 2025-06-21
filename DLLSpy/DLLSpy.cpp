#include "DLLSpy.h"
#include "Impersonation.h"
#include "Utils.h"
#include "ServiceRegistry.h"
#include "general.h"
#include "StringsExtractor.h"


string sSystemPaths[] = {"C:\\Windows\\System32", "C:\\Windows\\System", "C:\\Windows"};

unsigned char READABLE_CHARACTERS[90] =
    "'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+=-`{}[]:;,.? ";

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
    string sOutputPath = "";
    bool bDynamic = false;
    bool bStatic = false;
    bool bRecursive = false;
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
        if (bDynamic == false)
        {
            eReturn = ESTATS_MISSING_ARGUMENTS;
            goto lblCleanup;
        }

        eReturn = FindDllHijacking(sOutputPath, bStatic, bRecursive, dwRecursionLevel);
    }

lblCleanup:
    if (eReturn == ESTATS_MISSING_ARGUMENTS)
    {
        cerr << "Usage: DLLSPY.exe" << endl;
        cerr << "-d [mandatory] Find DLL hijacking in all running processes and services." << endl;
        cerr << "-s [optional] Search for DLL references in the binary files of current running processes and services."
            << endl;
        cerr << "-r n [optional] Recursion search for DLL references in found DLL files previous scan." << endl <<
            "   n is the number is the level of the recursion" << endl;
    }
    return eReturn;
}

ESTATUS FindDllHijacking(string OutputPath, bool bStatic, bool bRecrusive, DWORD level)
{
    ESTATUS eReturn = ESTATUS_INVALID;
    auto p = ProcessContainer();

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
    TCHAR* processName = _T("explorer.exe");
    ESTATUS eReturn = ESTATUS_INVALID;
    string sUserName;
    string sDomainName;

    //Impersonate explorer.exe token in order to preform access check with week privileges
    eReturn = GetImpersonatedToken(&hImpersonatedToken, processName);
    if (hImpersonatedToken == nullptr || ESTATUS_FAILED(eReturn))
    {
        goto lblCleanup;
    }
    eReturn = GetLogonFromToken(hImpersonatedToken, sUserName, sDomainName);

    processEntry.dwSize = sizeof(PROCESSENTRY32);
    // System Process
    Process32First(hSnapshot, &processEntry);

    while (Process32Next(hSnapshot, &processEntry))
    {
        HANDLE moduleSnapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processEntry.th32ProcessID);
        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        Module32First(moduleSnapshot, &moduleEntry);
        if (moduleSnapshot == INVALID_HANDLE_VALUE)
        {
            continue;
        }

        string sProcessName = processEntry.szExeFile;
        string sProcessDir = GetDirPath(sProcessName);
        string sProcessPath = moduleEntry.szExePath;
        p->vsProcessBinary.insert(sProcessPath);

        auto pData = ProcessData(sProcessPath, sUserName, sDomainName);

        while (Module32Next(moduleSnapshot, &moduleEntry))
        {
            eReturn = ESTATUS_SUCCESS;
            moduleEntry.dwSize = sizeof(MODULEENTRY32);

            auto sModuleName = string(moduleEntry.szExePath);

            string sExeDirPath = GetDirPath(sModuleName);
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
                // Check if current logged on user is able has write permission to directory, if so we can hijack a dll there
                BOOL bDirAccessAllowed = FALSE;
                BOOL bFileAllowed = FALSE;

                CanAccessDirectory(sExeDirPath.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bDirAccessAllowed);
                CanAccessDirectory(sModuleName.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bFileAllowed);

                if (bDirAccessAllowed && bFileAllowed)
                {
                    auto dData = DLLData(sModuleName, "high", "low", true);
                    pData.vsDLLs.insert(dData);
                    if (DEBUG_PRINT)
                    {
                        cerr << "high Severity in process: " << sProcessName.c_str() << "\tDLL: " << sModuleName.c_str()
                            << endl;
                        cerr << sUserName.c_str() << "," << "high," << "Yes, " << sProcessName.c_str() << "," <<
                            sModuleName.c_str() << endl;
                    }
                }
            }
        }
        if (!pData.vsDLLs.empty())
        {
            auto it = BinaryExists(p, pData.sBinaryPath);
            if (it != p->vProcessData.end())
                it->vsDLLs.insert(pData.vsDLLs.begin(), pData.vsDLLs.end());
            else
                p->vProcessData.push_back(pData);
        }
    }

lblCleanup:
    if (hSnapshot != nullptr)
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
    ESTATUS eReturn = ESTATUS_INVALID;
    StringsExtractor m;
    long lOutputSize;
    for (const auto& sServiceName : p->vsProcessBinary)
    {
        string sRawOutput;
        char* a = m.GenerateStrings(READABLE_CHARACTERS, const_cast<char*>(sServiceName.c_str()), 6, "\n", &lOutputSize,
                                    sRawOutput);
        sRawOutput = string(&a[0], &a[lOutputSize]);
        free(a);

        string token;
        istringstream tokenStream(sRawOutput);
        while (getline(tokenStream, token, '\n'))
        {
            //Double filtering, make sure we don't have any weird characters
            GetDllFromToken(token);
            GetDllFromToken(token);

            if (token.compare(""))
                if (find(p->msvStaticProcessMap[sServiceName].begin(), p->msvStaticProcessMap[sServiceName].end(),
                         token) == p->msvStaticProcessMap[sServiceName].end())
                {
                    p->msvStaticProcessMap[sServiceName].push_back(token);
                }
        }
    }
    eReturn = ESTATUS_SUCCESS;
    return eReturn;
}

ESTATUS GetHijackedDirectories(PProcessContainer p)
{
    HANDLE hImpersonatedToken = nullptr;
    TCHAR* sProcessName = _T("explorer.exe");
    ESTATUS eReturn = ESTATUS_INVALID;
    string sUserName;
    string sDomainName;

    eReturn = GetImpersonatedToken(&hImpersonatedToken, sProcessName);
    if (ESTATUS_FAILED(eReturn))
        goto lblCleanup;
    eReturn = GetLogonFromToken(hImpersonatedToken, sUserName, sDomainName);


    eReturn = ESTATUS_SUCCESS;
    for (auto& map_iter : p->msvStaticProcessMap)
    {
        BOOL bExist = FALSE;
        string ProcessPath = map_iter.first;
        string sProcessDir = GetDirPath(ProcessPath) + "\\";
        auto pData = ProcessData(map_iter.first, sUserName, sDomainName);

        for (const auto& sDllName : map_iter.second)
        {
            BOOL isSecureDir = FALSE;
            string sOptionalDllPath = sProcessDir + sDllName;
            auto dData = DLLData();
            BOOL bDirAccessAllowed = FALSE;
            BOOL bFileAllowed = FALSE;

            // If the DLL is in full path format, there is no chance for hijacking even if the DLL exist
            if (PathFileExistsA(sDllName.c_str()))
                break;

            if (PathFileExistsA(sOptionalDllPath.c_str()))
            {
                bExist = TRUE;

                CanAccessDirectory(sProcessDir.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bDirAccessAllowed);
                CanAccessDirectory(sOptionalDllPath.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bFileAllowed);

                if (!bDirAccessAllowed || !bFileAllowed)
                    isSecureDir = TRUE;
            }
            else
            {
                for (auto& sSystemPath : sSystemPaths)
                {
                    string sSystemDll = sSystemPath + "\\" + sDllName;
                    if (PathFileExistsA(sSystemDll.c_str()))
                    {
                        isSecureDir = TRUE;
                        break;
                    }
                }
            }

            if (!isSecureDir)
            {
                if (dData.bExist)
                    dData.sServirity = "high";
                else if (ends_with(pData.sBinaryPath, "dll"))
                    dData.sServirity = "medium";
                else
                    dData.sServirity = "low";

                dData.bExist = bExist == TRUE ? true : false;
                dData.sBinaryPath = sDllName;
                dData.sPermissionLevel = "low";
                pData.vsDLLs.insert(dData);

                if (DEBUG_PRINT)
                {
                    if (bExist)
                    {
                        cerr << sUserName.c_str() << "," << "high, " << "Yes," << ProcessPath.c_str() << "," << sDllName
                            << endl;
                    }
                    else if (!isSecureDir)
                    {
                        cerr << sUserName.c_str() << "," << "low, " << "No," << ProcessPath.c_str() << "," << sDllName
                            << endl;
                    }
                }
            }
        }

        if (!pData.vsDLLs.empty())
        {
            auto it = BinaryExists(p, pData.sBinaryPath);
            if (it != p->vProcessData.end())
                it->vsDLLs.insert(pData.vsDLLs.begin(), pData.vsDLLs.end());
            else
                p->vProcessData.push_back(pData);
        }
    }
lblCleanup:
    if (hImpersonatedToken != nullptr)
        CloseHandle(hImpersonatedToken);

    return eReturn;
}

void RecursiveChecking(PProcessContainer p)
{
    ESTATUS eReturn = ESTATUS_INVALID;

    p->vsProcessBinary.clear();

    for (auto& map_iter : p->msvStaticProcessMap)
    {
        const string ProcessPath = map_iter.first;
        string sProcessDir = GetDirPath(ProcessPath) + "\\";


        for (const auto& sDllName : map_iter.second)
        {
            string sOptionalDllPath = sProcessDir + sDllName;
            string sDefinedDLLPath = "";

            // In case dll name contains expanded environment variables
            if (PathFileExistsA(sDllName.c_str()))
                sDefinedDLLPath = sDllName;

            else if (PathFileExistsA(sOptionalDllPath.c_str()))
                sDefinedDLLPath = sOptionalDllPath;
            else
            {
                for (auto& sSystemPath : sSystemPaths)
                {
                    string sSystemDll = sSystemPath + "\\" + sDllName;
                    if (PathFileExistsA(sSystemDll.c_str()))
                    {
                        sDefinedDLLPath = sSystemDll;
                        break;
                    }
                }
            }
            if (sDefinedDLLPath.compare("") && p->sGlobalBinaries.find(sDefinedDLLPath) == p->sGlobalBinaries.end())
                p->vsProcessBinary.insert(sDefinedDLLPath);
        }
    }
}

vector<ProcessData>::iterator BinaryExists(PProcessContainer p, string sBinaryPath)
{
    for (auto it = p->vProcessData.begin(); it != p->vProcessData.end(); ++it)
    {
        if (!(*it).sBinaryPath.compare(sBinaryPath))
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

        for (const auto j : it.vsDLLs)
        {
            Json::Value module;
            module["path"] = j.sBinaryPath;
            module["severity"] = j.sServirity;

            entry["modules"].append(module);
        }

        node.append(entry);
    }
}
