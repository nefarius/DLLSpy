#pragma once

#include "general.h"
#include "Impersonation.h"
#include "PeImports.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <tchar.h>
#include <Shlobj.h>
#include <TlHelp32.h>
#include <map>
#include <vector>
#include <Shlwapi.h>
#include <algorithm>
#include <string>
#include <fstream>
#include <set>

#include <json/json.h>

#define DEBUG_PRINT 0

using namespace std;

class DLLData
{
public:
    string sBinaryPath;
    string sServirity;
    string sPermissionLevel;
    string sSource;
    string sWritableDir;
    bool bExist = false;
    bool bIsService = false;

    DLLData(string sBinaryPath, string sServirity, string sPermissionLevel, bool bExist, string sSource,
            string sWritableDir)
    {
        this->sBinaryPath = sBinaryPath;
        this->sServirity = sServirity;
        this->sPermissionLevel = sPermissionLevel;
        this->bExist = bExist;
        this->sSource = sSource;
        this->sWritableDir = sWritableDir;
    }

    DLLData() = default;

    ~DLLData() = default;

    bool operator<(const DLLData& other) const
    {
        return _stricmp(this->sBinaryPath.c_str(), other.sBinaryPath.c_str()) < 0;
    }
};

class ProcessData
{
public:
    set<DLLData> vsDLLs;
    string sBinaryPath;
    string sUserName;
    string sDomainName;
    bool bElevated = false;
    bool bSameUser = false;
    bool bIsService = false;

    ProcessData(string sBinaryPath, const ProcessContext& context)
    {
        this->sBinaryPath = sBinaryPath;
        this->sUserName = context.sUserName;
        this->sDomainName = context.sDomainName;
        this->bElevated = context.bElevated;
        this->bSameUser = context.bSameUser;
    }

    ~ProcessData() = default;
};

typedef struct _ProcessContainers
{
    set<string> vsProcessBinary;
    set<string> sGlobalBinaries;
    vector<ProcessData> vProcessData;
    map<string, vector<ImportRef>> msvStaticProcessMap;
    map<string, ProcessContext> mBinaryContext;
    string sReferenceUser;
    string sReferenceDomain;
    bool bIncludeAll = false;
    bool bStrings = false;
} ProcessContainer, *PProcessContainer;


ESTATUS ParseCommandLineArguments(int argc, TCHAR* argv[]);
ESTATUS FindDllHijacking([[maybe_unused]] string OutputPath, bool bStatic, bool bRecrusive, DWORD level,
                         bool bIncludeAll, bool bStrings);

ESTATUS EnumerateRunningProcesses(PProcessContainer p);
ESTATUS EnumerateProcessesBinaries(PProcessContainer p);
ESTATUS RecursiveEnumeration(PProcessContainer p, DWORD level);

ESTATUS GetServicesDLLs(PProcessContainer p);
ESTATUS GetHijackedDirectories(PProcessContainer p);
void RecursiveChecking(PProcessContainer p);
void RememberBinaryContext(PProcessContainer p, const string& sPath, const ProcessContext& context);

vector<ProcessData>::iterator BinaryExists(PProcessContainer p, string sBinaryPath);

void printAsJSON(PProcessContainer p);
void BeautifyAsJSON(Json::Value& node, PProcessContainer p);
string GetFilename(string sFullPath);


inline bool ends_with(const std::string& value, const std::string& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}
