#pragma once

#include "general.h"
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
    bool bExist;
    bool bIsService;

    DLLData(string sBinaryPath, string sServirity, string sPermissionLevel, bool bExist)
    {
        this->sBinaryPath = sBinaryPath;
        this->sServirity = sServirity;
        this->sPermissionLevel = sPermissionLevel;
        this->bExist = bExist;
    }

    DLLData() = default;

    ~DLLData() = default;

    bool operator <(const DLLData& a) const
    {
        return this->sBinaryPath < a.sBinaryPath;
    }
};

class ProcessData
{
public:
    set<DLLData> vsDLLs;
    string sBinaryPath;
    string sUserName;
    string sDomainName;
    bool bIsService;

    ProcessData(string sBinaryPath, string sUserName, string sDomainName)
    {
        this->sBinaryPath = sBinaryPath;
        this->sUserName = sUserName;
        this->sDomainName = sDomainName;
    }

    ~ProcessData() = default;
};

typedef struct _ProcessContainers
{
    set<string> vsProcessBinary;
    set<string> sGlobalBinaries;
    vector<ProcessData> vProcessData;
    map<string, vector<string>> msvStaticProcessMap;
} ProcessContainer, *PProcessContainer;


ESTATUS ParseCommandLineArguments(int argc, TCHAR* argv[]);
ESTATUS FindDllHijacking([[maybe_unused]] string OutputPath, bool bStatic, bool bRecrusive, DWORD level);

ESTATUS EnumerateRunningProcesses(PProcessContainer p);
ESTATUS EnumerateProcessesBinaries(PProcessContainer p);
ESTATUS RecursiveEnumeration(PProcessContainer p, DWORD level);

ESTATUS GetServicesDLLs(PProcessContainer p);
ESTATUS GetHijackedDirectories(PProcessContainer p);
void RecursiveChecking(PProcessContainer p);

vector<ProcessData>::iterator BinaryExists(PProcessContainer p, string sBinaryPath);

void printAsJSON(PProcessContainer p);
void BeautifyAsJSON(Json::Value& node, PProcessContainer p);
string GetFilename(string sFullPath);


inline bool ends_with(const std::string& value, const std::string& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}
