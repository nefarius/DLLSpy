#pragma once

#include "general.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

using namespace std;

struct ProcessContext
{
    string sUserName;
    string sDomainName;
    bool bElevated = false;
    bool bSameUser = false;
};

inline bool IsUnprivilegedContext(const ProcessContext& context)
{
    return context.bSameUser && !context.bElevated;
}

ESTATUS FindProcessId(const TCHAR *processName, DWORD *pProcessId);
ESTATUS GetImpersonatedToken(PHANDLE hImpersonatedToken, const TCHAR *processName);
ESTATUS CanAccessDirectory(LPCTSTR folderName, DWORD genericAccessRights, PHANDLE hImpersonatedToken, PBOOL hHasAccess);
ESTATUS GetLogonFromToken(HANDLE hToken, string& strUser, string& strDomain);
ESTATUS GetProcessContext(DWORD dwPid, HANDLE hReferenceToken, ProcessContext& context);
