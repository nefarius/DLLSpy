#include "ServiceRegistry.h"
#include "Utils.h"


ESTATUS EnumerateServicesFromRegistry(PProcessContainer p)
{
	LSTATUS lResult = 0;
	HKEY hKey;
	ESTATUS eReturn = ESTATUS_INVALID;

    lResult = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		R"(SYSTEM\CurrentControlSet\Services\)",
		0,
		KEY_ENUMERATE_SUB_KEYS | KEY_READ | KEY_QUERY_VALUE,
		&hKey
	);

	if (lResult == ERROR_SUCCESS)
	{
		DWORD cbName; // size of name string 
		TCHAR achClass[MAX_PATH] = TEXT(""); // buffer for class name 
		DWORD cchClassName = MAX_PATH; // size of class string 
		DWORD cSubKeys = 0; // number of subkeys 
		DWORD cbMaxSubKey; // longest subkey size 
		DWORD cchMaxClass; // longest class string 
		DWORD cValues; // number of values for key 
		DWORD cchMaxValue; // longest value name 
		DWORD cbMaxValueData; // longest value data 
		DWORD cbSecurityDescriptor; // size of security descriptor 
		FILETIME ftLastWriteTime; // last write time 
		DWORD i;

		// Get the class name and the value count. 
		DWORD retCode = RegQueryInfoKey(
			hKey,
			achClass,
			&cchClassName,
			nullptr,
			&cSubKeys,
			&cbMaxSubKey,
			&cchMaxClass,
			&cValues,
			&cchMaxValue,
			&cbMaxValueData,
			&cbSecurityDescriptor,
			&ftLastWriteTime
		);

		if (cSubKeys)
		{
			for (i = 0; i < cSubKeys; i++)
			{
				TCHAR achKey[MAX_KEY_LENGTH];
				cbName = MAX_KEY_LENGTH;
				retCode = RegEnumKeyEx(hKey, i, achKey, &cbName, nullptr, nullptr, nullptr, &ftLastWriteTime);
				if (retCode == ERROR_SUCCESS)
				{
					TCHAR cKeyName[MAX_PATH] = R"(SYSTEM\CurrentControlSet\Services\)";
					strncat_s(cKeyName, MAX_PATH, achKey, strlen(achKey));
					string ServicePath;
					ProcessContext context;
					const ESTATUS dwResult = GetServiceBinary(
						cKeyName, ServicePath, context, p->sReferenceUser, p->sReferenceDomain);
					if (!ServicePath.empty() && dwResult == ESTATUS_SUCCESS)
					{
						RememberBinaryContext(p, ServicePath, context);
						if (!IsUnprivilegedContext(context) || p->bIncludeAll)
						{
							if (p->vsProcessBinary.find(ServicePath) == p->vsProcessBinary.end())
								p->vsProcessBinary.insert(ServicePath);
						}
					}
				}
			}
		}
		RegCloseKey(hKey);
	}
	if (!p->vsProcessBinary.empty())
		eReturn = ESTATUS_SUCCESS;

	return eReturn;
}

ESTATUS GetServicePathFromRegistryDllKey(const TCHAR* cKeyName, string& ServicePath)
{
	ESTATUS eReturn = ESTATUS_INVALID;
	DWORD dwType = REG_EXPAND_SZ;
	DWORD dwSize = FULL_PATH_SIZE;
	HKEY hServiceDLLKey = nullptr;
	TCHAR cDLLName[FULL_PATH_SIZE] = { 0 };
	TCHAR cDLLKey[FULL_PATH_SIZE] = { 0 };
	strncpy_s(cDLLKey, FULL_PATH_SIZE, cKeyName, strlen(cKeyName));
	strncat_s(cDLLKey, FULL_PATH_SIZE, "\\Parameters", strlen("\\Parameters"));

	if (RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		cDLLKey,
		0,
		KEY_ENUMERATE_SUB_KEYS | KEY_READ | KEY_QUERY_VALUE,
		&hServiceDLLKey
	) == ERROR_SUCCESS)
	{
		RegQueryValueExA(hServiceDLLKey, "ServiceDll", nullptr, &dwType, reinterpret_cast<LPBYTE>(&cDLLName), &dwSize);
		if (cDLLName[0] != '\0')
		{
			ServicePath = ExpandPath(string(cDLLName));
			RegCloseKey(hServiceDLLKey);
			eReturn = ESTATUS_SUCCESS;
		}
		else
			eReturn = ESTATUS_REG_OPEN_KEY_ERROR;
	}
	return eReturn;
}

static ProcessContext ContextFromObjectName(const string& sObjectName, const string& sReferenceUser,
	const string& sReferenceDomain)
{
	ProcessContext context;
	context.bElevated = true;
	context.bSameUser = false;

	string objectName = sObjectName;
	const auto embeddedEnd = objectName.find('\0');
	if (embeddedEnd != string::npos)
		objectName.resize(embeddedEnd);

	if (objectName.empty() || CompareStrings(objectName, "LocalSystem"))
	{
		context.sUserName = "SYSTEM";
		context.sDomainName = "NT AUTHORITY";
		return context;
	}

	string domain;
	string user = objectName;
	const auto split = objectName.find('\\');
	if (split != string::npos)
	{
		domain = objectName.substr(0, split);
		user = objectName.substr(split + 1);
	}

	context.sUserName = user;
	context.sDomainName = domain == "." ? sReferenceDomain : domain;

	const bool userMatches = CompareStrings(user, sReferenceUser);
	const bool domainMatches = domain.empty() || domain == "." || CompareStrings(domain, sReferenceDomain);
	if (userMatches && domainMatches && !sReferenceUser.empty())
	{
		context.bSameUser = true;
		context.bElevated = false;
	}

	return context;
}

ESTATUS GetServiceBinary(const TCHAR* cKeyName, string& ServicePath, ProcessContext& context,
	const string& sReferenceUser, const string& sReferenceDomain)
{
	HKEY hNewKey = nullptr;
	DWORD dwSize = REG_DWORD;
	DWORD dwType = REG_SZ;
	DWORD dwServiceType = 0;
	TCHAR cServiceImagePath[FULL_PATH_SIZE] = { 0 };
	TCHAR cObjectName[FULL_PATH_SIZE] = { 0 };
	DWORD dwStartMode = 0;
	ESTATUS eReturn = ESTATUS_INVALID;
	context = ProcessContext();
	context.bElevated = true;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, cKeyName, 0, KEY_ENUMERATE_SUB_KEYS | KEY_READ | KEY_QUERY_VALUE, &hNewKey) ==
		ERROR_SUCCESS)
	{
		RegQueryValueExA(hNewKey, "Start", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwStartMode), &dwSize);
		dwSize = REG_DWORD;
		RegQueryValueExA(hNewKey, "Type", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwServiceType), &dwSize);
		dwType = REG_SZ;
		dwSize = FULL_PATH_SIZE;
		RegQueryValueExA(hNewKey, "ImagePath", nullptr, &dwType, reinterpret_cast<LPBYTE>(&cServiceImagePath), &dwSize);

		dwType = REG_SZ;
		dwSize = FULL_PATH_SIZE;
		RegQueryValueExA(hNewKey, "ObjectName", nullptr, &dwType, reinterpret_cast<LPBYTE>(&cObjectName), &dwSize);

		if ((dwServiceType == 0x20 || dwServiceType == 0x10 || dwServiceType == 0x110) && (dwStartMode != 0x4) && (
			cServiceImagePath[0] != '\0'))
		{
			if (strstr(cServiceImagePath, "svchost") == nullptr)
			{
				TCHAR cBinaryPath[FULL_PATH_SIZE] = { 0 };
				if (strchr(cServiceImagePath, '"') != nullptr)
					GetBinaryPath(cBinaryPath, cServiceImagePath);
				else
					strncat_s(cBinaryPath, FULL_PATH_SIZE, cServiceImagePath, strlen(cServiceImagePath));

				ServicePath = ExpandPath(string(cBinaryPath));
				eReturn = ESTATUS_SUCCESS;
			}
			else
				eReturn = GetServicePathFromRegistryDllKey(cKeyName, ServicePath);

			if (eReturn == ESTATUS_SUCCESS)
				context = ContextFromObjectName(string(cObjectName), sReferenceUser, sReferenceDomain);
		}
	}

	if (hNewKey != nullptr)
		RegCloseKey(hNewKey);

	return eReturn;
}
