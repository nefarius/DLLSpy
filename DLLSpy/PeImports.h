#pragma once

#include "general.h"
#include <string>
#include <vector>

using namespace std;

enum class DllRefSource
{
    Import,
    DelayImport,
    String
};

struct ImportRef
{
    string sName;
    DllRefSource eSource;
};

ESTATUS GetPeImports(const string& sPath, vector<ImportRef>& vImports);
