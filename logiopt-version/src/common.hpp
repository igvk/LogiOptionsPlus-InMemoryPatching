#pragma once
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <windows.h>
#include <stdio.h>
#include <algorithm>
#pragma comment(linker, "/DLL")

#include "config.h"
#include "outputdebugstring.hpp"
#define APPNAME "logioptions+version.dll"

enum class DllType {
    Unknown,
    Version,
};
