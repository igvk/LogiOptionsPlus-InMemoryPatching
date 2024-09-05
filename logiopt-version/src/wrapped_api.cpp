#include "common.hpp"

#define DllExport extern "C" __declspec(dllexport)

DllExport const wchar_t* LDR_VERSION_DLL_SIGNATURE() {
    return L"This is version.dll for LogiOptions+";
}
