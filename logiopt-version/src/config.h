#pragma once

//
// If you define and set '1' to EXPORT_VERSION_DLL_FUNCTIONS, DLL exports version.dll functions
//
#define EXPORT_VERSION_DLL_FUNCTIONS 1

#if defined(_DEBUG)
#define USE_OUTPUT_DEBUG_STRING 1
#define USE_DEBUG_TRACE 1
#else
#define USE_OUTPUT_DEBUG_STRING 0
#define USE_DEBUG_TRACE 0
#endif
