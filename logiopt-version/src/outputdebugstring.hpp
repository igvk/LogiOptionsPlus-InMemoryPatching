#pragma once
#if defined(USE_OUTPUT_DEBUG_STRING) && USE_OUTPUT_DEBUG_STRING == 1
void outputDebugString(const wchar_t* fmt, ...);
void outputDebugString(const char* fmt, ...);
#  define DEBUG_TRACE(...) outputDebugString(__VA_ARGS__)
#else
#  define DEBUG_TRACE(...)
#endif
