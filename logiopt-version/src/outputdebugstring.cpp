#include "common.hpp"

#if defined(USE_OUTPUT_DEBUG_STRING) && (USE_OUTPUT_DEBUG_STRING == 1)
void outputDebugString(const wchar_t* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    wchar_t buf[1024];
    const auto n = swprintf_s(buf, std::size(buf), L"" APPNAME ": ");
    vswprintf_s(buf+n, std::size(buf)-n, fmt, args);
    OutputDebugStringW(buf);
    va_end(args);
}

void outputDebugString(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    const auto n = sprintf_s(buf, std::size(buf), "" APPNAME ": ");
    vsprintf_s(buf+n, std::size(buf)-n, fmt, args);
    OutputDebugStringA(buf);
    va_end(args);
}

#endif
