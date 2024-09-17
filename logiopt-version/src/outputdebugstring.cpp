#include "common.hpp"

#if defined(USE_OUTPUT_DEBUG_STRING) && (USE_OUTPUT_DEBUG_STRING == 1)
void outputDebugString(const wchar_t* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    wchar_t buf[1024];
    auto str = buf;
    int len = std::size(buf);
    auto n = swprintf_s(str, len, L"" APPNAME ": ");
    str += n;
    len -= n;
    n = vswprintf_s(str, len, fmt, args);
    str += n;
    len -= n;
    if (len <= 1)
        str = &buf[std::size(buf) - 2];
    *str++ = '\n';
    *str = '\0';
    OutputDebugStringW(buf);
    va_end(args);
}

void outputDebugString(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    auto str = buf;
    int len = std::size(buf);
    auto n = sprintf_s(str, len, "" APPNAME ": ");
    str += n;
    len -= n;
    n = vsprintf_s(str, len, fmt, args);
    str += n;
    len -= n;
    if (len <= 1)
        str = &buf[std::size(buf) - 2];
    *str++ = '\n';
    *str = '\0';
    OutputDebugStringA(buf);
    va_end(args);
}

#endif
