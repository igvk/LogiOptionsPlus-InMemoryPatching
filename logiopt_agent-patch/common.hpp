#pragma once
extern "C" int printf(const char* format, ...);
#define DEBUG_TRACE(f_, ...) printf((f_ "\n"), __VA_ARGS__)
