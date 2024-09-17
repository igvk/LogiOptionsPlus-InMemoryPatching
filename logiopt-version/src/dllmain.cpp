#include <mutex>            // std::{once_flag, call_once}
#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <intrin.h>
#include <shlobj.h>
#include <windows.h>
#include <KnownFolders.h>
#include <TlHelp32.h>

#include "common.hpp"
#include "version_dll.hpp"

#include "hooking.hpp"
#include "utilities.hpp"

#define CONF_DIR L"logioptionsplus"
#define CONF_FILE L"wheel_apps_list.txt"
#define PROGRAM_NAME L"logioptionsplus_agent.exe"
#ifdef _WIN64
// TARGET_MACHINE_CODE is the unique byte sequence of target code in procedure to search for
#define TARGET_MACHINE_CODE_V100 0x48, 0x8D, 0x4C, 0x24, 0x78, 0x48, 0x83, 0xFF, 0x10, 0x48, 0x0F, 0x43, 0xCB, 0x48, 0x83, 0xFE, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC6
#define TARGET_MACHINE_CODE_V146 0x48, 0x8D, 0x4D, 0xFF, 0x49, 0x83, 0xFE, 0x10, 0x48, 0x0F, 0x43, 0xCE, 0x48, 0x83, 0xFB, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC3
#define TARGET_MACHINE_CODE_V168 0x48, 0x8D, 0x4D, 0xDF, 0x49, 0x83, 0xFE, 0x10, 0x48, 0x0F, 0x43, 0xCF, 0x48, 0x83, 0xFB, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC3
// HOOK_MACHINE_CODE is the byte sequence of code to be replaced by injected code that is close to and after the found target code
// (5 bytes minimum)
#define HOOK_MACHINE_CODE_V100 0x88, 0x45, 0x28, 0x48, 0x8B, 0x7D, 0x08
#define HOOK_MACHINE_CODE_V146 0x41, 0x88, 0x44, 0x24, 0x28, 0x4D, 0x8B, 0x64, 0x24, 0x08
#define HOOK_MACHINE_CODE_V168 0x41, 0x88, 0x44, 0x24, 0x28, 0x4D, 0x8B, 0x64, 0x24, 0x08
#define MAX_PATCH_CODE_DISP 0x20
#else
#define TARGET_MACHINE_CODE 0x48, 0x8D, 0x4C, 0x24, 0x78, 0x48, 0x83, 0xFF, 0x10, 0x48, 0x0F, 0x43, 0xCB, 0x48, 0x83, 0xFE, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC6
#define HOOK_MACHINE_CODE 0x88, 0x45, 0x28, 0x48, 0x8B, 0x7D, 0x08
#define MAX_PATCH_CODE_DISP 0x20
#endif

const wchar_t logioptions_agent_process_name[] = PROGRAM_NAME;
constexpr byte logioptions_target_code_V100[] = { TARGET_MACHINE_CODE_V100 };
constexpr byte logioptions_target_code_V146[] = { TARGET_MACHINE_CODE_V146 };
constexpr byte logioptions_target_code_V168[] = { TARGET_MACHINE_CODE_V168 };
constexpr byte logioptions_hook_code_V100[] = { HOOK_MACHINE_CODE_V100 };
constexpr byte logioptions_hook_code_V146[] = { HOOK_MACHINE_CODE_V146 };
constexpr byte logioptions_hook_code_V168[] = { HOOK_MACHINE_CODE_V168 };
constexpr long code_memory_protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

std::vector<std::string> enabled_names;
std::vector<std::string> disabled_names;

extern "C"
{
    extern void* original_jump_address;

    extern void injected_handler_V100();
    extern void injected_handler_V146();
    extern void injected_handler_V168();

    bool patched_switch_foreground_process_handler(const char* name, size_t length, bool previous_check)
    {
        DEBUG_TRACE("Patched handler: name = %s", name);
        for (auto& glob : disabled_names)
        {
            if (glob_match(name, glob.c_str()))
            {
                DEBUG_TRACE("Patched handler: Matched disabled name \"%s\"", glob.c_str());
                return false;
            }
        }
        if (previous_check)
            return true;
        for (auto& glob : enabled_names)
        {
            if (glob_match(name, glob.c_str()))
            {
                DEBUG_TRACE("Patched handler: Matched enabled name \"%s\"", glob.c_str());
                return true;
            }
        }
        return false;
    }
}

namespace
{
    bool isWin64()
    {
#if defined(_WIN64)
        DEBUG_TRACE(L"isWin64 : _WIN64");
        return true;
#else
        DEBUG_TRACE(L"isWin64 : _WIN32");
        BOOL wow64Process = FALSE;
        return (IsWow64Process(GetCurrentProcess(), &wow64Process) != 0) && (wow64Process != 0);
#endif
    }

    DllType determineDllType(const wchar_t* dllFilename)
    {
        return DllType::Version;
    }

    void loadGenuineDll(DllType dllType, const wchar_t* systemDirectory)
    {
        switch(dllType)
        {
        case DllType::Version:
            version_dll::loadGenuineDll(systemDirectory);
            break;
        default:
            break;
        }
    }

    void unloadGenuineDll(DllType dllType)
    {
        switch (dllType)
        {
        case DllType::Version:
            version_dll::unloadGenuineDll();
            break;
        default:
            break;
        }
    }
}


namespace
{
    DllType dllType = DllType::Unknown;

    bool find_data(byte* memory, size_t size, const byte* pattern, size_t length, byte*& data)
    {
        if (size >= length)
        {
            const byte* last_byte = memory + size - length;
            for (; memory <= last_byte; memory++)
            {
                if (!memcmp(memory, pattern, length))
                {
                    data = memory;
                    return true;
                }
            }
        }
        data = nullptr;
        return false;
    }

    wchar_t* mergeWChar(wchar_t* dest, const wchar_t* source)
    {
        const size_t size = (dest ? wcslen(dest) : 0) + wcslen(source) + 1;
        wchar_t* newdest = static_cast<wchar_t*>(malloc(size * sizeof(wchar_t)));
        if (dest)
            wcscpy_s(newdest, size, dest);
        else
            newdest[0] = 0;
        wcscat_s(newdest, size, source);
        return newdest;
    }

    void read_config()
    {
        PWSTR path;
        HRESULT hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path);
        if (SUCCEEDED(hr))
        {
            wchar_t* confpath = mergeWChar(path, L"\\" CONF_DIR L"\\" CONF_FILE);
            DEBUG_TRACE("Config file = %ls", confpath);
            std::ifstream conffile(confpath);
            free(confpath);
            if (conffile)
            {
                std::string line;
                while (std::getline(conffile, line))
                {
                    if (line.empty())
                        continue;
                    std::ranges::transform(
                        line,
                        line.begin(),
                        [](const char v) { return static_cast<char>(std::tolower(v)); }
                    );
                    switch (line[0])
                    {
                    case ';':
                        continue;
                    case '-':
                        disabled_names.emplace_back(line.substr(1));
                        break;
                    default:
                        enabled_names.emplace_back(line);
                        break;
                    }
                }
                enabled_names.shrink_to_fit();
                disabled_names.shrink_to_fit();
            }
        }
        else
        {
            DEBUG_TRACE("Config directory not found: error = %lux", hr);
        }
    }

    void init(HMODULE hModule) {
        DEBUG_TRACE(L"init : begin");

        wchar_t systemDirectory[MAX_PATH + 1];
        const auto w64 = isWin64();
        DEBUG_TRACE(L"init : isWin64=%d", w64);
        if (w64)
            GetSystemDirectoryW(systemDirectory, std::size(systemDirectory));
        else
            GetSystemWow64DirectoryW(systemDirectory, std::size(systemDirectory));
        DEBUG_TRACE(L"init : systemDirectory=\"%s\"", systemDirectory);

        {
            wchar_t moduleFullpathFilename[MAX_PATH + 1];
            GetModuleFileNameW(hModule, moduleFullpathFilename, std::size(moduleFullpathFilename));
            DEBUG_TRACE(L"init : moduleFullpathFilename=\"%s\"", moduleFullpathFilename);

            wchar_t fname[_MAX_FNAME + 1];
            wchar_t drive[_MAX_DRIVE + 1];
            wchar_t dir[_MAX_DIR + 1];
            wchar_t ext[_MAX_EXT + 1];
            _wsplitpath_s(moduleFullpathFilename, drive, dir, fname, ext);
            DEBUG_TRACE(L"init : fname=\"%s\"", fname);

            dllType = determineDllType(fname);
            DEBUG_TRACE(L"init : dllType=%d", dllType);
        }

        loadGenuineDll(dllType, systemDirectory);

        WCHAR exePath[MAX_PATH + 1];
        DWORD exePathLen = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (exePathLen == 0)
        {
            DEBUG_TRACE("GetModuleFileName: error = %lux", GetLastError());
        }
        else
        {
            DEBUG_TRACE("Exe path is %ls", exePath);
            const size_t processNameLen = wcsnlen(logioptions_agent_process_name, std::size(exePath));
            if (exePathLen >= processNameLen && wcsncmp(exePath + exePathLen - processNameLen, logioptions_agent_process_name, std::size(exePath)) == 0)
            {
                read_config();

                MEMORY_BASIC_INFORMATION mbi;

                for (byte* addr = nullptr; VirtualQuery(addr, &mbi, sizeof mbi); addr += mbi.RegionSize)
                {
                    if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & code_memory_protection) != 0)
                    {
                        byte* memory = static_cast<byte*>(mbi.BaseAddress);
                        const size_t bytes_count = mbi.RegionSize;

                        const byte* hook_code;
                        size_t target_code_size, hook_code_size;
                        void (*injected_handler)();
                        byte* found_addr;
                        if (find_data(memory, bytes_count, logioptions_target_code_V168, target_code_size = sizeof logioptions_target_code_V168, found_addr))
                        {
                            injected_handler = injected_handler_V168;
                            hook_code = logioptions_hook_code_V168;
                            hook_code_size = sizeof logioptions_hook_code_V168;
                        }
                        else if (find_data(memory, bytes_count, logioptions_target_code_V146, target_code_size = sizeof logioptions_target_code_V146, found_addr))
                        {
                            injected_handler = injected_handler_V146;
                            hook_code = logioptions_hook_code_V146;
                            hook_code_size = sizeof logioptions_hook_code_V146;
                        }
                        else if (find_data(memory, bytes_count, logioptions_target_code_V100, target_code_size = sizeof logioptions_target_code_V100, found_addr))
                        {
                            injected_handler = injected_handler_V100;
                            hook_code = logioptions_hook_code_V100;
                            hook_code_size = sizeof logioptions_hook_code_V100;
                        }
                        else
                            continue;

                        DEBUG_TRACE("Found pattern at %p", found_addr);
                        found_addr += target_code_size;
                        size_t count = bytes_count - (found_addr - memory);
                        if (count > MAX_PATCH_CODE_DISP)
                            count = MAX_PATCH_CODE_DISP;
                        if (find_data(found_addr, count, hook_code, hook_code_size, found_addr))
                        {
                            byte* hook_address = found_addr;
                            found_addr += hook_code_size;
                            DEBUG_TRACE("Found code to patch at %p", hook_address);
                            original_jump_address = found_addr;
                            unsigned long oldProtect;
                            if (!VirtualProtect(addr, bytes_count, PAGE_EXECUTE_READWRITE, &oldProtect))
                            {
                                DEBUG_TRACE("VirtualProtectEx: error = %lux", GetLastError());
                                break;
                            }
                            const bool result = InstallAllocateHook(hook_address, hook_code_size, injected_handler);
                            VirtualProtect(addr, bytes_count, oldProtect, &oldProtect);
                            if (result)
                                DEBUG_TRACE("Injected code at %p", hook_address);
                            else
                                DEBUG_TRACE("Unable to inject code at %p", hook_address);
                        }
                        else
                        {
                            DEBUG_TRACE("Not found code to patch or already patched");
                        }
                        break;
                    }
                }
            }
        }

        DEBUG_TRACE(L"init : end");
    }

    void cleanup()
    {
        DEBUG_TRACE(L"cleanup : begin");

        unloadGenuineDll(dllType);
        DEBUG_TRACE(L"cleanup : end");
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    static std::once_flag initFlag;
    static std::once_flag cleanupFlag;

    switch(ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DEBUG_TRACE(L"DLL_PROCESS_ATTACH (hModule=%p) : begin", hModule);
        std::call_once(initFlag, [&]() { init(hModule); });
        DEBUG_TRACE(L"DLL_PROCESS_ATTACH (hModule=%p) : end", hModule);
        break;

    case DLL_PROCESS_DETACH:
        DEBUG_TRACE(L"DLL_PROCESS_DETACH (hModule=%p) : begin", hModule);
        std::call_once(cleanupFlag, [&]() { cleanup(); });
        DEBUG_TRACE(L"DLL_PROCESS_DETACH (hModule=%p) : end", hModule);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        break;
    }

    return TRUE;
}
