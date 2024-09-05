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
#include "hooking.hpp"
#include "utilities.hpp"

#define CONF_DIR L"logioptionsplus"
#define CONF_FILE L"wheel_apps_list.txt"
#define PROGRAM_NAME L"logiopt_agent-patch.exe"
#define PROGRAM_NAME_CHARS "logiopt_agent-patch.exe"
#ifdef _WIN64
// TARGET_MACHINE_CODE is the unique byte sequence of target code in procedure to search for
#define TARGET_MACHINE_CODE_V100 0x48, 0x8D, 0x4C, 0x24, 0x78, 0x48, 0x83, 0xFF, 0x10, 0x48, 0x0F, 0x43, 0xCB, 0x48, 0x83, 0xFE, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC6
#define TARGET_MACHINE_CODE_V146 0x48, 0x8D, 0x4D, 0xFF, 0x49, 0x83, 0xFE, 0x10, 0x48, 0x0F, 0x43, 0xCE, 0x48, 0x83, 0xFB, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC3
#define TARGET_MACHINE_CODE_V168 0x48, 0x8D, 0x4D, 0xDF, 0x49, 0x83, 0xFE, 0x10, 0x48, 0x0F, 0x43, 0xCF, 0x48, 0x83, 0xFB, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC3
#define PATCH_MACHINE_CODE 0x32, 0xC0
#define REPLACEMENT_MACHINE_CODE 0xB0, 0x01
// HOOK_MACHINE_CODE is the byte sequence of code to be replaced by injected code that is close to and after the found target code
// (5 bytes minimum)
#define HOOK_MACHINE_CODE_V100 0x88, 0x45, 0x28, 0x48, 0x8B, 0x7D, 0x08
#define HOOK_MACHINE_CODE_V146 0x41, 0x88, 0x44, 0x24, 0x28, 0x4D, 0x8B, 0x64, 0x24, 0x08
#define HOOK_MACHINE_CODE_V168 0x41, 0x88, 0x44, 0x24, 0x28, 0x4D, 0x8B, 0x64, 0x24, 0x08
//#define CAVE_MACHINE_CODE_V100 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC // 13 bytes minimum (after displacement)
//#define CAVE_MACHINE_CODE_DISP_V100 2
#define MAX_PATCH_CODE_DISP 0x20
#else
#define TARGET_MACHINE_CODE 0x48, 0x83, 0xFF, 0x10, 0x48, 0x0F, 0x43, 0xCB, 0x48, 0x83, 0xFE, 0x0B, 0x75, 0x17, 0x4C, 0x8B, 0xC6
#define PATCH_MACHINE_CODE 0x32, 0xC0
#define REPLACEMENT_MACHINE_CODE 0xB0, 0x01
#define HOOK_MACHINE_CODE 0x88, 0x45, 0x28, 0x48, 0x8B, 0x7D, 0x08
#define MAX_PATCH_CODE_DISP 0x20
#endif

const wchar_t logioptions_agent_process_name[] = L"logioptionsplus_agent.exe";
constexpr byte logioptions_patch_code[] = { PATCH_MACHINE_CODE };
constexpr byte logioptions_replacement_code[] = { REPLACEMENT_MACHINE_CODE };
constexpr byte logioptions_target_code_V100[] = { TARGET_MACHINE_CODE_V100 };
constexpr byte logioptions_target_code_V146[] = { TARGET_MACHINE_CODE_V146 };
constexpr byte logioptions_target_code_V168[] = { TARGET_MACHINE_CODE_V168 };
constexpr byte logioptions_hook_code_V100[] = { HOOK_MACHINE_CODE_V100 };
constexpr byte logioptions_hook_code_V146[] = { HOOK_MACHINE_CODE_V146 };
constexpr byte logioptions_hook_code_V168[] = { HOOK_MACHINE_CODE_V168 };
const byte *logioptions_target_code = logioptions_target_code_V168;
const byte *logioptions_hook_code = logioptions_hook_code_V168;
#ifdef CODE_CAVE
//constexpr byte logioptions_cave_code_V100[] = { CAVE_MACHINE_CODE_V100 };
//constexpr size_t logioptions_cave_code_disp_V100 = CAVE_MACHINE_CODE_DISP_V100;
#endif
constexpr long code_memory_protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

std::vector<std::string> enabled_names;
std::vector<std::string> disabled_names;

extern "C"
{
    extern void* original_jump_address;

    extern bool target_handler_V100(const char* name, size_t length);
    extern bool target_handler_V146(const char* name, size_t length);
    extern bool target_handler_V168(const char* name, size_t length);

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

wchar_t* mergeWChar(const wchar_t* dest, const wchar_t* source)
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
            std::wstring program_name(PROGRAM_NAME);
            enabled_names.emplace_back(program_name.begin(), program_name.end());
            enabled_names.shrink_to_fit();
            disabled_names.shrink_to_fit();
        }
    }
    else
    {
        DEBUG_TRACE("Config directory not found: error = %lux", hr);
    }
}

DWORD get_proc_id(const wchar_t* procName)
{
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof procEntry;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hSnap, &procEntry))
    {
        do
        {
            if (!_wcsicmp(procEntry.szExeFile, procName))
            {
                CloseHandle(hSnap);
                return procEntry.th32ProcessID;
            }
        } while (Process32Next(hSnap, &procEntry));
    }
    CloseHandle(hSnap);
    return 0;
}

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

void patch_current_process()
{
    constexpr wchar_t logioptions_agent_process_name[] = PROGRAM_NAME;  // NOLINT(clang-diagnostic-shadow)
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
            const byte* target_code = logioptions_target_code, * patch_code = logioptions_patch_code;
            constexpr size_t target_code_size = sizeof logioptions_target_code, patch_code_size = sizeof logioptions_patch_code;

            /*
            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            */

            MEMORY_BASIC_INFORMATION mbi;

            for (byte* addr = nullptr; VirtualQuery(addr, &mbi, sizeof mbi); addr += mbi.RegionSize)
            {
                if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & code_memory_protection) != 0)
                {
                    byte* memory = static_cast<byte*>(mbi.BaseAddress);
                    size_t bytes_count = mbi.RegionSize;
                    byte* found_addr;
                    if (find_data(memory, bytes_count, target_code, target_code_size, found_addr))
                    {
                        DEBUG_TRACE("Found pattern at %p", found_addr);
                        found_addr += target_code_size;
                        size_t count = bytes_count - (found_addr - memory);
                        if (count > MAX_PATCH_CODE_DISP)
                            count = MAX_PATCH_CODE_DISP;
                        if (find_data(found_addr, count, patch_code, patch_code_size, found_addr))
                        {
                            DEBUG_TRACE("Found code to patch at %p", found_addr);
                            unsigned long oldProtect;
                            if (!VirtualProtect(addr, bytes_count, PAGE_EXECUTE_READWRITE, &oldProtect))
                            {
                                DEBUG_TRACE("VirtualProtectEx: error = %lux", GetLastError());
                                break;
                            }
                            memcpy(found_addr, logioptions_replacement_code, sizeof logioptions_replacement_code);
                            VirtualProtect(addr, bytes_count, oldProtect, &oldProtect);
                            DEBUG_TRACE("Replaced code at %p", found_addr);
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
    }
}

void patch_another_process()
{
    const DWORD pid = get_proc_id(logioptions_agent_process_name);

    if (!pid)
        return;

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process)
        return;

    const byte* target_code = logioptions_target_code,
        * patch_code = logioptions_patch_code,
        * replacement_code = logioptions_replacement_code;
    constexpr size_t target_code_size = sizeof logioptions_target_code,
        patch_code_size = sizeof logioptions_patch_code,
        replacement_code_size = sizeof logioptions_replacement_code;

    MEMORY_BASIC_INFORMATION mbi;

    std::cout << std::hex;
    for (byte* addr = nullptr; VirtualQueryEx(process, addr, &mbi, sizeof mbi); addr += mbi.RegionSize)
    {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & code_memory_protection) != 0)
        {
            std::cout
                << "Block " << mbi.State
                << " at " << reinterpret_cast<size_t>(addr)
                << " size " << mbi.RegionSize
                << " protect " << mbi.Protect
                << " type " << mbi.Type
                << '\n';
#ifdef UNPROTECT_PAGE
            unsigned long oldProtect;
            if (!VirtualProtectEx(process, addr, sizeof addr, PAGE_READWRITE, &oldProtect))
            {
                std::cout << "VirtualProtectEx: error = " << GetLastError() << '\n';
                continue;
            }
#endif
            byte* buffer = new byte[mbi.RegionSize];
            size_t bytes_count;
            ReadProcessMemory(process, mbi.BaseAddress, buffer, mbi.RegionSize, &bytes_count);
            byte* found_addr;
            if (find_data(buffer, bytes_count, target_code, target_code_size, found_addr))
            {
                size_t disp = found_addr - buffer;
                std::cout << "Found pattern at " << found_addr << '\n';
                found_addr += target_code_size;
                size_t count = bytes_count - disp;
                if (count > MAX_PATCH_CODE_DISP)
                    count = MAX_PATCH_CODE_DISP;
                if (find_data(found_addr, count, patch_code, patch_code_size, found_addr))
                {
                    byte* write_addr = addr + (found_addr - buffer);
                    std::cout << "Found code to patch at " << reinterpret_cast<size_t>(write_addr) << '\n';
                    if (WriteProcessMemory(process, write_addr, replacement_code, replacement_code_size, &bytes_count))
                        std::cout << "Replaced code at " << reinterpret_cast<size_t>(write_addr) << '\n';
                    else
                        std::cout << "Error replacing code = " << GetLastError() << '\n';
                }
                else
                {
                    std::cout << "Not found code to patch or already patched" << '\n';
                }
                delete[] buffer;
                break;
            }
            delete[] buffer;
        }
    }
}

void hook_current_process()
{
    const wchar_t logioptions_agent_process_name[] = PROGRAM_NAME;
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
            /*
            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            */

            MEMORY_BASIC_INFORMATION mbi;

            for (byte* addr = nullptr; VirtualQuery(addr, &mbi, sizeof mbi); addr += mbi.RegionSize)
            {
                if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & code_memory_protection) != 0)
                {
                    byte* memory = static_cast<byte*>(mbi.BaseAddress);
                    size_t bytes_count = mbi.RegionSize;

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
#ifdef CODE_CAVE
                        count = bytes_count - (found_addr - memory);
                        if (count > MAX_PATCH_CODE_DISP)
                            count = MAX_PATCH_CODE_DISP;
                        if (find_data(found_addr, count, cave_code, cave_code_size, found_addr))
                        {
                            found_addr += cave_code_disp;
                            DEBUG_TRACE("Found code cave at %p", found_addr);
                            original_jump_address = hook_address + hook_code_size;
                            unsigned long oldProtect;
                            if (!VirtualProtect(addr, bytes_count, PAGE_EXECUTE_READWRITE, &oldProtect))
                            {
                                DEBUG_TRACE("VirtualProtectEx: error = %lux", GetLastError());
                                break;
                            }
                            const bool result = InstallCaveHook(hook_address, hook_code_size, found_addr, injected_handler);
                            VirtualProtect(addr, bytes_count, oldProtect, &oldProtect);
                            if (result)
                                DEBUG_TRACE("Injected code at %p", hook_address);
                            else
                                DEBUG_TRACE("Unable to inject code at %p", hook_address);
                        }
                        else
                            DEBUG_TRACE("Unable to find code cave");
#endif
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
}

int main()
{
    //patch_another_process();
    read_config();
    hook_current_process();
    const bool result = target_handler_V168(PROGRAM_NAME_CHARS, sizeof PROGRAM_NAME_CHARS);
    std::cout << "Handler result = " << static_cast<int>(result) << '\n';
    return 0;
}
