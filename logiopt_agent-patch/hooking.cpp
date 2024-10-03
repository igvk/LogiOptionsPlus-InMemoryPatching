#include <cstdint>
#include <intrin.h>
#include <windows.h>
#include "common.hpp"
#include "hooking.hpp"

void* AllocatePageNearAddress(void* targetAddr)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const size_t PAGE_SIZE = sysInfo.dwPageSize;
    constexpr size_t maxDisp = 0x7FFFFF00;

    uintptr_t startPage = reinterpret_cast<uintptr_t>(targetAddr) & ~(PAGE_SIZE - 1); //round down to nearest page boundary
    uintptr_t minAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t addr = _sat_sub_u64(startPage, maxDisp); // addr is decremented by maxDisp, but not wrapped around zero
    minAddr = addr >= minAddr ? addr : minAddr;
    uintptr_t maxAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
    addr = _sat_add_u64(startPage, maxDisp); // addr is incremented by maxDisp, but not wrapped around zero
    maxAddr = addr <= maxAddr ? addr : maxAddr;
    const size_t addrStep = PAGE_SIZE;
    uintptr_t highAddr = startPage, lowAddr = startPage;

    do
    {
        highAddr = _sat_add_u64(highAddr, addrStep); // highAddr is incremented by addrStep, but is bounded above by UINT64_MAX
        lowAddr = _sat_sub_u64(lowAddr, addrStep); // lowAddr is decremented by addrStep, but is bounded below by 0
        if (highAddr < maxAddr)
        {
            void* outAddr = VirtualAlloc(reinterpret_cast<void*>(highAddr), PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  // NOLINT(performance-no-int-to-ptr)
            if (outAddr)
                return outAddr;
        }
        if (lowAddr > minAddr)
        {
            void* outAddr = VirtualAlloc(reinterpret_cast<void*>(lowAddr), PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  // NOLINT(performance-no-int-to-ptr)
            if (outAddr)
                return outAddr;
        }
    } while (highAddr < maxAddr || lowAddr > minAddr);

    return nullptr;
}

void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
    constexpr uint16_t absJumpInstructionMov = 0x49 + (0xBA << 8); // mov r10, addr64
    constexpr uint8_t absJumpInstructionJmp[] =
    {
      0x41, 0xFF, 0xE2 // jmp r10
    };
    auto code = static_cast<uint8_t*>(absJumpMemory);
    *reinterpret_cast<uint16_t*>(code) = absJumpInstructionMov;
    code += sizeof absJumpInstructionMov;
    *reinterpret_cast<void**>(code) = addrToJumpTo;
    code += sizeof addrToJumpTo;
    memcpy(code, absJumpInstructionJmp, sizeof absJumpInstructionJmp);
}

bool InstallCaveHook(void* func2hook, size_t injectSize, void* caveRelayMemory, void payloadFunction())
{
    // relative jmp displacement to relay function
    long long relayDisp = static_cast<byte*>(caveRelayMemory) - static_cast<byte*>(func2hook) - 2;
    int8_t shortDisp = static_cast<int8_t>(relayDisp);
    if (shortDisp != relayDisp)
        return false;

    WriteAbsoluteJump64(caveRelayMemory, reinterpret_cast<void*>(payloadFunction)); //write relay func instructions

    // 8 bit relative jump opcode is EB, takes 1 8-bit operand for jump offset
    constexpr uint8_t jmpInstruction = 0xE9;

    // install the hook
    auto code = static_cast<uint8_t*>(func2hook);
    *code = jmpInstruction;
    code += sizeof jmpInstruction;
    *code = shortDisp;
    code += sizeof shortDisp;

    injectSize -= sizeof jmpInstruction + sizeof shortDisp;
    if (injectSize > 0)
        memset(code, 0x90, injectSize);

    return true;
}

bool InstallAllocateHook(void* func2hook, size_t injectSize, void payloadFunction())
{
    void* relayFuncMemory = AllocatePageNearAddress(func2hook);
    if (!relayFuncMemory)
    {
        DEBUG_TRACE("Unable to allocate page near address");
        return false;
    }
    WriteAbsoluteJump64(relayFuncMemory, reinterpret_cast<void*>(payloadFunction)); //write relay func instructions

    // now that the relay function is built, we need to install the E9 jump into the target func,
    // this will jump to the relay function

    // 32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
    constexpr uint8_t jmpInstruction = 0xE9;

    // to fill out the last 4 bytes of jmpInstruction, we need the offset between 
    // the relay function and the instruction immediately AFTER the jmp instruction
    const uint32_t relAddr = static_cast<int8_t*>(relayFuncMemory) - (static_cast<int8_t*>(func2hook) + sizeof jmpInstruction + sizeof uint32_t);

    // install the hook
    auto code = static_cast<uint8_t*>(func2hook);
    *code = jmpInstruction;
    code += sizeof jmpInstruction;
    *reinterpret_cast<uint32_t*>(code) = relAddr;
    code += sizeof relAddr;

    injectSize -= sizeof jmpInstruction + sizeof relAddr;
    if (injectSize > 0)
        memset(code, 0x90, injectSize);

    return true;
}
