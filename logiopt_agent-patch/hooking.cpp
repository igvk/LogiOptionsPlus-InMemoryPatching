#include <cstdint>
#include <windows.h>
#include "common.hpp"
#include "hooking.hpp"

void* AllocatePageNearAddress(void* targetAddr)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;
    constexpr uint64_t maxDisp = 0x7FFFFF00;

    uint64_t startPage = reinterpret_cast<uint64_t>(targetAddr) & ~(PAGE_SIZE - 1); //round down to nearest page boundary
    uint64_t minAddr = reinterpret_cast<uint64_t>(sysInfo.lpMinimumApplicationAddress);
    uint64_t addr = startPage > maxDisp ? startPage - maxDisp : 0;
    minAddr = addr >= minAddr ? addr : minAddr;
    uint64_t maxAddr = reinterpret_cast<uint64_t>(sysInfo.lpMaximumApplicationAddress);
    addr = startPage < UINT64_MAX - maxDisp ? startPage + maxDisp : UINT64_MAX;
    maxAddr = addr <= maxAddr ? addr : maxAddr;
    uint64_t byteOffset = PAGE_SIZE;
    uint64_t highAddr, lowAddr;

    do
    {
        highAddr = startPage < UINT64_MAX - byteOffset ? startPage + byteOffset : UINT64_MAX;
        lowAddr = startPage > byteOffset ? startPage - byteOffset : 0;
        if (highAddr < maxAddr)
        {
            void* outAddr = VirtualAlloc(reinterpret_cast<void*>(highAddr), PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  // NOLINT(performance-no-int-to-ptr)
            if (outAddr)
                return outAddr;
        }
        if (lowAddr > minAddr)
        {
            void* outAddr = VirtualAlloc(reinterpret_cast<void*>(lowAddr), PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  // NOLINT(performance-no-int-to-ptr)
            if (outAddr != nullptr)
                return outAddr;
        }
        byteOffset += PAGE_SIZE;
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
