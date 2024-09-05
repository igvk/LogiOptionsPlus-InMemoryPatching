#pragma once
void* AllocatePageNearAddress(void* targetAddr);
void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo);
bool InstallCaveHook(void* func2hook, size_t injectSize, void* caveRelayMemory, void payloadFunction());
bool InstallAllocateHook(void* func2hook, size_t injectSize, void payloadFunction());
