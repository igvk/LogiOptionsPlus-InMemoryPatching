
extern patched_switch_foreground_process_handler : proc
;externdef c original_jump_address : qword

.data

original_jump_address dd 0

.code

injected_handler proc
    push eax ; previous check
    push esi ; length
    push ecx ; name
    call patched_switch_foreground_process_handler
    add esp, 4 * 3
    jmp [original_jump_address]
    mov [ebp+14h], al
    mov edi, [rbp+4]
injected_handler endp

end
