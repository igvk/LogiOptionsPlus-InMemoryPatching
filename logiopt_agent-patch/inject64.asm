
public original_jump_address
extern patched_switch_foreground_process_handler : proc

.data

original_jump_address dq 0

.code

; Injected procedure must be called by jmp from the patched code
; original_jump_address should be set beforehand to the return code address

injected_handler_V100 proc
    ; Not saving registers in stack, due to not reqired by the patched code
    ; This means that we can follow x64 calling convention without modifying stack
    ;push rcx
    ;push rdx
    ;push rsi
    ;push r8
    ;;push r9
    ;;push r10
    ;;push r11
    ; Next command is dependent on stack pointer not changed
    lea rcx, [rsp+0B8h-40h]
    cmp rdi, 10h
    cmovnb rcx, rbx ; name
    mov rdx, rsi ; length
    movzx r8, al ; previous check
    call patched_switch_foreground_process_handler
    mov [rbp+28h], al
    mov rdi, [rbp+8h]
    ;;pop r11
    ;;pop r10
    ;;pop r9
    ;pop r8
    ;pop rsi
    ;pop rdx
    ;pop rcx
    jmp [original_jump_address]
injected_handler_V100 endp

injected_handler_V146 proc
    ; Not saving registers in stack, due to not reqired by the patched code
    lea rcx, [rbp+57h-58h]
    cmp r14, 10h
    cmovnb rcx, rsi ; name
    mov rdx, rbx ; length
    movzx r8, al ; previous check
    call patched_switch_foreground_process_handler
    mov [r12+28h], al
    mov r12, [r12+8h]
    jmp [original_jump_address]
injected_handler_V146 endp

injected_handler_V168 proc
    ; Not saving registers in stack, due to not reqired by the patched code
    lea rcx, [rbp+57h-78h]
    cmp r14, 10h
    cmovnb rcx, rdi ; name
    mov rdx, rbx ; length
    movzx r8, al ; previous check
    call patched_switch_foreground_process_handler
    mov [r12+28h], al
    mov r12, [r12+8h]
    jmp [original_jump_address]
injected_handler_V168 endp

end
