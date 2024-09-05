
memcmp proto; :qword,:qword,:qword

.data

firefox_exe db "firefox.exe", 0

.code

target_handler_V100 proc
    push rbp
    push rbx
    push rdi
    push rsi
    sub rsp, 0C0h-40h
    mov rbp, rsp
    mov rbx, rcx ; name
    mov rsi, rdx ; length
    mov [rsp+0B8h-40h], rcx
    mov rdi, 10h
    lea rcx, [rsp+0B8h-40h]
    cmp rdi, 10h
    cmovnb rcx, rbx
    cmp rsi, sizeof firefox_exe - 1
    jnz notfound
    mov r8, rsi
    lea rdx, [firefox_exe]
    call memcmp
    test eax, eax
    jz notfound
found:
    mov al, 1
    jmp return
notfound:
    xor al, al
return:
    mov [rbp+28h], al
    mov rdi, [rbp+8h]
    add rsp, 0C0h-40h
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret
    db 12 dup(0cch)
target_handler_V100 endp

target_handler_V146 proc
    push rbp
    push rbx
    push rsi
    push r12
    push r14
    lea rbp, [rsp-27h]
    sub rsp, 0A0h
    mov rsi, rcx ; name
    mov rbx, rdx ; length
    mov r12, rsp
    mov [rbp+57h-58h], rcx
    mov r14, 10h
    lea rcx, [rbp+57h-58h]
    cmp r14, 10h
    cmovnb rcx, rsi
    cmp rbx, sizeof firefox_exe - 1
    jnz notfound
    mov r8, rbx
    lea rdx, [firefox_exe]
    call memcmp
    test eax, eax
    jz notfound
found:
    mov al, 1
    jmp return
notfound:
    xor al, al
return:
    mov [r12+28h], al
    mov r12, [r12+8h]
    add rsp, 0A0h
    pop r14
    pop r12
    pop rsi
    pop rbx
    pop rbp
    ret
    db 12 dup(0cch)
target_handler_V146 endp

target_handler_V168 proc
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r14
    lea rbp, [rsp-27h]
    sub rsp, 0B0h
    mov rdi, rcx ; name
    mov rbx, rdx ; length
    mov r12, rsp
    mov [rbp+57h-78h], rcx
    mov r14, 10h
    lea rcx, [rbp+57h-78h]
    cmp r14, 10h
    cmovnb rcx, rdi
    cmp rbx, sizeof firefox_exe - 1
    jnz notfound
    mov r8, rbx
    lea rdx, [firefox_exe]
    call memcmp
    test eax, eax
    jz notfound
found:
    mov al, 1
    jmp return
notfound:
    xor al, al
return:
    mov [r12+28h], al
    mov r12, [r12+8h]
    add rsp, 0B0h
    pop r14
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
    db 12 dup(0cch)
target_handler_V168 endp

end