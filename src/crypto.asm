section .data
sha256_name dw 0053h,0048h,0041h,0032h,0035h,0036h,0000h

section .text

; BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG).
crypto_random:
    sub rsp,38h
    mov r8d,edx
    mov rdx,rcx
    xor ecx,ecx
    mov r9d,BCRYPT_USE_SYSTEM_PREFERRED_RNG
    call BCryptGenRandom
    test eax,eax
    setz al
    movzx eax,al
    add rsp,38h
    ret

crypto_init:
    sub rsp,38h
    lea rcx,[sha256_alg]
    lea rdx,[sha256_name]
    xor r8d,r8d
    xor r9d,r9d
    call BCryptOpenAlgorithmProvider
    test eax,eax
    setz al
    movzx eax,al
    add rsp,38h
    ret

crypto_shutdown:
    sub rsp,38h
    mov rcx,[sha256_alg]
    test rcx,rcx
    jz .done
    xor edx,edx
    call BCryptCloseAlgorithmProvider
    mov qword [sha256_alg],0
.done:
    add rsp,38h
    ret

; hash_password(password rcx, length edx, salt r8, output r9).
; SHA-256(salt || password), with a random 128-bit salt stored per account.
hash_password:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,360h
    mov r12,rcx
    mov r13d,edx
    mov r14,r8
    mov r15,r9
    mov rbx,[sha256_alg]
    test rbx,rbx
    jz .fail

    lea rdx,[rsp+18h]
    mov rcx,rbx
    lea r8,[rsp+40h]
    mov r9d,512
    mov qword [rsp+20h],0
    mov qword [rsp+28h],0
    mov qword [rsp+30h],0
    call BCryptCreateHash
    test eax,eax
    jnz .fail

    mov rcx,[rsp+18h]
    mov rdx,r14
    mov r8d,16
    xor r9d,r9d
    call BCryptHashData
    test eax,eax
    jnz .destroy_fail
    mov rcx,[rsp+18h]
    mov rdx,r12
    mov r8d,r13d
    xor r9d,r9d
    call BCryptHashData
    test eax,eax
    jnz .destroy_fail
    mov rcx,[rsp+18h]
    mov rdx,r15
    mov r8d,32
    xor r9d,r9d
    call BCryptFinishHash
    test eax,eax
    jnz .destroy_fail
    mov rcx,[rsp+18h]
    call BCryptDestroyHash
    mov eax,1
    jmp .done
.destroy_fail:
    mov rcx,[rsp+18h]
    call BCryptDestroyHash
.fail:
    xor eax,eax
.done:
    add rsp,360h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; hex_encode(input rcx, byte_count edx, output r8).
hex_encode:
    push rbx
    push rsi
    push rdi
    mov rsi,rcx
    mov rdi,r8
    mov ebx,edx
    lea r8,[hex_digits]
.loop:
    test ebx,ebx
    jz .done
    movzx eax,byte [rsi]
    mov edx,eax
    shr eax,4
    and edx,0fh
    mov al,[r8+rax]
    mov [rdi],al
    mov al,[r8+rdx]
    mov [rdi+1],al
    inc rsi
    add rdi,2
    dec ebx
    jmp .loop
.done:
    pop rdi
    pop rsi
    pop rbx
    ret

; hex_decode(input rcx, hex_char_count edx, output r8) -> eax=1/0.
hex_decode:
    push rbx
    push rsi
    push rdi
    mov rsi,rcx
    mov rdi,r8
    mov ebx,edx
    test ebx,1
    jnz .fail
.loop:
    test ebx,ebx
    jz .ok
    movzx eax,byte [rsi]
    call hex_nibble
    jc .fail
    shl eax,4
    mov edx,eax
    movzx eax,byte [rsi+1]
    call hex_nibble
    jc .fail
    or eax,edx
    mov [rdi],al
    add rsi,2
    inc rdi
    sub ebx,2
    jmp .loop
.ok:
    mov eax,1
    jmp .done
.fail:
    xor eax,eax
.done:
    pop rdi
    pop rsi
    pop rbx
    ret

hex_nibble:
    cmp al,'0'
    jb .letter
    cmp al,'9'
    ja .letter
    sub al,'0'
    clc
    ret
.letter:
    or al,32
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
    sub al,'a'-10
    clc
    ret
.bad:
    stc
    ret

; uuid_decode(text rcx, length edx, output r8) -> eax=1/0.
uuid_decode:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,40h
    cmp edx,36
    jne .fail
    mov rsi,rcx
    mov rdi,r8
    xor ebx,ebx
    xor r12d,r12d
.loop:
    cmp r12d,16
    jae .ok
.skip_hyphen:
    cmp byte [rsi+rbx],'-'
    jne .pair
    inc ebx
    jmp .skip_hyphen
.pair:
    mov al,[rsi+rbx]
    call hex_nibble
    jc .fail
    shl eax,4
    mov r13d,eax
    mov al,[rsi+rbx+1]
    call hex_nibble
    jc .fail
    or eax,r13d
    mov [rdi+r12],al
    add ebx,2
    inc r12d
    jmp .loop
.ok:
    cmp ebx,36
    jne .fail
    mov eax,1
    jmp .done
.fail:
    xor eax,eax
.done:
    add rsp,40h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
