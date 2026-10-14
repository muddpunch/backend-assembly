section .text

; send_all(SOCKET rcx, const void *rdx, uint32_t r8d).
; Winsock may return short writes; loop until all bytes are sent.
send_all:
    push rbx
    push rsi
    push rdi
    sub rsp,40h
    mov rbx,rcx
    mov rsi,rdx
    mov edi,r8d
.loop:
    test edi,edi
    jz .done
    mov rcx,rbx
    mov rdx,rsi
    mov r8d,edi
    xor r9d,r9d
    call send
    test eax,eax
    jle .done
    add rsi,rax
    sub edi,eax
    jmp .loop
.done:
    add rsp,40h
    pop rdi
    pop rsi
    pop rbx
    ret

; send_json(SOCKET rcx, response_buffer rdx, status r8, status_len r9d,
;           body [rsp+28h], body_len [rsp+30h]).
send_json:
    mov r10,[rsp+28h]
    mov r11d,[rsp+30h]
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,40h
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    mov r15d,r9d

    cld
    mov rdi,r13
    mov rsi,r14
    mov ecx,r15d
    rep movsb
    lea rsi,[json_header]
    mov ecx,json_header_len
    rep movsb

    ; Decimal Content-Length conversion, written backwards in local scratch.
    lea rbx,[rsp+20h]
    mov eax,r11d
    mov ecx,10
.digits:
    xor edx,edx
    div ecx
    add dl,'0'
    dec rbx
    mov [rbx],dl
    test eax,eax
    jnz .digits
    mov rsi,rbx
    lea rax,[rsp+20h]
    sub rax,rbx
    mov ecx,eax
    rep movsb
    lea rsi,[crlf2]
    mov ecx,4
    rep movsb
    mov rsi,r10
    mov ecx,r11d
    rep movsb

    mov rdx,r13
    mov r8,rdi
    sub r8,rdx
    mov rcx,r12
    call send_all

    add rsp,40h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; send_204(SOCKET rcx, response_buffer rdx).
send_204:
    push rbx
    push rsi
    push r12
    sub rsp,40h
    mov rbx,rcx
    mov r12,rdx
    mov rdi,r12
    lea rsi,[status_204]
    mov ecx,status_204_len
    cld
    rep movsb
    lea rsi,[plain_204]
    mov ecx,plain_204_len
    rep movsb
    mov rcx,rbx
    mov rdx,r12
    mov r8d,status_204_len + plain_204_len
    call send_all
    add rsp,40h
    pop r12
    pop rsi
    pop rbx
    ret
