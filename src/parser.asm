section .text

; parse_request(buffer rcx, size edx, info r8) ->
; 0 incomplete, 1 complete, 2 malformed, 3 too large.
parse_request:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp,48h
    mov r12,rcx
    mov r13d,edx
    mov r14,r8
    mov [r14+INFO_REQUEST],r12
    cmp r13d,REQUEST_CAP
    jae .too_large

    ; Find CRLFCRLF without reading past the received bytes.
    cmp r13d,4
    jb .incomplete
    xor ebx,ebx
.find_end:
    lea eax,[ebx+4]
    cmp eax,r13d
    ja .incomplete
    cmp dword [r12+rbx],0x0a0d0a0d
    je .headers_found
    inc ebx
    jmp .find_end
.headers_found:
    lea eax,[ebx+4]
    mov [r14+INFO_HEADER_END],eax

    ; Parse request method and path from the request line.
    mov rsi,r12
    xor edi,edi
    cmp r13d,4
    jb .bad
    cmp dword [rsi],'GET '
    je .get
    cmp dword [rsi],'POST'
    je .post
    cmp dword [rsi],'PUT '
    je .put
    cmp dword [rsi],'DELE'
    jne .bad
    cmp byte [rsi+4],'T'
    jne .bad
    mov edi,4
    lea rsi,[rsi+5]
    jmp .method_done
.get:
    mov edi,1
    lea rsi,[rsi+4]
    jmp .method_done
.post:
    cmp byte [rsi+4],' '
    jne .bad
    mov edi,2
    lea rsi,[rsi+5]
    jmp .method_done
.put:
    mov edi,3
    lea rsi,[rsi+4]
.method_done:
    mov [r14+INFO_METHOD],edi
    mov rdi,rsi
.find_path_end:
    mov eax,[r14+INFO_HEADER_END]
    add rax,r12
    cmp rsi,rax
    jae .bad
    cmp byte [rsi],' '
    je .path_found
    inc rsi
    jmp .find_path_end
.path_found:
    cmp rsi,rdi
    je .bad
    mov [r14+INFO_PATH],rdi
    mov rax,rsi
    sub rax,rdi
    mov edx,eax
    ; Strip query parameters for route matching.
    mov dword [r14+INFO_QUERY_LEN],0
    xor ecx,ecx
.query_scan:
    cmp ecx,edx
    jae .path_ready
    cmp byte [rdi+rcx],'?'
    je .query_found
    inc ecx
    jmp .query_scan
.query_found:
    lea rax,[rdi+rcx+1]
    mov [r14+INFO_QUERY],rax
    mov eax,edx
    sub eax,ecx
    dec eax
    mov [r14+INFO_QUERY_LEN],eax
    mov edx,ecx
.path_ready:
    cmp byte [r14+INFO_QUERY_LEN],0
    jne .query_ready
    mov qword [r14+INFO_QUERY],0
.query_ready:
    mov [r14+INFO_PATH_LEN],edx
    lea rsi,[rsi+1]
    lea rax,[rsi+8]
    mov rcx,r12
    mov edx,[r14+INFO_HEADER_END]
    add rcx,rdx
    cmp rax,rcx
    ja .bad
    mov rax,0x312e312f50545448          ; HTTP/1.1
    cmp qword [rsi],rax
    jne .bad
    cmp word [rsi+8],0x0a0d
    jne .bad

    ; Parse Content-Length. Missing header means an empty body.
    mov dword [r14+INFO_BODY_LEN],0
    mov eax,[r14+INFO_HEADER_END]
    lea rcx,[r12+rax]
    mov [r14+INFO_BODY],rcx
    lea rdi,[rsi+10]
    mov rbx,r12
    mov eax,[r14+INFO_HEADER_END]
    add rbx,rax
.header_loop:
    cmp rdi,rbx
    jae .complete
    cmp word [rdi],0x0a0d
    je .complete
    mov rsi,rdi
.header_eol:
    cmp rsi,rbx
    jae .bad
    cmp word [rsi],0x0a0d
    je .header_line
    inc rsi
    jmp .header_eol
.header_line:
    mov rdx,rsi
    sub rdx,rdi
    cmp edx,15
    jb .next_header
    ; Case-insensitive Content-Length: prefix.
    mov ecx,0
.cl_match:
    cmp ecx,14
    jae .cl_colon
    mov al,[rdi+rcx]
    or al,32
    lea r8,[content_length_name]
    cmp al,[r8+rcx]
    jne .next_header
    inc ecx
    jmp .cl_match
.cl_colon:
    cmp byte [rdi+14],':'
    jne .next_header
    lea rax,[rdi+15]
.skip_spaces:
    cmp rax,rsi
    jae .bad
    cmp byte [rax],' '
    jne .parse_digits
    inc rax
    jmp .skip_spaces
.parse_digits:
    xor r8d,r8d
    cmp rax,rsi
    jae .bad
.digit_loop:
    movzx ecx,byte [rax]
    cmp ecx,'0'
    jb .bad
    cmp ecx,'9'
    ja .bad
    imul r8d,r8d,10
    sub ecx,'0'
    add r8d,ecx
    cmp r8d,REQUEST_CAP
    ja .too_large
    inc rax
    cmp rax,rsi
    jb .digit_loop
    mov [r14+INFO_BODY_LEN],r8d
.next_header:
    lea rdi,[rsi+2]
    jmp .header_loop
.complete:
    mov eax,[r14+INFO_HEADER_END]
    add eax,[r14+INFO_BODY_LEN]
    cmp eax,REQUEST_CAP
    ja .too_large
    cmp r13d,eax
    jb .incomplete
    mov eax,1
    jmp .done
.incomplete:
    xor eax,eax
    jmp .done
.bad:
    mov eax,2
    jmp .done
.too_large:
    mov eax,3
.done:
    add rsp,48h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

section .data
content_length_name db 'content-length'
