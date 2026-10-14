section .text

main:
    push rbp
    mov rbp,rsp
    sub rsp,60h

    mov ecx,STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [stdout_handle],rax
    mov rcx,rax
    lea rdx,[startup_msg]
    mov r8d,startup_msg_len
    lea r9,[bytes_written]
    mov qword [rsp+20h],0
    call WriteFile

    mov ecx,0202h
    lea rdx,[wsadata]
    call WSAStartup
    test eax,eax
    jnz .wsa_fail
    call crypto_init
    test eax,eax
    jz .crypto_fail
    call storage_init
    test eax,eax
    jz .storage_fail
    mov ecx,AF_INET
    mov edx,SOCK_STREAM
    mov r8d,IPPROTO_TCP
    call socket
    cmp rax,INVALID_SOCKET
    je .socket_fail
    mov [server_socket],rax
    mov qword [rsp+20h],4
    mov rcx,rax
    mov edx,SOL_SOCKET
    mov r8d,SO_REUSEADDR
    lea r9,[reuse_addr]
    call setsockopt
    mov rcx,[server_socket]
    lea rdx,[listen_addr]
    mov r8d,16
    call bind
    cmp eax,SOCKET_ERROR
    je .bind_fail
    mov rcx,[server_socket]
    mov edx,128
    call listen
    cmp eax,SOCKET_ERROR
    je .listen_fail

.accept_loop:
    mov rcx,[server_socket]
    xor edx,edx
    xor r8d,r8d
    call accept
    cmp rax,INVALID_SOCKET
    je .close_server
    ; One heap-backed request arena per client makes worker state thread-safe.
    mov r9,rax
    mov [rsp+30h],rax
    xor ecx,ecx
    xor edx,edx
    lea r8,[client_worker]
    mov qword [rsp+20h],0
    mov qword [rsp+28h],0
    call CreateThread
    test rax,rax
    jz .thread_failed
    mov rcx,rax
    call CloseHandle
    jmp .accept_loop
.thread_failed:
    mov rcx,[rsp+30h]
    call closesocket
    jmp .accept_loop
.close_server:
    mov rcx,[server_socket]
    call closesocket
.cleanup:
    call WSACleanup
.crypto_cleanup:
    call crypto_shutdown
.exit:
    xor ecx,ecx
    call ExitProcess
    ud2
.wsa_fail:
    lea rcx,[diag_wsa]
    mov edx,diag_wsa_len
    call server_log
    jmp .exit
.crypto_fail:
    lea rcx,[diag_crypto]
    mov edx,diag_crypto_len
    call server_log
    jmp .cleanup
.storage_fail:
    lea rcx,[diag_storage]
    mov edx,diag_storage_len
    call server_log
    jmp .cleanup
.socket_fail:
    lea rcx,[diag_socket]
    mov edx,diag_socket_len
    call server_log
    jmp .cleanup
.bind_fail:
    lea rcx,[diag_bind]
    mov edx,diag_bind_len
    call server_log
    call server_log_wsa
    jmp .close_server
.listen_fail:
    lea rcx,[diag_listen]
    mov edx,diag_listen_len
    call server_log
    call server_log_wsa
    jmp .close_server

; server_log(message rcx, length edx).
server_log:
    push rbx
    sub rsp,40h
    mov rbx,rcx
    mov r8d,edx
    mov rcx,[stdout_handle]
    mov rdx,rbx
    lea r9,[bytes_written]
    mov qword [rsp+20h],0
    call WriteFile
    add rsp,40h
    pop rbx
    ret

server_log_wsa:
    push rbx
    push rsi
    push rdi
    sub rsp,40h
    call WSAGetLastError
    mov ebx,eax
    lea rdi,[error_hex+8]
    lea rsi,[hex_digits]
    mov ecx,8
.hex:
    mov edx,ebx
    and edx,0fh
    mov dl,[rsi+rdx]
    dec rdi
    mov [rdi],dl
    shr ebx,4
    dec ecx
    jnz .hex
    lea rcx,[diag_wsa_prefix]
    mov edx,diag_wsa_prefix_len
    call server_log
    lea rcx,[error_hex]
    mov edx,8
    call server_log
    lea rcx,[diag_wsa_suffix]
    mov edx,diag_wsa_suffix_len
    call server_log
    add rsp,40h
    pop rdi
    pop rsi
    pop rbx
    ret

; DWORD WINAPI client_worker(SOCKET client_socket).
client_worker:
    push rbp
    mov rbp,rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,48h
    mov r12,rcx
    call GetProcessHeap
    mov rsi,rax
    mov [rsp+30h],rax
    mov rcx,rsi
    xor edx,edx
    mov r8d,WORK_SIZE
    call HeapAlloc
    test rax,rax
    jz .close_socket
    mov r13,rax
    mov rdi,rax
    lea r14,[rax+REQUEST_CAP]
    lea r15,[r14+RESPONSE_CAP]
    mov dword [rsp+20h],4
    mov rcx,r12
    mov edx,SOL_SOCKET
    mov r8d,SO_RCVTIMEO
    lea r9,[recv_timeout]
    call setsockopt
    xor ebx,ebx
.read:
    cmp ebx,REQUEST_CAP
    jae .large
    mov rcx,r12
    lea rdx,[r13+rbx]
    mov r8d,REQUEST_CAP
    sub r8d,ebx
    xor r9d,r9d
    call recv
    test eax,eax
    jle .cleanup_worker
    add ebx,eax
    mov rcx,r13
    mov edx,ebx
    mov r8,r15
    call parse_request
    test eax,eax
    jz .read
    cmp eax,1
    je .route
    cmp eax,3
    je .large
    ; malformed request
    lea rax,[body_bad]
    mov [rsp+20h],rax
    mov dword [rsp+28h],body_bad_len
    mov rcx,r12
    mov rdx,r14
    lea r8,[status_400]
    mov r9d,status_400_len
    call send_json
    jmp .cleanup_worker
.large:
    lea rax,[body_large]
    mov [rsp+20h],rax
    mov dword [rsp+28h],body_large_len
    mov rcx,r12
    mov rdx,r14
    lea r8,[status_413]
    mov r9d,status_413_len
    call send_json
    jmp .cleanup_worker
.route:
    mov rcx,r12
    mov rdx,r15
    mov r8,r14
    call route_request
.cleanup_worker:
    mov rcx,r12
    call closesocket
    mov rcx,rsi
    xor edx,edx
    mov r8,rdi
    call HeapFree
    jmp .close_only
.close_socket:
    mov rcx,r12
    call closesocket
.close_only:
    xor eax,eax
    add rsp,48h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
