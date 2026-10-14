section .text

storage_lock:
    mov rcx,[storage_mutex]
    test rcx,rcx
    jz .ok
    mov edx,0ffffffffh
    sub rsp,38h
    call WaitForSingleObject
    add rsp,38h
    cmp eax,WAIT_OBJECT_0
    jne .fail
.ok:
    mov eax,1
    ret
.fail:
    xor eax,eax
    ret

storage_unlock:
    mov rcx,[storage_mutex]
    test rcx,rcx
    jz .done
    sub rsp,38h
    call ReleaseMutex
    add rsp,38h
.done:
    ret

storage_init:
    sub rsp,48h
    lea rcx,[storage_dir]
    xor edx,edx
    call CreateDirectoryA
    xor ecx,ecx
    xor edx,edx
    lea r8,[storage_mutex_name]
    call CreateMutexA
    mov [storage_mutex],rax
    test rax,rax
    jz .fail
    call storage_load_accounts
    call storage_load_sessions
    mov eax,1
    jmp .done
.fail:
    xor eax,eax
.done:
    add rsp,48h
    ret

storage_load_accounts:
    sub rsp,48h
    lea rcx,[accounts_file]
    mov edx,GENERIC_READ
    mov r8d,FILE_SHARE_READ | FILE_SHARE_WRITE
    xor r9d,r9d
    mov qword [rsp+20h],OPEN_EXISTING
    mov qword [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+30h],0
    call CreateFileA
    cmp rax,INVALID_HANDLE
    je .done
    mov r12,rax
    mov rcx,rax
    xor edx,edx
    call GetFileSize
    cmp eax,ACCOUNT_SIZE
    jb .close
    xor edx,edx
    mov ecx,ACCOUNT_SIZE
    div ecx
    cmp eax,MAX_ACCOUNTS
    jbe .count_ok
    mov eax,MAX_ACCOUNTS
.count_ok:
    mov [account_count],eax
    imul r8d,eax,ACCOUNT_SIZE
    mov rcx,r12
    lea rdx,[accounts]
    lea r9,[rsp+40h]
    mov qword [rsp+20h],0
    call ReadFile
.close:
    mov rcx,r12
    call CloseHandle
.done:
    add rsp,48h
    ret

storage_load_sessions:
    sub rsp,48h
    lea rcx,[sessions_file]
    mov edx,GENERIC_READ
    mov r8d,FILE_SHARE_READ | FILE_SHARE_WRITE
    xor r9d,r9d
    mov qword [rsp+20h],OPEN_EXISTING
    mov qword [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+30h],0
    call CreateFileA
    cmp rax,INVALID_HANDLE
    je .done
    mov r12,rax
    mov rcx,rax
    xor edx,edx
    call GetFileSize
    cmp eax,SESSION_SIZE
    jb .close
    xor edx,edx
    mov ecx,SESSION_SIZE
    div ecx
    cmp eax,MAX_SESSIONS
    jbe .count_ok
    mov eax,MAX_SESSIONS
.count_ok:
    mov [session_count],eax
    imul r8d,eax,SESSION_SIZE
    mov rcx,r12
    lea rdx,[sessions]
    lea r9,[rsp+40h]
    mov qword [rsp+20h],0
    call ReadFile
.close:
    mov rcx,r12
    call CloseHandle
.done:
    add rsp,48h
    ret

; storage_append(path rcx, record rdx, size r8d) -> eax=1/0.
storage_append:
    push r12
    push r13
    push r14
    sub rsp,40h
    mov r12,rcx
    mov r13,rdx
    mov r14d,r8d
    mov rcx,r12
    mov edx,GENERIC_READ | GENERIC_WRITE
    mov r8d,FILE_SHARE_READ
    xor r9d,r9d
    mov qword [rsp+20h],OPEN_ALWAYS
    mov qword [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+30h],0
    call CreateFileA
    cmp rax,INVALID_HANDLE
    je .unlock_fail
    mov r12,rax
    mov rcx,rax
    xor edx,edx
    xor r8d,r8d
    mov r9d,FILE_END
    call SetFilePointer
    mov rcx,r12
    mov rdx,r13
    mov r8d,r14d
    lea r9,[rsp+38h]
    mov qword [rsp+20h],0
    call WriteFile
    test eax,eax
    jz .close_fail
    mov rcx,r12
    call FlushFileBuffers
    mov rcx,r12
    call CloseHandle
    mov eax,1
    jmp .done
.close_fail:
    mov rcx,r12
    call CloseHandle
.unlock_fail:
.fail:
    xor eax,eax
.done:
    add rsp,40h
    pop r14
    pop r13
    pop r12
    ret

; storage_find_username(username rcx, length edx) -> account pointer or 0.
storage_find_username:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,40h
    mov r12,rcx
    mov r13d,edx
    call storage_lock
    test eax,eax
    jz .not_found
    call storage_find_username_unlocked
    mov rbx,rax
    call storage_unlock
    mov rax,rbx
    jmp .done
.not_found:
    xor eax,eax
.done:
    add rsp,40h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

storage_find_username_unlocked:
    xor ebx,ebx
    mov eax,[account_count]
.account_loop:
    cmp ebx,eax
    jae .not_found
    imul edx,ebx,ACCOUNT_SIZE
    lea rsi,[rel accounts+ACC_NAME]
    add rsi,rdx
    cmp r13d,31
    ja .next
    xor edi,edi
.char_loop:
    cmp edi,r13d
    jae .end_name
    movzx ecx,byte [r12+rdi]
    movzx edx,byte [rsi+rdi]
    or ecx,20h
    or edx,20h
    cmp ecx,edx
    jne .next
    inc edi
    jmp .char_loop
.end_name:
    cmp byte [rsi+rdi],0
    jne .next
    imul edx,ebx,ACCOUNT_SIZE
    lea rax,[rel accounts]
    add rax,rdx
    ret
.next:
    inc ebx
    jmp .account_loop
.not_found:
    xor eax,eax
    ret

; storage_find_id(raw_id rcx) -> account pointer or 0.
storage_find_id:
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp,28h
    mov r12,rcx
    call storage_lock
    test eax,eax
    jz .not_found
    xor ebx,ebx
    mov eax,[account_count]
.loop:
    cmp ebx,eax
    jae .unlock_not_found
    imul edx,ebx,ACCOUNT_SIZE
    lea rsi,[rel accounts+ACC_ID]
    add rsi,rdx
    mov rdi,r12
    mov ecx,16
    repe cmpsb
    je .found
    inc ebx
    jmp .loop
.found:
    imul edx,ebx,ACCOUNT_SIZE
    lea rax,[rel accounts]
    add rax,rdx
    mov r12,rax
    call storage_unlock
    mov rax,r12
    jmp .done
.unlock_not_found:
    call storage_unlock
.not_found:
    xor eax,eax
.done:
    add rsp,28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; storage_create_account(username rcx, name_len edx, password r8, password_len r9d).
storage_create_account:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,40h
    mov r12,rcx
    mov r13d,edx
    mov r14,r8
    mov r15d,r9d
    cmp r13d,3
    jb .fail
    cmp r13d,31
    ja .fail
    cmp r15d,1
    jb .fail
    cmp r15d,256
    ja .fail
    call storage_lock
    test eax,eax
    jz .fail
    mov ecx,[account_count]
    cmp ecx,MAX_ACCOUNTS
    jae .unlock_fail
    mov rcx,r12
    mov edx,r13d
    call storage_find_username_unlocked
    test rax,rax
    jnz .unlock_fail
    mov eax,[account_count]
    imul edx,eax,ACCOUNT_SIZE
    lea rbx,[rel accounts]
    add rbx,rdx
    mov rdi,rbx
    xor eax,eax
    mov ecx,ACCOUNT_SIZE
    rep stosb
    mov rcx,rbx
    mov edx,16
    call crypto_random
    test eax,eax
    jz .unlock_fail
    lea rcx,[rbx+ACC_SALT]
    mov edx,16
    call crypto_random
    test eax,eax
    jz .unlock_fail
    mov rcx,r14
    mov edx,r15d
    lea r8,[rbx+ACC_SALT]
    lea r9,[rbx+ACC_HASH]
    call hash_password
    test eax,eax
    jz .unlock_fail
    mov rsi,r12
    lea rdi,[rbx+ACC_NAME]
    mov ecx,r13d
    rep movsb
    mov byte [rdi],0
    lea rcx,[rbx+ACC_CREATED]
    call GetSystemTimeAsFileTime
    lea rcx,[accounts_file]
    mov rdx,rbx
    mov r8d,ACCOUNT_SIZE
    call storage_append
    test eax,eax
    jz .unlock_fail
    inc dword [account_count]
    call storage_unlock
    mov rax,rbx
    jmp .done
.unlock_fail:
    call storage_unlock
.fail:
    xor eax,eax
.done:
    add rsp,40h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; storage_verify_password(account rcx, password rdx, length r8d) -> eax=1/0.
storage_verify_password:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,78h
    mov r12,rcx
    mov r13,rdx
    mov r14d,r8d
    mov rcx,r13
    mov edx,r14d
    lea r8,[r12+ACC_SALT]
    lea r9,[rsp+40h]
    call hash_password
    test eax,eax
    jz .fail
    lea rsi,[rsp+40h]
    lea rdi,[r12+ACC_HASH]
    mov ecx,32
    repe cmpsb
    sete al
    movzx eax,al
    jmp .done
.fail:
    xor eax,eax
.done:
    add rsp,78h
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; storage_create_session(account rcx, client_id rdx, client_len r8d) -> session pointer/0.
storage_create_session:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp,58h
    mov r12,rcx
    mov r13,rdx
    mov r14d,r8d
    call storage_lock
    test eax,eax
    jz .fail
    mov eax,[session_count]
    cmp eax,MAX_SESSIONS
    jae .unlock_fail
    imul edx,eax,SESSION_SIZE
    lea rbx,[rel sessions]
    add rbx,rdx
    mov rdi,rbx
    xor eax,eax
    mov ecx,SESSION_SIZE
    rep stosb
    mov rcx,rbx
    mov edx,32
    call crypto_random
    test eax,eax
    jz .unlock_fail
    lea rcx,[rbx+SES_REFRESH]
    mov edx,32
    call crypto_random
    test eax,eax
    jz .unlock_fail
    lea rsi,[r12+ACC_ID]
    lea rdi,[rbx+SES_ACCOUNT]
    mov ecx,16
    rep movsb
    lea rsi,[r13]
    lea rdi,[rbx+SES_CLIENT]
    mov ecx,r14d
    cmp ecx,31
    jbe .client_len_ok
    mov ecx,31
.client_len_ok:
    rep movsb
    mov byte [rdi],0
    lea rcx,[rbx+SES_ACCESS_EXP]
    call GetSystemTimeAsFileTime
    mov rax,[rbx+SES_ACCESS_EXP]
    mov rcx,288000000000
    add rax,rcx
    mov [rbx+SES_ACCESS_EXP],rax
    mov rax,[rbx+SES_ACCESS_EXP]
    mov rcx,864000000000
    add rax,rcx
    mov [rbx+SES_REFRESH_EXP],rax
    lea rcx,[sessions_file]
    mov rdx,rbx
    mov r8d,SESSION_SIZE
    call storage_append
    test eax,eax
    jz .unlock_fail
    inc dword [session_count]
    call storage_unlock
    mov rax,rbx
    jmp .done
.unlock_fail:
    call storage_unlock
.fail:
    xor eax,eax
.done:
    add rsp,58h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; storage_find_token(raw token rcx, token offset edx, expiration offset r8d).
storage_find_token:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,48h
    mov r12,rcx
    mov r13d,edx
    mov r14d,r8d
    call storage_lock
    test eax,eax
    jz .not_found
    lea rcx,[rsp+30h]
    call GetSystemTimeAsFileTime
    xor ebx,ebx
    mov eax,[session_count]
.loop:
    cmp ebx,eax
    jae .unlock_not_found
    imul edx,ebx,SESSION_SIZE
    lea rsi,[rel sessions]
    add rsi,rdx
    mov r15,rsi
    lea rdi,[r15+r13]
    mov rsi,r12
    mov ecx,32
    repe cmpsb
    jne .next
    mov rax,[r15+r14]
    cmp rax,[rsp+30h]
    jbe .next
    mov rbx,r15
    call storage_unlock
    mov rax,rbx
    jmp .done
.next:
    inc ebx
    jmp .loop
.unlock_not_found:
    call storage_unlock
.not_found:
    xor eax,eax
.done:
    add rsp,48h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

storage_find_access:
    mov edx,SES_ACCESS
    mov r8d,SES_ACCESS_EXP
    jmp storage_find_token

storage_find_refresh:
    mov edx,SES_REFRESH
    mov r8d,SES_REFRESH_EXP
    jmp storage_find_token
