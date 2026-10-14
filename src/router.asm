section .text

; route_request(SOCKET rcx, info rdx, response r8).
route_request:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,40h
    mov r12,rcx
    mov r13,rdx
    mov rbx,r8
    mov rcx,r12
    mov rdx,rbx
    mov r8,r13
    call auth_route
    test eax,eax
    jnz .done

    ; 204 compatibility endpoints.
    lea rsi,[path_unknown]
    mov edx,path_unknown_len
    call route_equals
    test eax,eax
    jnz .no_content

    ; GET /health.
    lea rsi,[path_health]
    mov edx,path_health_len
    call route_equals
    test eax,eax
    jz .status_routes
    cmp dword [r13+INFO_METHOD],1
    jne .method_not_allowed
    lea r8,[status_200]
    mov r9d,status_200_len
    lea r10,[body_ok]
    mov r11d,body_ok_len
    jmp .json

.status_routes:
    lea rsi,[path_status1]
    mov edx,path_status1_len
    call route_equals
    test eax,eax
    jnz .status_ok
    lea rsi,[path_status2]
    mov edx,path_status2_len
    call route_equals
    test eax,eax
    jnz .status_ok
    lea rsi,[path_status3]
    mov edx,path_status3_len
    call route_equals
    test eax,eax
    jnz .status_ok
    lea rsi,[path_status4]
    mov edx,path_status4_len
    call route_equals
    test eax,eax
    jnz .status_ok

    lea rsi,[path_lightswitch]
    mov edx,path_lightswitch_len
    call route_equals
    test eax,eax
    jnz .lightswitch
    lea rsi,[path_catalog]
    mov edx,path_catalog_len
    call route_equals
    test eax,eax
    jnz .catalog
    lea rsi,[path_version]
    mov edx,path_version_len
    call route_prefix
    test eax,eax
    jnz .version
    lea rsi,[path_cloudstorage]
    mov edx,path_cloudstorage_len
    call route_equals
    test eax,eax
    jnz .cloudstorage
    lea rsi,[path_oauth]
    mov edx,path_oauth_len
    call route_equals
    test eax,eax
    jnz .unsupported

    ; Known backend namespaces fail explicitly while their stateful modules are pending.
    lea rsi,[prefix_account]
    mov edx,prefix_account_len
    call route_prefix
    test eax,eax
    jnz .unsupported
    lea rsi,[prefix_fortnite]
    mov edx,prefix_fortnite_len
    call route_prefix
    test eax,eax
    jnz .unsupported
    lea rsi,[prefix_friends]
    mov edx,prefix_friends_len
    call route_prefix
    test eax,eax
    jnz .unsupported
    lea rsi,[prefix_party]
    mov edx,prefix_party_len
    call route_prefix
    test eax,eax
    jnz .unsupported
    lea rsi,[prefix_api]
    mov edx,prefix_api_len
    call route_prefix
    test eax,eax
    jnz .unsupported
    lea rsi,[prefix_auth]
    mov edx,prefix_auth_len
    call route_prefix
    test eax,eax
    jnz .unsupported

    ; Preserve the complete public route surface with an explicit response.
    ; Stateful Mongo/JWT/XMPP operations are intentionally not faked.
    lea r8,[status_404]
    mov r9d,status_404_len
    lea r10,[body_notfound]
    mov r11d,body_notfound_len
    jmp .json

.status_ok:
    cmp dword [r13+INFO_METHOD],1
    jne .method_not_allowed
    lea r8,[status_200]
    mov r9d,status_200_len
    lea r10,[body_players]
    mov r11d,body_players_len
    jmp .json
.lightswitch:
    cmp dword [r13+INFO_METHOD],1
    jne .method_not_allowed
    lea r8,[status_200]
    mov r9d,status_200_len
    lea r10,[body_lightswitch]
    mov r11d,body_lightswitch_len
    jmp .json
.catalog:
    cmp dword [r13+INFO_METHOD],1
    jne .method_not_allowed
    lea r8,[status_200]
    mov r9d,status_200_len
    lea r10,[body_catalog]
    mov r11d,body_catalog_len
    jmp .json
.version:
    cmp dword [r13+INFO_METHOD],1
    jne .method_not_allowed
    lea r8,[status_200]
    mov r9d,status_200_len
    lea r10,[body_version]
    mov r11d,body_version_len
    jmp .json
.cloudstorage:
    cmp dword [r13+INFO_METHOD],1
    jne .method_not_allowed
    lea r8,[status_200]
    mov r9d,status_200_len
    lea r10,[body_cloudstorage]
    mov r11d,body_cloudstorage_len
    jmp .json
.unsupported:
    lea r8,[status_501]
    mov r9d,status_501_len
    lea r10,[body_unsupported]
    mov r11d,body_unsupported_len
.json:
    mov [rsp+20h],r10
    mov [rsp+28h],r11
    mov rcx,r12
    mov rdx,rbx
    call send_json
    jmp .done
.method_not_allowed:
    lea rax,[body_method]
    mov [rsp+20h],rax
    mov dword [rsp+28h],body_method_len
    mov rcx,r12
    mov rdx,rbx
    lea r8,[status_405]
    mov r9d,status_405_len
    call send_json
    jmp .done
.no_content:
    mov rcx,r12
    mov rdx,rbx
    call send_204
.done:
    add rsp,40h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; route_equals uses info in r13 and candidate rsi/edx.
route_equals:
    cmp [r13+INFO_PATH_LEN],edx
    jne .no
    mov rcx,[r13+INFO_PATH]
    xor eax,eax
.loop:
    cmp eax,edx
    jae .yes
    mov r8b,[rcx+rax]
    cmp r8b,[rsi+rax]
    jne .no
    inc eax
    jmp .loop
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; route_prefix uses the same candidate buffer/length and accepts either an exact
; match or a slash-delimited child path (e.g. /v2/versioncheck/8.51).
route_prefix:
    cmp [r13+INFO_PATH_LEN],edx
    jb .no
    mov rcx,[r13+INFO_PATH]
    xor eax,eax
.compare:
    cmp eax,edx
    jae .boundary
    mov r8b,[rcx+rax]
    cmp r8b,[rsi+rax]
    jne .no
    inc eax
    jmp .compare
.boundary:
    cmp [r13+INFO_PATH_LEN],edx
    je .yes
    cmp byte [rcx+rax],'/'
    jne .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
