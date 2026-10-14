section .data
auth_header_name db 'authorization'
auth_bearer_name db 'bearer '
form_grant_type db 'grant_type'
form_username db 'username'
form_password db 'password'
form_refresh_token db 'refresh_token'
query_account_id db 'accountId'
query_q db 'q'
grant_password db 'password'
grant_refresh db 'refresh_token'
grant_client db 'client_credentials'
client_username db 'client',0

json_token_prefix db '{"access_token":"'
json_token_prefix_len equ $-json_token_prefix
json_token_mid1 db '","expires_in":28800,"expires_at":"'
json_token_mid1_len equ $-json_token_mid1
json_token_mid2 db '","token_type":"bearer","refresh_token":"'
json_token_mid2_len equ $-json_token_mid2
json_token_mid3 db '","refresh_expires":115200,"refresh_expires_at":"'
json_token_mid3_len equ $-json_token_mid3
json_token_mid4 db '","account_id":"'
json_token_mid4_len equ $-json_token_mid4
json_token_mid5 db '","client_id":"'
json_token_mid5_len equ $-json_token_mid5
json_token_mid6 db '","internal_client":true,"client_service":"fortnite","displayName":"'
json_token_mid6_len equ $-json_token_mid6
json_token_mid7 db '","app":"fortnite","in_app_id":"'
json_token_mid7_len equ $-json_token_mid7
json_token_mid8 db '","device_id":"'
json_token_mid8_len equ $-json_token_mid8
json_token_suffix db '","tfa_enabled":true,"mfa_enabled":true}'
json_token_suffix_len equ $-json_token_suffix

json_verify_prefix db '{"token":"'
json_verify_prefix_len equ $-json_verify_prefix
json_verify_mid1 db '","session_id":"'
json_verify_mid1_len equ $-json_verify_mid1
json_verify_mid2 db '","token_type":"bearer","client_id":"'
json_verify_mid2_len equ $-json_verify_mid2
json_verify_mid3 db '","internal_client":true,"client_service":"fortnite","account_id":"'
json_verify_mid3_len equ $-json_verify_mid3
json_verify_mid4 db '","displayName":"'
json_verify_mid4_len equ $-json_verify_mid4
json_verify_mid5 db '","app":"fortnite","expires_in":28800,"expires_at":"'
json_verify_mid5_len equ $-json_verify_mid5
json_verify_suffix db '","auth_method":"password","in_app_id":"'
json_verify_suffix_len equ $-json_verify_suffix
json_verify_suffix2 db '","tfa_enabled":true,"mfa_enabled":true}'
json_verify_suffix2_len equ $-json_verify_suffix2

json_account_prefix db '{"id":"'
json_account_prefix_len equ $-json_account_prefix
json_account_mid1 db '","displayName":"'
json_account_mid1_len equ $-json_account_mid1
json_account_mid2 db '","name":"'
json_account_mid2_len equ $-json_account_mid2
json_account_mid3 db '","email":"****@****.com","failedLoginAttempts":0,"lastLogin":"'
json_account_mid3_len equ $-json_account_mid3
json_account_mid4 db '","numberOfDisplayNameChanges":0,"ageGroup":"UNKNOWN","headless":false,"country":"US","preferredLanguage":"en","canUpdateDisplayName":true,"tfaEnabled":true,"twoFactorEnabled":true,"mfaEnabled":true,"canGift":true,"giftEligible":true,"emailVerified":true,"minorVerified":false,"minorStatus":"NOT_MINOR","externalAuths":{}}'
json_account_mid4_len equ $-json_account_mid4
json_persona_prefix db '{"id":"'
json_persona_prefix_len equ $-json_persona_prefix
json_persona_mid db '","displayName":"'
json_persona_mid_len equ $-json_persona_mid

fallback_time db '1970-01-01T00:00:00Z'
fallback_time_len equ $-fallback_time

section .text

; auth_send_body has the same six-argument layout as send_json and is a
; deliberately tiny forwarding shim.
auth_send_body:
    jmp send_json

auth_path_equals:
    cmp [rdx+INFO_PATH_LEN],r9d
    jne .no
    mov rcx,[rdx+INFO_PATH]
    xor eax,eax
.loop:
    cmp eax,r9d
    jae .yes
    mov r10b,[rcx+rax]
    cmp r10b,[r8+rax]
    jne .no
    inc eax
    jmp .loop
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

auth_path_prefix:
    cmp [rdx+INFO_PATH_LEN],r9d
    jb .no
    mov rcx,[rdx+INFO_PATH]
    xor eax,eax
.compare:
    cmp eax,r9d
    jae .boundary
    mov r10b,[rcx+rax]
    cmp r10b,[r8+rax]
    jne .no
    inc eax
    jmp .compare
.boundary:
    cmp [rdx+INFO_PATH_LEN],r9d
    je .yes
    cmp byte [rcx+rax],'/'
    jne .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; auth_param_value(base rcx, length edx, key r8, key_len r9d,
;                  output [rsp+28h], output_capacity [rsp+30h]).
auth_param_value:
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
    mov r13d,edx
    mov r14,r8
    mov r15d,r9d
    xor eax,eax
    test r11d,r11d
    jz .fail
    mov rsi,r12
    lea rdi,[r12+r13]
.field:
    cmp rsi,rdi
    jae .fail
    mov rbx,rsi
    xor ecx,ecx
.key_loop:
    cmp ecx,r15d
    jae .key_end
    cmp rbx,rdi
    jae .next_field
    cmp byte [rbx],'='
    je .next_field
    mov al,[rbx]
    cmp al,[r14+rcx]
    jne .next_field
    inc rbx
    inc ecx
    jmp .key_loop
.key_end:
    cmp rbx,rdi
    jae .next_field
    cmp byte [rbx],'='
    jne .next_field
    inc rbx
    mov rsi,rbx
    xor ecx,ecx
    mov r8,rsi
.value_end:
    cmp r8,rdi
    jae .decode
    cmp byte [r8],'&'
    je .decode
    inc r8
    jmp .value_end
.decode:
    mov r9,r10
    dec r11d
    js .fail
    xor ebx,ebx
.decode_loop:
    cmp rsi,r8
    jae .terminate
    cmp ebx,r11d
    jae .fail
    mov al,[rsi]
    cmp al,'+'
    je .space
    cmp al,'%'
    jne .plain
    lea rdx,[rsi+2]
    cmp rdx,r8
    jae .fail
    mov al,[rsi+1]
    call hex_nibble
    jc .fail
    shl eax,4
    mov edx,eax
    mov al,[rsi+2]
    call hex_nibble
    jc .fail
    or eax,edx
    mov [r9],al
    inc r9
    add rsi,3
    inc ebx
    jmp .decode_loop
.space:
    mov byte [r9],' '
    inc r9
    inc rsi
    inc ebx
    jmp .decode_loop
.plain:
    mov [r9],al
    inc r9
    inc rsi
    inc ebx
    jmp .decode_loop
.terminate:
    mov byte [r9],0
    mov eax,ebx
    jmp .done
.next_field:
    cmp rbx,rdi
    jae .fail
.skip:
    cmp rbx,rdi
    jae .fail
    cmp byte [rbx],'&'
    je .next_start
    inc rbx
    jmp .skip
.next_start:
    lea rsi,[rbx+1]
    jmp .field
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

; auth_form_value(info rcx, key rdx, key_len r8d, output r9,
;                 output_capacity [rsp+28h]).
auth_form_value:
    mov r10,r9
    mov r11d,[rsp+28h]
    mov r9,r8
    mov r8,rdx
    mov rax,[rcx+INFO_BODY]
    mov edx,[rcx+INFO_BODY_LEN]
    mov rcx,rax
    mov [rsp+28h],r10
    mov [rsp+30h],r11
    jmp auth_param_value

auth_validate_bearer:
    ; info rcx, raw-token output rdx -> session pointer or zero.
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,40h
    mov r12,rcx
    mov r13,rdx
    mov rsi,[r12+INFO_REQUEST]
    mov eax,[r12+INFO_HEADER_END]
    lea rdi,[rsi+rax]
.scan:
    lea rax,[rsi+14]
    cmp rax,rdi
    jae .fail
    mov rbx,rsi
    lea r8,[auth_header_name]
    xor ecx,ecx
.name:
    cmp ecx,13
    jae .colon
    mov al,[rbx+rcx]
    or al,20h
    cmp al,[r8+rcx]
    jne .advance
    inc ecx
    jmp .name
.colon:
    cmp byte [rbx+13],':'
    jne .advance
    lea rsi,[rbx+14]
.spaces:
    cmp rsi,rdi
    jae .fail
    cmp byte [rsi],' '
    jne .bearer
    inc rsi
    jmp .spaces
.bearer:
    lea r8,[auth_bearer_name]
    xor ecx,ecx
.bearer_loop:
    cmp ecx,7
    jae .token
    mov al,[rsi+rcx]
    or al,20h
    cmp al,[r8+rcx]
    jne .fail
    inc ecx
    jmp .bearer_loop
.token:
    add rsi,7
    lea rax,[rsi+64]
    cmp rax,rdi
    jae .fail
    mov rcx,rsi
    mov edx,64
    mov r8,r13
    call hex_decode
    test eax,eax
    jz .fail
    mov rcx,r13
    call storage_find_access
    jmp .done
.advance:
    inc rsi
    jmp .scan
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

auth_put:
    cld
    rep movsb
    ret

auth_put_cstr:
    mov rsi,rcx
.loop:
    mov al,[rsi]
    test al,al
    jz .done
    mov [rdi],al
    inc rsi
    inc rdi
    jmp .loop
.done:
    ret

auth_put_hex:
    push rbx
    push rsi
    push r8
    mov rsi,rcx
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
    pop r8
    pop rsi
    pop rbx
    ret

auth_put_uuid:
    push rbx
    push rsi
    push r8
    mov rsi,rcx
    xor ebx,ebx
    lea r8,[hex_digits]
.loop:
    cmp ebx,16
    jae .done
    movzx eax,byte [rsi+rbx]
    mov edx,eax
    shr eax,4
    and edx,0fh
    mov al,[r8+rax]
    mov [rdi],al
    mov al,[r8+rdx]
    mov [rdi+1],al
    add rdi,2
    inc ebx
    cmp ebx,4
    je .dash
    cmp ebx,6
    je .dash
    cmp ebx,8
    je .dash
    cmp ebx,10
    jne .loop
.dash:
    mov byte [rdi],'-'
    inc rdi
    jmp .loop
.done:
    pop r8
    pop rsi
    pop rbx
    ret

auth_put_2:
    xor edx,edx
    mov ecx,10
    div ecx
    add al,'0'
    mov [rdi],al
    add dl,'0'
    mov [rdi+1],dl
    add rdi,2
    ret

auth_put_4:
    xor edx,edx
    mov ecx,100
    div ecx
    mov r8d,edx
    call auth_put_2
    mov eax,r8d
    call auth_put_2
    ret

; append an RFC3339 UTC timestamp from a FILETIME pointer in rsi.
auth_put_time:
    push rbx
    push r12
    push r13
    sub rsp,40h
    mov r12,rdi
    mov r13,rsi
    lea rdx,[rsp+20h]
    mov rcx,r13
    call FileTimeToSystemTime
    test eax,eax
    jnz .valid
    mov rdi,r12
    lea rsi,[fallback_time]
    mov ecx,fallback_time_len
    call auth_put
    jmp .done
.valid:
    mov rdi,r12
    movzx eax,word [rsp+20h]
    call auth_put_4
    mov byte [rdi],'-'
    inc rdi
    movzx eax,word [rsp+22h]
    call auth_put_2
    mov byte [rdi],'-'
    inc rdi
    movzx eax,word [rsp+26h]
    call auth_put_2
    mov byte [rdi],'T'
    inc rdi
    movzx eax,word [rsp+28h]
    call auth_put_2
    mov byte [rdi],':'
    inc rdi
    movzx eax,word [rsp+2ah]
    call auth_put_2
    mov byte [rdi],':'
    inc rdi
    movzx eax,word [rsp+2ch]
    call auth_put_2
    mov byte [rdi],'Z'
    inc rdi
.done:
    add rsp,40h
    pop r13
    pop r12
    pop rbx
    ret

; auth_issue_token(socket rcx, response rdx, account r8).
auth_issue_token:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,300h
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    mov rcx,r14
    lea rdx,[default_client_id]
    mov r8d,default_client_id_len
    call storage_create_session
    test rax,rax
    jz .failure
    mov r15,rax
    lea rbx,[r13+4096]
    mov rdi,rbx
    lea rsi,[json_token_prefix]
    mov ecx,json_token_prefix_len
    call auth_put
    lea rcx,[r15+SES_ACCESS]
    mov edx,32
    call auth_put_hex
    lea rsi,[json_token_mid1]
    mov ecx,json_token_mid1_len
    call auth_put
    lea rsi,[r15+SES_ACCESS_EXP]
    call auth_put_time
    lea rsi,[json_token_mid2]
    mov ecx,json_token_mid2_len
    call auth_put
    lea rcx,[r15+SES_REFRESH]
    mov edx,32
    call auth_put_hex
    lea rsi,[json_token_mid3]
    mov ecx,json_token_mid3_len
    call auth_put
    lea rsi,[r15+SES_REFRESH_EXP]
    call auth_put_time
    lea rsi,[json_token_mid4]
    mov ecx,json_token_mid4_len
    call auth_put
    lea rcx,[r14+ACC_ID]
    call auth_put_uuid
    lea rsi,[json_token_mid5]
    mov ecx,json_token_mid5_len
    call auth_put
    lea rcx,[default_client_id]
    call auth_put_cstr
    lea rsi,[json_token_mid6]
    mov ecx,json_token_mid6_len
    call auth_put
    lea rcx,[r14+ACC_NAME]
    call auth_put_cstr
    lea rsi,[json_token_mid7]
    mov ecx,json_token_mid7_len
    call auth_put
    lea rcx,[r14+ACC_ID]
    call auth_put_uuid
    lea rsi,[json_token_mid8]
    mov ecx,json_token_mid8_len
    call auth_put
    lea rcx,[rsp+80h]
    mov edx,16
    call crypto_random
    lea rcx,[rsp+80h]
    call auth_put_uuid
    lea rsi,[json_token_suffix]
    mov ecx,json_token_suffix_len
    call auth_put
    mov r10,rbx
    mov rax,rdi
    sub rax,rbx
    mov r11d,eax
    mov [rsp+20h],r10
    mov [rsp+28h],r11
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_200]
    mov r9d,status_200_len
    call auth_send_body
    jmp .done
.failure:
    lea rax,[auth_invalid_request]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_invalid_request_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_400]
    mov r9d,status_400_len
    call auth_send_body
.done:
    add rsp,300h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

auth_string_equals:
    cmp edx,r9d
    jne .no
    test edx,edx
    jz .yes
    mov rcx,rcx
    mov r10d,edx
.loop:
    mov al,[rcx]
    cmp al,[r8]
    jne .no
    inc rcx
    inc r8
    dec r10d
    jnz .loop
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; POST /account/api/oauth/token.
auth_oauth_token:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,500h
    mov r12,rcx
    mov r13,rdx
    mov r14,r8

    mov rcx,r14
    lea rdx,[form_grant_type]
    mov r8d,10
    lea r9,[rsp+80h]
    mov dword [rsp+20h],32
    call auth_form_value
    test eax,eax
    jz .bad_request
    mov ebx,eax
    mov rcx,rsp
    add rcx,80h
    mov edx,ebx
    lea r8,[grant_password]
    mov r9d,8
    call auth_string_equals
    test eax,eax
    jnz .password
    mov rcx,rsp
    add rcx,80h
    mov edx,ebx
    lea r8,[grant_refresh]
    mov r9d,13
    call auth_string_equals
    test eax,eax
    jnz .refresh
    mov rcx,rsp
    add rcx,80h
    mov edx,ebx
    lea r8,[grant_client]
    mov r9d,18
    call auth_string_equals
    test eax,eax
    jnz .client_credentials
    jmp .unsupported

.password:
    mov rcx,r14
    lea rdx,[form_username]
    mov r8d,8
    lea r9,[rsp+100h]
    mov dword [rsp+20h],64
    call auth_form_value
    test eax,eax
    jz .bad_request
    mov [rsp+60h],eax
    mov rcx,r14
    lea rdx,[form_password]
    mov r8d,8
    lea r9,[rsp+180h]
    mov dword [rsp+20h],256
    call auth_form_value
    test eax,eax
    jz .bad_request
    mov [rsp+64h],eax
    lea rcx,[rsp+100h]
    mov edx,[rsp+60h]
    call storage_find_username
    test rax,rax
    jnz .existing
    lea rcx,[rsp+100h]
    mov edx,[rsp+60h]
    lea r8,[rsp+180h]
    mov r9d,[rsp+64h]
    call storage_create_account
    test rax,rax
    jz .create_race
    mov r8,rax
    jmp .issue
.create_race:
    lea rcx,[rsp+100h]
    mov edx,[rsp+60h]
    call storage_find_username
    test rax,rax
    jz .invalid_credentials
.existing:
    mov rbx,rax
    mov rcx,rbx
    lea rdx,[rsp+180h]
    mov r8d,[rsp+64h]
    call storage_verify_password
    test eax,eax
    jz .invalid_credentials
    mov r8,rbx
.issue:
    mov rcx,r12
    mov rdx,r13
    call auth_issue_token
    jmp .done

.refresh:
    mov rcx,r14
    lea rdx,[form_refresh_token]
    mov r8d,13
    lea r9,[rsp+200h]
    mov dword [rsp+20h],128
    call auth_form_value
    cmp eax,64
    jne .invalid_credentials
    mov rcx,rsp
    add rcx,200h
    mov edx,64
    lea r8,[rsp+280h]
    call hex_decode
    test eax,eax
    jz .invalid_credentials
    lea rcx,[rsp+280h]
    call storage_find_refresh
    test rax,rax
    jz .invalid_credentials
    mov rbx,rax
    lea rcx,[rbx+SES_ACCOUNT]
    call storage_find_id
    test rax,rax
    jz .invalid_credentials
    mov r8,rax
    mov rcx,r12
    mov rdx,r13
    call auth_issue_token
    jmp .done

.client_credentials:
    ; Internal client tokens still map to a persisted local account so subsequent
    ; authenticated profile requests have a concrete identity.
    lea rcx,[client_username]
    mov edx,6
    call storage_find_username
    test rax,rax
    jnz .client_found
    lea rcx,[rsp+300h]
    mov edx,32
    call crypto_random
    test eax,eax
    jz .invalid_credentials
    lea rcx,[client_username]
    mov edx,6
    lea r8,[rsp+300h]
    mov r9d,32
    call storage_create_account
    test rax,rax
    jz .invalid_credentials
.client_found:
    mov r8,rax
    mov rcx,r12
    mov rdx,r13
    call auth_issue_token
    jmp .done
.bad_request:
    lea rax,[auth_invalid_request]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_invalid_request_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_400]
    mov r9d,status_400_len
    call auth_send_body
    jmp .done
.invalid_credentials:
    lea rax,[auth_invalid_credentials]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_invalid_credentials_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_401]
    mov r9d,status_401_len
    call auth_send_body
    jmp .done
.unsupported:
    lea rax,[auth_unsupported_grant]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_unsupported_grant_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_400]
    mov r9d,status_400_len
    call auth_send_body
.done:
    add rsp,500h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

auth_send_verify:
    ; socket rcx, response rdx, info r8.
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,300h
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    lea rdx,[rsp+280h]
    mov rcx,r14
    call auth_validate_bearer
    test rax,rax
    jz .fail
    mov r15,rax
    lea rcx,[rsp+80h]
    mov edx,16
    call crypto_random
    lea rbx,[r13+4096]
    mov rdi,rbx
    lea rsi,[json_verify_prefix]
    mov ecx,json_verify_prefix_len
    call auth_put
    lea rcx,[rsp+280h]
    mov edx,32
    call auth_put_hex
    lea rsi,[json_verify_mid1]
    mov ecx,json_verify_mid1_len
    call auth_put
    lea rcx,[rsp+80h]
    call auth_put_uuid
    lea rsi,[json_verify_mid2]
    mov ecx,json_verify_mid2_len
    call auth_put
    lea rcx,[r15+SES_CLIENT]
    call auth_put_cstr
    lea rsi,[json_verify_mid3]
    mov ecx,json_verify_mid3_len
    call auth_put
    lea rcx,[r15+SES_ACCOUNT]
    call auth_put_uuid
    lea rcx,[r15+SES_ACCOUNT]
    call storage_find_id
    test rax,rax
    jz .fail
    mov rbx,rax
    lea rsi,[json_verify_mid4]
    mov ecx,json_verify_mid4_len
    call auth_put
    lea rcx,[rbx+ACC_NAME]
    call auth_put_cstr
    lea rsi,[json_verify_mid5]
    mov ecx,json_verify_mid5_len
    call auth_put
    lea rsi,[r15+SES_ACCESS_EXP]
    call auth_put_time
    lea rsi,[json_verify_suffix]
    mov ecx,json_verify_suffix_len
    call auth_put
    lea rcx,[r15+SES_ACCOUNT]
    call auth_put_uuid
    lea rsi,[json_verify_suffix2]
    mov ecx,json_verify_suffix2_len
    call auth_put
    mov r10,r13
    lea rax,[r13+4096]
    sub rdi,rax
    mov r11d,edi
    mov [rsp+20h],rax
    mov [rsp+28h],r11
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_200]
    mov r9d,status_200_len
    call auth_send_body
    jmp .done
.fail:
    lea rax,[auth_invalid_token]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_invalid_token_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_401]
    mov r9d,status_401_len
    call auth_send_body
.done:
    add rsp,300h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

auth_send_account:
    ; socket rcx, response rdx, account r8.
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp,218h
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    lea rbx,[r13+4096]
    mov rdi,rbx
    lea rsi,[json_account_prefix]
    mov ecx,json_account_prefix_len
    call auth_put
    lea rcx,[r14+ACC_ID]
    call auth_put_uuid
    lea rsi,[json_account_mid1]
    mov ecx,json_account_mid1_len
    call auth_put
    lea rcx,[r14+ACC_NAME]
    call auth_put_cstr
    lea rsi,[json_account_mid2]
    mov ecx,json_account_mid2_len
    call auth_put
    lea rcx,[r14+ACC_NAME]
    call auth_put_cstr
    lea rsi,[json_account_mid3]
    mov ecx,json_account_mid3_len
    call auth_put
    lea rsi,[r14+ACC_CREATED]
    call auth_put_time
    lea rsi,[json_account_mid4]
    mov ecx,json_account_mid4_len
    call auth_put
    mov r10,rbx
    mov rax,rdi
    sub rax,rbx
    mov r11d,eax
    mov [rsp+20h],r10
    mov [rsp+28h],r11
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_200]
    mov r9d,status_200_len
    call auth_send_body
    add rsp,218h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

auth_persona_lookup:
    ; GET /persona/api/public/account/lookup?q=displayName.
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,180h
    mov r12,rcx
    mov r13,rdx
    mov rcx,[r8+INFO_QUERY]
    mov edx,[r8+INFO_QUERY_LEN]
    lea r8,[query_q]
    mov r9d,1
    lea rax,[rsp+80h]
    mov [rsp+20h],rax
    mov qword [rsp+28h],64
    call auth_param_value
    test eax,eax
    jz .not_found
    mov ebx,eax
    lea rcx,[rsp+80h]
    mov edx,ebx
    call storage_find_username
    test rax,rax
    jz .not_found
    mov rsi,rax
    mov rbx,rax
    lea rdi,[r13+4096]
    lea rsi,[json_persona_prefix]
    mov ecx,json_persona_prefix_len
    call auth_put
    lea rcx,[rbx+ACC_ID]
    call auth_put_uuid
    lea rsi,[json_persona_mid]
    mov ecx,json_persona_mid_len
    call auth_put
    lea rcx,[rbx+ACC_NAME]
    call auth_put_cstr
    mov byte [rdi],'}'
    inc rdi
    lea rax,[r13+4096]
    mov r10,rax
    sub rdi,rax
    mov r11d,edi
    mov [rsp+20h],r10
    mov [rsp+28h],r11
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_200]
    mov r9d,status_200_len
    call auth_send_body
    jmp .done
.not_found:
    lea rax,[auth_not_found]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_not_found_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_404]
    mov r9d,status_404_len
    call auth_send_body
.done:
    add rsp,180h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

auth_account_lookup:
    ; Authenticated GET /account/api/public/account and /.../<accountId>.
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,240h
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    lea rdx,[rsp+80h]
    mov rcx,r14
    call auth_validate_bearer
    test rax,rax
    jz .invalid
    mov r15,rax
    lea rcx,[r15+SES_ACCOUNT]
    call storage_find_id
    test rax,rax
    jz .invalid
    mov rbx,rax

    ; If accountId is present in the query, it must match the bearer account.
    cmp dword [r14+INFO_QUERY_LEN],0
    je .path_target
    mov rcx,[r14+INFO_QUERY]
    mov edx,[r14+INFO_QUERY_LEN]
    lea r8,[query_account_id]
    mov r9d,9
    lea rax,[rsp+100h]
    mov [rsp+20h],rax
    mov qword [rsp+28h],64
    call auth_param_value
    test eax,eax
    jz .path_target
    mov ecx,eax
    lea rdx,[rsp+100h]
    lea r8,[rsp+140h]
    call uuid_decode
    test eax,eax
    jz .forbidden
    lea rsi,[rsp+140h]
    lea rdi,[r15+SES_ACCOUNT]
    mov ecx,16
    repe cmpsb
    jne .forbidden
.path_target:
    ; A path suffix is also checked when present.
    mov eax,[r14+INFO_PATH_LEN]
    cmp eax,path_account_base_len
    jbe .send
    mov rcx,[r14+INFO_PATH]
    add rcx,path_account_base_len
    cmp byte [rcx],'/'
    jne .send
    inc rcx
    mov edx,[r14+INFO_PATH_LEN]
    sub edx,path_account_base_len+1
    lea r8,[rsp+140h]
    call uuid_decode
    test eax,eax
    jz .forbidden
    lea rsi,[rsp+140h]
    lea rdi,[r15+SES_ACCOUNT]
    mov ecx,16
    repe cmpsb
    jne .forbidden
.send:
    mov rcx,r12
    mov rdx,r13
    mov r8,rbx
    call auth_send_account
    jmp .done
.invalid:
    lea rax,[auth_invalid_token]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_invalid_token_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_401]
    mov r9d,status_401_len
    call auth_send_body
    jmp .done
.forbidden:
    lea rax,[auth_forbidden]
    mov [rsp+20h],rax
    mov dword [rsp+28h],auth_forbidden_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_403]
    mov r9d,status_403_len
    call auth_send_body
.done:
    add rsp,240h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

auth_route:
    ; socket rcx, response rdx, request-info r8 -> eax=handled.
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp,58h
    mov r12,rcx
    mov r13,rdx
    mov r14,r8

    mov rdx,r14
    lea r8,[path_oauth]
    mov r9d,path_oauth_len
    call auth_path_equals
    test eax,eax
    jz .verify
    cmp dword [r14+INFO_METHOD],2
    jne .method
    mov rcx,r12
    mov rdx,r13
    mov r8,r14
    call auth_oauth_token
    jmp .handled
.verify:
    mov rdx,r14
    lea r8,[path_oauth_verify]
    mov r9d,path_oauth_verify_len
    call auth_path_equals
    test eax,eax
    jz .persona
    cmp dword [r14+INFO_METHOD],1
    jne .method
    mov rcx,r12
    mov rdx,r13
    mov r8,r14
    call auth_send_verify
    jmp .handled
.persona:
    mov rdx,r14
    lea r8,[path_persona_lookup]
    mov r9d,path_persona_lookup_len
    call auth_path_equals
    test eax,eax
    jz .account
    cmp dword [r14+INFO_METHOD],1
    jne .method
    mov rcx,r12
    mov rdx,r13
    mov r8,r14
    call auth_persona_lookup
    jmp .handled
.account:
    mov rdx,r14
    lea r8,[path_account_register]
    mov r9d,path_account_register_len
    call auth_path_equals
    test eax,eax
    jnz .not_handled
    mov rdx,r14
    lea r8,[path_account_base]
    mov r9d,path_account_base_len
    call auth_path_prefix
    test eax,eax
    jz .not_handled
    cmp dword [r14+INFO_METHOD],1
    jne .method
    mov rcx,r12
    mov rdx,r13
    mov r8,r14
    call auth_account_lookup
    jmp .handled
.method:
    lea rax,[body_method]
    mov [rsp+20h],rax
    mov dword [rsp+28h],body_method_len
    mov rcx,r12
    mov rdx,r13
    lea r8,[status_405]
    mov r9d,status_405_len
    call auth_send_body
.handled:
    mov eax,1
    jmp .done
.not_handled:
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
