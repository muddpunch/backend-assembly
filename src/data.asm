section .data

listen_addr:
    dw AF_INET
    dw 0x901f                         ; htons(8080), loopback only
    dd 0x0100007f                     ; 127.0.0.1 only
    dq 0

startup_msg db 'OGFN ASM backend listening on http://127.0.0.1:8080',13,10
startup_msg_len equ $-startup_msg
diag_wsa db '[FATAL] WSAStartup failed',13,10
diag_wsa_len equ $-diag_wsa
diag_crypto db '[FATAL] CNG SHA-256 initialization failed',13,10
diag_crypto_len equ $-diag_crypto
diag_storage db '[FATAL] storage initialization failed',13,10
diag_storage_len equ $-diag_storage
diag_socket db '[FATAL] socket creation failed',13,10
diag_socket_len equ $-diag_socket
diag_bind db '[FATAL] bind(127.0.0.1:8080) failed',13,10
diag_bind_len equ $-diag_bind
diag_listen db '[FATAL] listen failed',13,10
diag_listen_len equ $-diag_listen
diag_wsa_prefix db '[WSA] error=0x'
diag_wsa_prefix_len equ $-diag_wsa_prefix
diag_wsa_suffix db 13,10
diag_wsa_suffix_len equ $-diag_wsa_suffix

status_200 db 'HTTP/1.1 200 OK',13,10
status_200_len equ $-status_200
status_204 db 'HTTP/1.1 204 No Content',13,10
status_204_len equ $-status_204
status_400 db 'HTTP/1.1 400 Bad Request',13,10
status_400_len equ $-status_400
status_401 db 'HTTP/1.1 401 Unauthorized',13,10
status_401_len equ $-status_401
status_403 db 'HTTP/1.1 403 Forbidden',13,10
status_403_len equ $-status_403
status_404 db 'HTTP/1.1 404 Not Found',13,10
status_404_len equ $-status_404
status_405 db 'HTTP/1.1 405 Method Not Allowed',13,10
status_405_len equ $-status_405
status_413 db 'HTTP/1.1 413 Content Too Large',13,10
status_413_len equ $-status_413
status_501 db 'HTTP/1.1 501 Not Implemented',13,10
status_501_len equ $-status_501

json_header db 'Content-Type: application/json',13,10,'Connection: close',13,10,'Content-Length: '
json_header_len equ $-json_header
plain_204 db 'Connection: close',13,10,'Content-Length: 0',13,10,13,10
plain_204_len equ $-plain_204
crlf2 db 13,10,13,10

body_ok db '{"status":"ok"}'
body_ok_len equ $-body_ok
body_players db '{"server":"online","players":0}'
body_players_len equ $-body_players
body_lightswitch db '{"services":[]}'
body_lightswitch_len equ $-body_lightswitch
body_catalog db '{"refreshIntervalHrs":24,"dailyPurchaseHrs":24,"storefront":[]}'
body_catalog_len equ $-body_catalog
body_version db '{"type":"LIVE","version":"8.51","app":"Fortnite"}'
body_version_len equ $-body_version
body_cloudstorage db '[]'
body_cloudstorage_len equ $-body_cloudstorage
body_bad db '{"error":"bad_request"}'
body_bad_len equ $-body_bad
body_notfound db '{"error":"not_found"}'
body_notfound_len equ $-body_notfound
body_method db '{"error":"method_not_allowed"}'
body_method_len equ $-body_method
body_large db '{"error":"payload_too_large"}'
body_large_len equ $-body_large
body_unsupported db '{"error":"not_implemented"}'
body_unsupported_len equ $-body_unsupported

; Exact routes retained from backend 8.51's health/status surface.
path_health db '/health'
path_health_len equ $-path_health
path_status1 db '/api/status/players'
path_status1_len equ $-path_status1
path_status2 db '/api/players/online'
path_status2_len equ $-path_status2
path_status3 db '/status/players'
path_status3_len equ $-path_status3
path_status4 db '/launcher/api/status'
path_status4_len equ $-path_status4
path_lightswitch db '/lightswitch/api/service/bulk/status'
path_lightswitch_len equ $-path_lightswitch
path_catalog db '/fortnite/api/storefront/v2/catalog'
path_catalog_len equ $-path_catalog
path_version db '/fortnite/api/v2/versioncheck'
path_version_len equ $-path_version
path_cloudstorage db '/fortnite/api/cloudstorage/system'
path_cloudstorage_len equ $-path_cloudstorage
path_unknown db '/unknown'
path_unknown_len equ $-path_unknown
path_oauth db '/account/api/oauth/token'
path_oauth_len equ $-path_oauth
prefix_account db '/account/api'
prefix_account_len equ $-prefix_account
prefix_fortnite db '/fortnite/api'
prefix_fortnite_len equ $-prefix_fortnite
prefix_friends db '/friends/api'
prefix_friends_len equ $-prefix_friends
prefix_party db '/party/api'
prefix_party_len equ $-prefix_party
prefix_api db '/api/'
prefix_api_len equ $-prefix_api
prefix_auth db '/auth/'
prefix_auth_len equ $-prefix_auth

path_oauth_verify db '/account/api/oauth/verify'
path_oauth_verify_len equ $-path_oauth_verify
path_account_register db '/account/api/public/account/register'
path_account_register_len equ $-path_account_register
path_account_base db '/account/api/public/account'
path_account_base_len equ $-path_account_base
path_persona_lookup db '/persona/api/public/account/lookup'
path_persona_lookup_len equ $-path_persona_lookup

default_client_id db 'ec684b8c687f479fadea3cb2ad83f5c6',0
default_client_id_len equ $-default_client_id-1
storage_dir db 'data',0
accounts_file db 'data\accounts.bin',0
sessions_file db 'data\sessions.bin',0
storage_mutex_name db 'OGFN_ASM_STORAGE',0

auth_invalid_request db '{"errorCode":"errors.com.epicgames.common.oauth.invalid_request","errorMessage":"Username and password required","messageVars":[],"numericErrorCode":1013,"originatingService":"backend851","intent":"prod"}'
auth_invalid_request_len equ $-auth_invalid_request
auth_invalid_credentials db '{"errorCode":"errors.com.epicgames.account.invalid_account_credentials","errorMessage":"Invalid credentials","messageVars":[],"numericErrorCode":18031,"originatingService":"backend851","intent":"prod"}'
auth_invalid_credentials_len equ $-auth_invalid_credentials
auth_invalid_token db '{"errorCode":"errors.com.epicgames.common.oauth.invalid_token","errorMessage":"OAuth token is invalid or expired","messageVars":[],"numericErrorCode":1014,"originatingService":"backend851","intent":"prod"}'
auth_invalid_token_len equ $-auth_invalid_token
auth_unsupported_grant db '{"errorCode":"errors.com.epicgames.common.oauth.unsupported_grant_type","errorMessage":"Unsupported grant type","messageVars":[],"numericErrorCode":1016,"originatingService":"backend851","intent":"prod"}'
auth_unsupported_grant_len equ $-auth_unsupported_grant
auth_forbidden db '{"errorCode":"errors.com.epicgames.common.authorization.authorization_failed","errorMessage":"Forbidden","messageVars":[],"numericErrorCode":1032,"originatingService":"backend851","intent":"prod"}'
auth_forbidden_len equ $-auth_forbidden
auth_not_found db '{"errorCode":"errors.com.epicgames.account.account_not_found","errorMessage":"Account not found","messageVars":[],"numericErrorCode":18007,"originatingService":"backend851","intent":"prod"}'
auth_not_found_len equ $-auth_not_found

hex_digits db '0123456789abcdef'

section .bss
wsadata resb 408
server_socket resq 1
stdout_handle resq 1
bytes_written resd 1
error_hex resb 8
sha256_alg resq 1
storage_mutex resq 1
account_count resd 1
session_count resd 1
accounts resb (MAX_ACCOUNTS * ACCOUNT_SIZE)
sessions resb (MAX_SESSIONS * SESSION_SIZE)

section .data
reuse_addr dd 1
recv_timeout dd 30000                    ; WinSock timeout in milliseconds
