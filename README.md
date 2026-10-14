# OGFN ASM backend

Win64 NASM rewrite of the backend's transport/core surface. The source is intentionally split by responsibility:

- `src/server.asm` — WinSock lifecycle, accept loop, heap-backed client workers
- `src/parser.asm` — bounded HTTP/1.1 parser with `Content-Length` framing
- `src/router.asm` — backend-compatible health/status/store/version routes
- `src/response.asm` — short-write-safe response writer
- `src/data.asm` — protocol constants and response payloads
- `src/config.inc` — ABI, buffer, and request-info layout constants

Build from a Visual Studio Developer Command Prompt with NASM installed:

```bat
build.bat
ogfn-server-8080.exe
```

The server binds `127.0.0.1:8080`.

Implemented auth flow:

- `POST /account/api/oauth/token` with `grant_type=password`
- `POST /account/api/oauth/token` with `grant_type=refresh_token`
- `POST /account/api/oauth/token` with `grant_type=client_credentials`
- `GET /account/api/oauth/verify` with a Bearer token
- `GET /account/api/public/account` and `/account/api/public/account/:accountId`
- `GET /persona/api/public/account/lookup?q=...`

Accounts and sessions are persisted as fixed-size binary records in `data\accounts.bin` and `data\sessions.bin`. Passwords are never stored in plaintext; password verification uses a per-account random salt and Windows CNG SHA-256. `tests\auth.ps1` is the regression test for the implemented flow.

Registration JSON and exchange-code authentication are intentionally not claimed as implemented until their Fortnite 8.51 payloads are verified.
