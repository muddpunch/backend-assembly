default rel
bits 64

global main

%include "src/config.inc"
%include "src/data.asm"
%include "src/response.asm"
%include "src/parser.asm"
%include "src/crypto.asm"
%include "src/storage.asm"
%include "src/auth.asm"
%include "src/router.asm"
%include "src/server.asm"
