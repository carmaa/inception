;-----------------------------------------------------------------------------;
; kernel32.dll!ExitThread (0x0A2A1DE0) - This exit function will force the 
; current thread to terminate. On Windows 2008, Vista and 7 this function is
; a forwarded export to ntdll.dll!RtlExitUserThread and as such cannot be 
; called by the api_call function.
;
; ntdll.dll!RtlExitUserThread (0x6F721347) - This exit function will force 
; the current thread to terminate. This function is not available on Windows 
; NT or 2000.
;-----------------------------------------------------------------------------;
; Windows 7               6.1  
; Windows Server 2008 R2  6.1   We must call
; Windows Server 2008     6.0   RtlExitUserThread instead.
; Windows Vista           6.0 _______________________________________________
; Windows Server 2003 R2  5.2
; Windows Server 2003     5.2
; Windows XP              5.1
; Windows 2000            5.0
; Windows NT4             4.0
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: None.
; Clobbers: EAX, EBX, (ESP will also be modified)
; Note: Execution is not expected to (successfully) continue past this block

exitthread:
  mov ebx, 0x0A2A1DE0    ; hash( "kernel32.dll", "ExitThread" )
  push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
  call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
  cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
  jl short goodbye       ; Then just call the exit function...
  mov ebx, 0x6F721347    ; Else we swap the ExitThread to that of RtlExitUserThread
goodbye:                 ; We now perform the actual call to the exit function
  push byte 0            ; push the exit function parameter
  push ebx               ; push the hash of the exit function
  call ebp               ; call ExitThread/RtlExitUserThread( 0 );
