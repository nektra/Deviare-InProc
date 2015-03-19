 ;
 ; Copyright (C) 2010-2015 Nektra S.A., Buenos Aires, Argentina.
 ; All rights reserved. Contact: http://www.nektra.com
 ;
 ;
 ; This file is part of Deviare In-Proc
 ;
 ;
 ; Commercial License Usage
 ; ------------------------
 ; Licensees holding valid commercial Deviare In-Proc licenses may use this
 ; file in accordance with the commercial license agreement provided with the
 ; Software or, alternatively, in accordance with the terms contained in
 ; a written agreement between you and Nektra.  For licensing terms and
 ; conditions see http://www.nektra.com/licensing/.  For further information
 ; use the contact form at http://www.nektra.com/contact/.
 ;
 ;
 ; GNU General Public License Usage
 ; --------------------------------
 ; Alternatively, this file may be used under the terms of the GNU
 ; General Public License version 3.0 as published by the Free Software
 ; Foundation and appearing in the file LICENSE.GPL included in the
 ; packaging of this file.  Please review the following information to
 ; ensure the GNU General Public License version 3.0 requirements will be
 ; met: http://www.gnu.org/copyleft/gpl.html.
 ;
 ;

_TEXT SEGMENT

;---------------------------------------------------------------------------------

IMAGE_DOS_SIGNATURE            EQU    5A4Dh     ;MZ
IMAGE_NT_SIGNATURE             EQU    00004550h ;PE00
IMAGE_NT_OPTIONAL_HDR64_MAGIC  EQU    20Bh
IMAGE_FILE_MACHINE_AMD64       EQU    8664h

UNICODE_STRING64 STRUCT 8
    _Length       WORD  ?
    MaximumLength WORD  ?
    Buffer        QWORD ?
UNICODE_STRING64 ENDS

LIST_ENTRY64 STRUCT
    Flink QWORD ?
    Blink QWORD ?
LIST_ENTRY64 ENDS

MODULE_ENTRY64 STRUCT
    InLoadOrderLinks           LIST_ENTRY64 <>
    InMemoryOrderLinks         LIST_ENTRY64 <>
    InInitializationOrderLinks LIST_ENTRY64 <>
    DllBase                    QWORD ?
    EntryPoint                 QWORD ?
    SizeOfImage                QWORD ?
    FullDllName                UNICODE_STRING64 <>
    BaseDllName                UNICODE_STRING64 <>
    Flags                      DWORD ?
    LoadCount                  WORD  ?
    ;structure continues but it is not needed
MODULE_ENTRY64 ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress DWORD ?
    _Size          DWORD ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_DOS_HEADER STRUCT
    e_magic    WORD  ?
    e_cblp     WORD  ?
    e_cp       WORD  ?
    e_crlc     WORD  ?
    e_cparhdr  WORD  ?
    e_minalloc WORD  ?
    e_maxalloc WORD  ?
    e_ss       WORD  ?
    e_sp       WORD  ?
    e_csum     WORD  ?
    e_ip       WORD  ?
    e_cs       WORD  ?
    e_lfarlc   WORD  ?
    e_ovno     WORD  ?
    e_res      DW 4 DUP (<?>)
    e_oemid    WORD  ?
    e_oeminfo  WORD  ?
    e_res2     DW 10 DUP (<?>)
    e_lfanew   DWORD ?
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
    Machine              WORD  ?
    NumberOfSections     WORD  ?
    TimeDateStamp        DWORD ?
    PointerToSymbolTable DWORD ?
    NumberOfSymbols      DWORD ?
    SizeOfOptionalHeader WORD  ?
    Characteristics      WORD  ?
IMAGE_FILE_HEADER ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT 
    Magic                       WORD  ?
    MajorLinkerVersion          BYTE  ?
    MinorLinkerVersion          BYTE  ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    ImageBase                   QWORD ?
    SectionAlignment            DWORD ?
    FileAlignment               DWORD ?
    MajorOperatingSystemVersion WORD  ?
    MinorOperatingSystemVersion WORD  ?
    MajorImageVersion           WORD  ?
    MinorImageVersion           WORD  ?
    MajorSubsystemVersion       WORD  ?
    MinorSubsystemVersion       WORD  ?
    Win32VersionValue           DWORD ?
    SizeOfImage                 DWORD ?
    SizeOfHeaders               DWORD ?
    CheckSum                    DWORD ?
    Subsystem                   WORD  ?
    DllCharacteristics          WORD  ?
    SizeOfStackReserve          QWORD ?
    SizeOfStackCommit           QWORD ?
    SizeOfHeapReserve           QWORD ?
    SizeOfHeapCommit            QWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY 16 DUP (<>)
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_NT_HEADERS64 STRUCT 
    Signature      DWORD ?
    FileHeader     IMAGE_FILE_HEADER <>
    OptionalHeader IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS

IMAGE_EXPORT_DIRECTORY STRUCT
    Characteristics       DWORD ?
    TimeDateStamp         DWORD ?
    MajorVersion          WORD  ?
    MinorVersion          WORD  ?
    _Name                 DWORD ?
    Base                  DWORD ?
    NumberOfFunctions     DWORD ?
    NumberOfNames         DWORD ?
    AddressOfFunctions    DWORD ?
    AddressOfNames        DWORD ?
    AddressOfNameOrdinals DWORD ?
IMAGE_EXPORT_DIRECTORY ENDS

;NOTE: Getting rid of the "error A2006: undefined symbol : rip" of MASM x64
GetPtr MACRO _reg:REQ, symbol:REQ, ofs:REQ
    DB   0E8h, 0, 0, 0, 0 ;call 0
    sub  QWORD PTR [rsp], OFFSET $ - (symbol + ofs)
    pop  _reg
ENDM

;---------------------------------------------------------------------------------

PUBLIC GETMODULEANDPROCADDR_SECTION_START
PUBLIC GETMODULEANDPROCADDR_SECTION_END

ALIGN 8
GETMODULEANDPROCADDR_SECTION_START:

ALIGN 8
;BOOL __stdcall SimpleStrNICmpW(LPCWSTR string1, LPCWSTR string2, SIZE_T len)
SimpleStrNICmpW PROC
    ;get string1 and check for null
    test rcx, rcx
    je   @@mismatch
    mov  r9, rcx
    ;get string2 and check for null
    test rdx, rdx
    je   @@mismatch
    ;get length and check for zero
    test r8, r8
    je   @@afterloop
@@loop:
    ;compare letter
    mov  ax, WORD PTR [r9]
    mov  cx, WORD PTR [rdx]
    cmp  cx, ax
    je   @@next
    ;check letters between A-Z and a-z
    cmp  ax, 41h
    jb   @@check2
    cmp  ax, 5Ah
    jbe  @@check2_test
@@check2:
    cmp  ax, 61h
    jb   @@mismatch
    cmp  ax, 7Ah
    ja   @@mismatch
@@check2_test:
    ;compare letter case insensitive
    or   ax, 20h
    or   cx, 20h
    cmp  cx, ax
    jne  @@mismatch
@@next:
    add  r9, 2
    add  rdx, 2
    dec  r8
    jne  @@loop
@@afterloop:
    cmp  WORD PTR [rdx], 0
    jne  @@mismatch
    xor  rax, rax
    inc  rax
    ret
@@mismatch:
    xor  rax, rax
    ret
SimpleStrNICmpW ENDP

ALIGN 8
;BOOL __stdcall SimpleStrCmpA(LPCSTR string1, LPCSTR string2)
SimpleStrCmpA PROC
    ;get string1 and check for null
    test rcx, rcx
    je   @@mismatch
    ;get string2 and check for null
    test rdx, rdx
    je   @@mismatch
@@loop:
    ;compare letter
    mov  al, BYTE PTR [rcx]
    cmp  al, BYTE PTR [rdx]
    jne  @@mismatch
    cmp  al, 0
    je   @F
    inc  rcx
    inc  rdx
    jne  @@loop
@@: ;match
    xor  rax, rax
    inc  rax
    ret
@@mismatch:
    xor  rax, rax
    ret
SimpleStrCmpA ENDP

ALIGN 8
;LPVOID __stcall GetPEB()
GetPEB PROC
    mov  rax, QWORD PTR gs:[30h]
    mov  rax, QWORD PTR [rax+60h]
    ret
GetPEB ENDP

ALIGN 8
;LPVOID __stdcall GetLoaderLockAddr()
GetLoaderLockAddr PROC
    call GetPEB
    mov  rax, QWORD PTR [rax+110h]
    ret
GetLoaderLockAddr ENDP

ALIGN 8
;BOOL __stdcall CheckImageType(LPVOID lpBase, LPVOID *lplpNtHdr)
CheckImageType PROC
    xor  rax, rax
    ;get lpBase and check for null
    test rcx, rcx
    je   @@end
    ;check dos header magic
    cmp  WORD PTR [rcx].IMAGE_DOS_HEADER.e_magic, IMAGE_DOS_SIGNATURE
    jne  @@end
    ;get header offset
    xor  r8, r8
    mov  r8d, DWORD PTR [rcx].IMAGE_DOS_HEADER.e_lfanew
    add  rcx, r8 ;rcx now points to NtHeader address
    ;check if we are asked to store NtHeader address 
    test rdx, rdx
    je   @F
    mov  QWORD PTR [rdx], rcx ;save it
@@: ;check image type
    cmp  WORD PTR [rcx].IMAGE_NT_HEADERS64.FileHeader.Machine, IMAGE_FILE_MACHINE_AMD64
    jne  @@end
    ;check magic
    cmp  WORD PTR [rcx].IMAGE_NT_HEADERS64.Signature, IMAGE_NT_SIGNATURE
    jne  @@end
    inc  rax
@@end:
    ret
CheckImageType ENDP

ALIGN 8
;LPVOID __stdcall GetModuleBaseAddress(LPCWSTR szDllNameW)
GetModuleBaseAddress PROC
szDllNameW$ = 20h+28h + 8h

    mov  QWORD PTR [rsp+8h], rcx ;save 1st parameter for later use
    sub  rsp, 20h + 28h             ;locals + shadow space + return address. Size should be 0x####8h always to mantain 16-byte alignment
    call GetPEB
    mov  rax, QWORD PTR [rax+18h] ;peb64+24 => pointer to PEB_LDR_DATA64
    test rax, rax
    je   @@not_found
    cmp  DWORD PTR [rax+4], 0h ;check PEB_LDR_DATA64.Initialize flag
    je   @@not_found
    mov  r10, rax
    add  r10, 10h ;r10 has the first link (PEB_LDR_DATA64.InLoadOrderModuleList.Flink)
    mov  rbx, QWORD PTR [r10]
@@loop:
    cmp  rbx, r10
    je   @@not_found
    ;check if this is the entry we are looking for...
    movzx r8, WORD PTR [rbx].MODULE_ENTRY64.BaseDllName._Length
    test r8, r8
    je   @@next
    shr  r8, 1 ;divide by 2 because they are unicode chars
    mov  rcx, QWORD PTR [rbx].MODULE_ENTRY64.BaseDllName.Buffer
    test rcx, rcx
    je   @@next
    mov  rdx, QWORD PTR szDllNameW$[rsp]
    CALL SimpleStrNICmpW
    test rax, rax
    je   @@next
    ;got it
    mov  rcx, QWORD PTR [rbx].MODULE_ENTRY64.DllBase
    xor  rdx, rdx
    call CheckImageType
    test rax, rax
    je   @@next
    mov  rax, QWORD PTR [rbx].MODULE_ENTRY64.DllBase
    jmp  @@found
@@next:
    mov  rbx, QWORD PTR [rbx].MODULE_ENTRY64.InLoadOrderLinks.Flink ;go to the next entry
    jmp  @@loop
@@not_found:
    xor  rax, rax
@@found:
    add  rsp, 20h + 28h
    ret
GetModuleBaseAddress ENDP

ALIGN 8
;LPVOID __stdcall GetProcedureAddress(LPVOID lpDllBase, LPCSTR szFuncNameA)
GetProcedureAddress PROC
lpDllBase$ = 40h+28h + 8h
szFuncNameA$ = 40h+28h + 10h
_lpNtHdr$ = 32
_nNamesCount$ = 40
_lpAddrOfNames$ = 48

    mov  QWORD PTR [rsp+8h], rcx ;save 1st parameter for later use
    mov  QWORD PTR [rsp+10h], rdx ;save 2nd parameter for later use
    sub  rsp, 38h + 28h             ;locals + shadow space + return address. Size should be 0x####8h always to mantain 16-byte alignment
    push r13
    ;check szFuncNameA for null
    test rdx, rdx
    je   @@not_found
    ;get module base address and check for null
    test rcx, rcx
    je   @@not_found
    ;get nt header
    lea  rdx, QWORD PTR _lpNtHdr$[rsp]
    call CheckImageType
    test rax, rax
    je   @@not_found
    ;check export data directory
    mov  rax, QWORD PTR _lpNtHdr$[rsp]
    cmp  DWORD PTR [rax].IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[0]._Size, 0
    je   @@not_found
    xor  r8, r8
    mov  r8d, DWORD PTR [rax].IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[0].VirtualAddress
    test r8d, r8d
    je   @@not_found
    add  r8, QWORD PTR lpDllBase$[rsp]
    ;get the number of names
    xor  rax, rax
    mov  eax, DWORD PTR [r8].IMAGE_EXPORT_DIRECTORY.NumberOfNames
    mov  QWORD PTR _nNamesCount$[rsp], rax
    ;get the AddressOfNames
    xor  rax, rax
    mov  eax, DWORD PTR [r8].IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add  rax, QWORD PTR lpDllBase$[rsp]
    mov  QWORD PTR _lpAddrOfNames$[rsp], rax
    ;main loop
    xor  r13, r13
@@loop:
    cmp  r13, QWORD PTR _nNamesCount$[rsp]
    jae  @@not_found
    ;get exported name
    mov  rdx, QWORD PTR szFuncNameA$[rsp]
    mov  rax, QWORD PTR _lpAddrOfNames$[rsp]
    xor  rcx, rcx
    mov  ecx, DWORD PTR [rax]
    add  rcx, QWORD PTR lpDllBase$[rsp]
    call SimpleStrCmpA
    test rax, rax
    je   @@next
    ;got the function
    xor  rax, rax
    mov  eax, DWORD PTR [r8].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
    add  rax, QWORD PTR lpDllBase$[rsp]
    shl  r13, 1
    add  rax, r13
    xor  rcx, rcx
    mov  cx, WORD PTR [rax] ;get the ordinal of this function
    xor  rax, rax
    mov  eax, DWORD PTR [r8].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add  rax, QWORD PTR lpDllBase$[rsp]
    shl  rcx, 2
    add  rcx, rax
    ;get the function address
    xor  rax, rax
    mov  eax, DWORD PTR [rcx]
    add  rax, QWORD PTR lpDllBase$[rsp]
    jmp  @@found
@@next:
    add  QWORD PTR _lpAddrOfNames$[rsp], 4
    inc  r13
    jmp  @@loop
@@not_found:
    xor  rax, rax
@@found:
    pop  r13
    add  rsp, 38h + 28h
    ret
GetProcedureAddress ENDP

GETMODULEANDPROCADDR_SECTION_END:

;---------------------------------------------------------------------------------

PUBLIC INJECTDLLINSUSPENDEDPROCESS_SECTION_START
PUBLIC INJECTDLLINSUSPENDEDPROCESS_SECTION_END

ALIGN 8
INJECTDLLINSUSPENDEDPROCESS_SECTION_START:

ALIGN 8
InjectDllInSuspendedProcess PROC
_GETPROCADDR_1     EQU 0
_GETMODBASEADDR_1  EQU 8
_HINST_1           EQU 16
_SEARCHPATH_1      EQU 24
_DLLCHARACT_1      EQU 28
_DLLNAME_1         EQU 32
_SZ_NTDLLDLL_1     EQU 48
_SZ_LDRLOADDLL_1   EQU 72

    db   8 DUP (0h)                                                  ;offset 0: address of GetProcedureAddress
    db   8 DUP (0h)                                                  ;offset 8: address of GetModuleBaseAddress
    db   8 DUP (0h)                                                  ;offset 16: will hold the dll instance
    db   '.', 0, 0, 0                                                ;offset 24: search path
    db   4 DUP (0h)                                                  ;offset 28: dll characteristics
    db   16 DUP (0h)                                                 ;offset 32: UNICODE_STRING of dll to inject
    dw   'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0, 0, 0        ;offset 48: L"ntdll.dll"
    db   'LdrLoadDll', 0, 0, 0, 0, 0, 0                              ;offset 72: "LdrLoadDll"

    ;offset 88: code start
    push rax
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    pushfq
    sub  rsp, 40h

    ;get ntdll.dll base address
    GetPtr rcx, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _SZ_NTDLLDLL_1
    GetPtr rax, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _GETMODBASEADDR_1
    call QWORD PTR [rax]
    test rax, rax
    je   @@done

    ;get address of LdrLoadDll
    mov rcx, rax ;hinstance
    GetPtr rdx, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _SZ_LDRLOADDLL_1
    GetPtr rax, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _GETPROCADDR_1
    call QWORD PTR [rax]
    test rax, rax
    je   @@done

    ;call LdrLoadDll
    GetPtr rcx, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _SEARCHPATH_1
    GetPtr rdx, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _DLLCHARACT_1
    GetPtr r8, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _DLLNAME_1
    GetPtr r9, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _HINST_1
    call rax

@@done:
    add  rsp, 40h
    popfq
    pop  rdi
    pop  rsi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ;jmp to original address
    db   48h, 0FFh, 25h
    dd   0
    dq   0
InjectDllInSuspendedProcess ENDP

INJECTDLLINSUSPENDEDPROCESS_SECTION_END:

;---------------------------------------------------------------------------------

PUBLIC INJECTDLLINRUNNINGPROCESS_SECTION_START
PUBLIC INJECTDLLINRUNNINGPROCESS_SECTION_END

ALIGN 8
INJECTDLLINRUNNINGPROCESS_SECTION_START:

ALIGN 8
InjectDllInRunningProcess PROC
_GETPROCADDR_2                    EQU 0
_GETMODBASEADDR_2                 EQU 8
_HINST_2                          EQU 16
_SEARCHPATH_2                     EQU 24
_DLLCHARACT_2                     EQU 28
_DLLNAME_2                        EQU 32
_READYEVENT_2                     EQU 48
_CONTINUEEVENT_2                  EQU 56
_ADDR_LDRLOADDLL_2                EQU 64
_ADDR_NTCLOSE_2                   EQU 72
_ADDR_NTSETEVENT_2                EQU 80
_ADDR_NTWAITFORMULTIPLEOBJECTS_2  EQU 88
_SZ_NTDLLDLL_2                    EQU 96
_SZ_LDRLOADDLL_2                  EQU 120
_SZ_NTCLOSE_2                     EQU 136
_SZ_NTSETEVENT_2                  EQU 144
_SZ_NTWAITFORMULTIPLEOBJECTS_2    EQU 156

    db   8 DUP (0h)                                                  ;offset 0: address of GetProcedureAddress
    db   8 DUP (0h)                                                  ;offset 8: address of GetModuleBaseAddress
    db   8 DUP (0h)                                                  ;offset 16: will hold the dll instance
    db   '.', 0, 0, 0                                                ;offset 24: search path
    db   4 DUP (0h)                                                  ;offset 28: dll characteristics
    db   16 DUP (0h)                                                 ;offset 32: UNICODE_STRING of dll to inject
    db   8 DUP (0h)                                                  ;offset 48: ready event handle
    db   8 DUP (0h)                                                  ;offset 56: continue event handle
    db   8 DUP (0h)                                                  ;offset 64: address of LdrLoadDll
    db   8 DUP (0h)                                                  ;offset 72: address of NtClose
    db   8 DUP (0h)                                                  ;offset 80: address of NtSetEvent
    db   8 DUP (0h)                                                  ;offset 88: address of NtWaitForMultipleObjects
    dw   'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0, 0, 0        ;offset 96: L"ntdll.dll"
    db   'LdrLoadDll', 0, 0, 0, 0, 0, 0                              ;offset 120: "LdrLoadDll"
    db   'NtClose', 0                                                ;offset 136: "NtClose"
    db   'NtSetEvent', 0, 0                                          ;offset 144: "NtSetEvent"
    db   'NtWaitForMultipleObjects', 0, 0, 0, 0                      ;offset 156: "NtWaitForMultipleObjects"

    ;offset 184: code start
    push rax
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    pushfq
    sub  rsp, 40h

    ;get ntdll.dll base address
    GetPtr rcx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTDLLDLL_2
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _GETMODBASEADDR_2
    call QWORD PTR [rax]
    test rax, rax
    je   @@done

    mov  r12, rax ;save hinstance
    GetPtr r13, INJECTDLLINRUNNINGPROCESS_SECTION_START, _GETPROCADDR_2

    ;get address of LdrLoadDll
    mov  rcx, r12 ;hinstance
    GetPtr rdx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_LDRLOADDLL_2
    call QWORD PTR [r13]
    test rax, rax
    je   @@done
    GetPtr rcx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_LDRLOADDLL_2
    mov  QWORD PTR [rcx], rax

    ;get address of NtClose
    mov  rcx, r12 ;hinstance
    GetPtr rdx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTCLOSE_2
    call QWORD PTR [r13]
    test rax, rax
    je   @@done
    GetPtr rcx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTCLOSE_2
    mov  QWORD PTR [rcx], rax

    ;get address of NtSetEvent
    mov rcx, r12 ;hinstance
    GetPtr rdx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTSETEVENT_2
    call QWORD PTR [r13]
    test rax, rax
    je   @@done
    GetPtr rcx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTSETEVENT_2
    mov  QWORD PTR [rcx], rax

    ;get address of NtWaitForMultipleObjects
    mov rcx, r12 ;hinstance
    GetPtr rdx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTWAITFORMULTIPLEOBJECTS_2
    call QWORD PTR [r13]
    test rax, rax
    je   @@done
    GetPtr rcx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_2
    mov  QWORD PTR [rcx], rax

    ;wait for ready event ?
    GetPtr rdx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _READYEVENT_2
    cmp  QWORD PTR [rdx], 0
    je   @F
    mov  rcx, 1
    mov  r8, 1 ;WaitAnyObject
    xor  r9, r9 ;FALSE
    mov  QWORD PTR [rsp+20h], 0
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_2
    call QWORD PTR [rax]

    ;close ready event
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _READYEVENT_2
    mov  rcx, QWORD PTR [rax]
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTCLOSE_2
    call QWORD PTR [rax]
@@:

    ;load library
    GetPtr rcx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SEARCHPATH_2
    GetPtr rdx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _DLLCHARACT_2
    GetPtr r8, INJECTDLLINRUNNINGPROCESS_SECTION_START, _DLLNAME_2
    GetPtr r9, INJECTDLLINRUNNINGPROCESS_SECTION_START, _HINST_2
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_LDRLOADDLL_2
    call QWORD PTR [rax]

    ;set continue event
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _CONTINUEEVENT_2
    mov  rcx, QWORD PTR [rax]
    cmp  rcx, 0
    je   @F
    xor  rdx, rdx ;NULL
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTSETEVENT_2
    call QWORD PTR [rax]

    ;close continue event
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _CONTINUEEVENT_2
    mov  rcx, QWORD PTR [rax]
    GetPtr rax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTCLOSE_2
    call QWORD PTR [rax]
@@:

@@done:
    add  rsp, 40h
    popfq
    pop  rdi
    pop  rsi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    xor  rax, rax
    ret
InjectDllInRunningProcess ENDP

INJECTDLLINRUNNINGPROCESS_SECTION_END:

;---------------------------------------------------------------------------------

PUBLIC WAITFOREVENTATSTARTUP_SECTION_START
PUBLIC WAITFOREVENTATSTARTUP_SECTION_END

ALIGN 8
WAITFOREVENTATSTARTUP_SECTION_START:

ALIGN 8
WaitForEventAtStartup PROC
_GETPROCADDR_3                    EQU 0
_GETMODBASEADDR_3                 EQU 8
_READYEVENT_3                     EQU 16
_CONTINUEEVENT_3                  EQU 24
_CONTROLLERPROC_3                 EQU 32
_ADDR_NTCLOSE_3                   EQU 40
_ADDR_NTSETEVENT_3                EQU 48
_ADDR_NTWAITFORMULTIPLEOBJECTS_3  EQU 56
_SZ_NTDLLDLL_3                    EQU 64
_SZ_NTCLOSE_3                     EQU 88
_SZ_NTSETEVENT_3                  EQU 96
_SZ_NTWAITFORMULTIPLEOBJECTS_3    EQU 108

    db   8 DUP (0h)                                                  ;offset 0: address of GetProcedureAddress
    db   8 DUP (0h)                                                  ;offset 8: address of GetModuleBaseAddress
    db   8 DUP (0h)                                                  ;offset 16: ready event handle
    db   8 DUP (0h)                                                  ;offset 24: continue event handle
    db   8 DUP (0h)                                                  ;offset 32: controller process handle
    db   8 DUP (0h)                                                  ;offset 40: address of NtClose
    db   8 DUP (0h)                                                  ;offset 48: address of NtSetEvent
    db   8 DUP (0h)                                                  ;offset 56: address of NtWaitForMultipleObjects
    dw   'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0, 0, 0        ;offset 64: L"ntdll.dll"
    db   'NtClose', 0                                                ;offset 88: "NtClose"
    db   'NtSetEvent', 0, 0                                          ;offset 96: "NtSetEvent"
    db   'NtWaitForMultipleObjects', 0, 0, 0, 0                      ;offset 108: "NtWaitForMultipleObjects"

    ;offset 136: code start
    push rax
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    pushfq
    sub  rsp, 40h

    ;get ntdll.dll base address
    GetPtr rcx, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTDLLDLL_3
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _GETMODBASEADDR_3
    call QWORD PTR [rax]
    test rax, rax
    je   @@done

    mov  r12, rax ;save hinstance
    GetPtr r13, WAITFOREVENTATSTARTUP_SECTION_START, _GETPROCADDR_3

    ;get address of NtClose
    mov  rcx, r12 ;hinstance
    GetPtr rdx, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTCLOSE_3
    call QWORD PTR [r13]
    test rax, rax
    je   @@done
    GetPtr rcx, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    mov  QWORD PTR [rcx], rax

    ;get address of NtSetEvent
    mov rcx, r12 ;hinstance
    GetPtr rdx, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTSETEVENT_3
    call QWORD PTR [r13]
    test rax, rax
    je   @@done
    GetPtr rcx, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTSETEVENT_3
    mov  QWORD PTR [rcx], rax

    ;get address of NtWaitForMultipleObjects
    mov rcx, r12 ;hinstance
    GetPtr rdx, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTWAITFORMULTIPLEOBJECTS_3
    call QWORD PTR [r13]
    test rax, rax
    je   @@done
    GetPtr rcx, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_3
    mov  QWORD PTR [rcx], rax

    ;set ready event
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _READYEVENT_3
    mov  rcx, QWORD PTR [rax]
    xor  rdx, rdx ;NULL
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTSETEVENT_3
    call QWORD PTR [rax]

    ;close ready event
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _READYEVENT_3
    mov  rcx, QWORD PTR [rax]
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    call QWORD PTR [rax]

    ;wait for continue event or controller process termination
    mov  rcx, 2
    GetPtr rdx, WAITFOREVENTATSTARTUP_SECTION_START, _CONTINUEEVENT_3
    mov  r8, 1 ;WaitAnyObject
    xor  r9, r9 ;FALSE
    mov  QWORD PTR [rsp+20h], 0
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_3
    call QWORD PTR [rax]

    ;close continue event
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _CONTINUEEVENT_3
    mov  rcx, QWORD PTR [rax]
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    call QWORD PTR [rax]

    ;close controller process
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _CONTROLLERPROC_3
    mov  rcx, QWORD PTR [rax]
    GetPtr rax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    call QWORD PTR [rax]

@@done:
    add  rsp, 40h
    popfq
    pop  rdi
    pop  rsi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ;jmp to original address
    db   48h, 0FFh, 25h
    dd   0
    dq   0
WaitForEventAtStartup ENDP

WAITFOREVENTATSTARTUP_SECTION_END:

;---------------------------------------------------------------------------------

_TEXT ENDS

END
