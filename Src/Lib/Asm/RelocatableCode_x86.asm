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

.386
.model flat, stdcall
.code

_TEXT SEGMENT

;---------------------------------------------------------------------------------

IMAGE_DOS_SIGNATURE            EQU    5A4Dh     ;MZ
IMAGE_NT_SIGNATURE             EQU    00004550h ;PE00
IMAGE_FILE_MACHINE_I386        EQU    14ch
IMAGE_NT_OPTIONAL_HDR32_MAGIC  EQU    10Bh

UNICODE_STRING32 STRUCT 8
    _Length       WORD  ?
    MaximumLength WORD  ?
    Buffer        DWORD ?
UNICODE_STRING32 ENDS
   
LIST_ENTRY32 STRUCT
    Flink DWORD ?
    Blink DWORD ?
LIST_ENTRY32 ENDS

MODULE_ENTRY32 STRUCT
    InLoadOrderLinks           LIST_ENTRY32 <>
    InMemoryOrderLinks         LIST_ENTRY32 <>
    InInitializationOrderLinks LIST_ENTRY32 <>
    DllBase                    DWORD ?
    EntryPoint                 DWORD ?
    SizeOfImage                DWORD ?
    FullDllName                UNICODE_STRING32 <>
    BaseDllName                UNICODE_STRING32 <>
    Flags                      DWORD ?
    LoadCount                  WORD  ?
    ;structure continues but it is not needed
MODULE_ENTRY32 ENDS

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
    e_res      WORD  4 DUP (?)
    e_oemid    WORD  ?
    e_oeminfo  WORD  ?
    e_res2     WORD 10 DUP (?)
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

IMAGE_OPTIONAL_HEADER32 STRUCT
    Magic                       WORD  ?
    MajorLinkerVersion          BYTE  ?
    MinorLinkerVersion          BYTE  ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    BaseOfData                  DWORD ?
    ;NT additional fields
    ImageBase                   DWORD ?
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
    SizeOfStackReserve          DWORD ?
    SizeOfStackCommit           DWORD ?
    SizeOfHeapReserve           DWORD ?
    SizeOfHeapCommit            DWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY 16 DUP (<>)
IMAGE_OPTIONAL_HEADER32 ENDS

IMAGE_NT_HEADERS32 STRUCT 
    Signature      DWORD ?
    FileHeader     IMAGE_FILE_HEADER <>
    OptionalHeader IMAGE_OPTIONAL_HEADER32 <>
IMAGE_NT_HEADERS32 ENDS

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

GetPtr MACRO _reg:REQ, symbol:REQ, ofs:REQ
    DB   0E8h, 0, 0, 0, 0 ;call 0
    pop  _reg
    sub  _reg, OFFSET $ - (symbol + ofs) - 1
ENDM

;---------------------------------------------------------------------------------

PUBLIC GETMODULEANDPROCADDR_SECTION_START
PUBLIC GETMODULEANDPROCADDR_SECTION_END

ALIGN 4
GETMODULEANDPROCADDR_SECTION_START:

ALIGN 4
;BOOL __stdcall SimpleStrNICmpW(LPCWSTR string1, LPCWSTR string2, SIZE_T len)
SimpleStrNICmpW PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push esi
    push edi
    ;get string1 and check for null
    mov  esi, DWORD PTR [ebp+08h]
    test esi, esi
    je   @@mismatch
    ;get string2 and check for null
    mov  edi, DWORD PTR [ebp+0Ch] 
    test edi, edi
    je   @@mismatch
    ;get length and check for zero
    mov  ecx, DWORD PTR [ebp+10h] ;length
    test ecx, ecx
    je   @@afterloop
@@loop:
    ;compare letter
    mov  ax, WORD PTR [esi]
    mov  bx, WORD PTR [edi]
    cmp  bx, ax
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
    or   bx, 20h
    cmp  bx, ax
    jne  @@mismatch
@@next:
    add  esi, 2
    add  edi, 2
    dec  ecx
    jne  @@loop
@@afterloop:
    cmp WORD PTR [edi], 0
    jne @@mismatch
    xor  eax, eax
    inc  eax
    jmp  @@end
@@mismatch:
    xor  eax, eax
@@end:
    pop  edi
    pop  esi
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  0Ch ;pop parameters
SimpleStrNICmpW ENDP

ALIGN 4
;BOOL __stdcall SimpleStrCmpA(LPCSTR string1, LPCSTR string2)
SimpleStrCmpA PROC
    push ebp
    mov  ebp, esp
    push esi
    push edi
    ;get string1 and check for null
    mov  esi, DWORD PTR [ebp+08h]
    test esi, esi
    je   @@mismatch
    ;get string2 and check for null
    mov  edi, DWORD PTR [ebp+0Ch] 
    test edi, edi
    je   @@mismatch
@@loop:
    ;compare letter
    mov  al, BYTE PTR [esi]
    cmp  al, BYTE PTR [edi]
    jne  @@mismatch
    cmp  al, 0
    je   @F
    inc  esi
    inc  edi
    jne  @@loop
@@: ;match
    xor  eax, eax
    inc  eax
    jmp  @@end
@@mismatch:
    xor  eax, eax
@@end:
    pop  edi
    pop  esi
    mov  esp, ebp 
    pop  ebp
    ret  8h ;pop parameters
SimpleStrCmpA ENDP

ALIGN 4
;LPVOID __stcall GetPEB()
GetPEB PROC
ASSUME FS:NOTHING
    mov  eax, DWORD PTR [fs:30h]
ASSUME FS:ERROR
    ret
GetPEB ENDP

ALIGN 4
;LPVOID __stdcall GetLoaderLockAddr()
GetLoaderLockAddr PROC
    call GetPEB
    mov  eax, DWORD PTR [eax+0A0h]
    ret
GetLoaderLockAddr ENDP

ALIGN 4
;BOOL __stdcall CheckImageType(LPVOID lpBase, LPVOID *lplpNtHdr)
CheckImageType PROC
    push ebp
    mov  ebp, esp
    push ecx
    push edx
    ;get lpBase and check for null
    xor  eax, eax
    mov  ecx, DWORD PTR [ebp+8h]
    test ecx, ecx
    je   @@end
    ;check dos header magic
    cmp  WORD PTR [ecx].IMAGE_DOS_HEADER.e_magic, IMAGE_DOS_SIGNATURE
    jne  @@end
    ;get header offset
    mov  edx, DWORD PTR [ecx].IMAGE_DOS_HEADER.e_lfanew
    add  ecx, edx ;ecx now points to NtHeader address
    ;check if we are asked to store NtHeader address 
    mov  edx, DWORD PTR [ebp+0Ch]
    test edx, edx 
    je   @F
    mov  DWORD PTR [edx], ecx ;save it
@@: ;check image type
    cmp  WORD PTR [ecx].IMAGE_NT_HEADERS32.FileHeader.Machine, IMAGE_FILE_MACHINE_I386
    jne  @@end
    ;check magic
    cmp  WORD PTR [ecx].IMAGE_NT_HEADERS32.Signature, IMAGE_NT_SIGNATURE
    jne  @@end
    inc  eax
@@end:
    pop  edx
    pop  ecx
    mov  esp, ebp 
    pop  ebp
    ret  8h ;pop parameters
CheckImageType ENDP

ALIGN 4
;LPVOID __stdcall GetModuleBaseAddress(LPCWSTR szDllNameW)
GetModuleBaseAddress PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push esi
    call  GetPEB
    mov  eax, DWORD PTR [eax+0Ch] ;peb32+12 => pointer to PEB_LDR_DATA32
    test eax, eax
    je   @@not_found
    cmp  DWORD PTR [eax+4], 0h ;check PEB_LDR_DATA32.Initialize flag
    je   @@not_found
    mov  esi, eax
    add  esi, 0Ch ;esi has the first link (PEB_LDR_DATA32.InLoadOrderModuleList.Flink)
    mov  ebx, DWORD PTR [esi]
@@loop:
    cmp  ebx, esi
    je   @@not_found
    ;check if this is the entry we are looking for...
    movzx ecx, WORD PTR [ebx].MODULE_ENTRY32.BaseDllName._Length
    test ecx, ecx
    je   @@next
    shr  ecx, 1 ;divide by 2 because they are unicode chars
    mov  eax, DWORD PTR [ebx].MODULE_ENTRY32.BaseDllName.Buffer
    test eax, eax
    je   @@next
    push ecx                 ;push 3rd param (length)
    push DWORD PTR [ebp+08h] ;push 2nd param (dll name to find)
    push eax                 ;push 1st param (string)
    CALL SimpleStrNICmpW
    test eax, eax
    je   @@next
    ;got it
    push 0
    push DWORD PTR [ebx].MODULE_ENTRY32.DllBase
    call CheckImageType
    test eax, eax
    je   @@next
    mov  eax, DWORD PTR [ebx].MODULE_ENTRY32.DllBase
    jmp  @@found
@@next:
    mov  ebx, DWORD PTR [ebx].MODULE_ENTRY32.InLoadOrderLinks.Flink ;go to the next entry
    jmp  @@loop
@@not_found:
    xor  eax, eax
@@found:
    pop  esi
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  4h ;pop parameters
GetModuleBaseAddress ENDP

ALIGN 4
;LPVOID __stdcall GetProcedureAddress(LPVOID lpDllBase, LPCSTR szFuncNameA)
GetProcedureAddress PROC
_lpNtHdr$ = -8
_nNamesCount$ = -12
_lpAddrOfNames$ = -16

    push ebp
    mov  ebp, esp
    sub  esp, 20h
    push ebx
    push ecx
    push esi
    ;check szFuncNameA for null
    cmp  DWORD PTR [ebp+0Ch], 0
    je   @@not_found
    ;get module base address and check for null
    mov  ecx, DWORD PTR [ebp+8h]
    test ecx, ecx
    je   @@not_found
    ;get nt header
    lea  eax, DWORD PTR _lpNtHdr$[ebp]
    push eax
    push ecx
    call CheckImageType
    test eax, eax
    je   @@not_found
    ;check export data directory
    mov  eax, DWORD PTR _lpNtHdr$[ebp]
    cmp  DWORD PTR [eax].IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory[0]._Size, 0
    je   @@not_found
    mov  esi, DWORD PTR [eax].IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory[0].VirtualAddress
    test esi, esi
    je   @@not_found
    add  esi, DWORD PTR [ebp+8h]
    ;get the number of names
    mov  eax, DWORD PTR [esi].IMAGE_EXPORT_DIRECTORY.NumberOfNames
    mov  DWORD PTR _nNamesCount$[ebp], eax
    ;get the AddressOfNames
    mov  eax, DWORD PTR [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add  eax, DWORD PTR [ebp+8h]
    mov  DWORD PTR _lpAddrOfNames$[ebp], eax
    ;main loop
    xor  ecx, ecx
@@loop:
    cmp  ecx, DWORD PTR _nNamesCount$[ebp]
    jae  @@not_found
    ;get exported name
    push DWORD PTR [ebp+0Ch]
    mov  eax, DWORD PTR _lpAddrOfNames$[ebp]
    mov  eax, DWORD PTR [eax]
    add  eax, DWORD PTR [ebp+8h]
    push eax
    call SimpleStrCmpA
    test eax, eax
    je   @@next
    ;got the function
    mov  eax, DWORD PTR [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
    add  eax, DWORD PTR [ebp+8h]
    shl  ecx, 1
    add  eax, ecx
    movzx ecx, WORD PTR [eax] ;get the ordinal of this function
    mov  eax, DWORD PTR [esi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add  eax, DWORD PTR [ebp+8h]
    shl  ecx, 2
    add  eax, ecx
    ;get the function address
    mov  eax, DWORD PTR [eax]
    add  eax, DWORD PTR [ebp+8h]
    jmp  @@found
@@next:
    add  DWORD PTR _lpAddrOfNames$[ebp], 4
    inc  ecx
    jmp  @@loop
@@not_found:
    xor  eax, eax
@@found:
    pop  esi
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8h ;pop parameters
GetProcedureAddress ENDP

GETMODULEANDPROCADDR_SECTION_END:

;---------------------------------------------------------------------------------

PUBLIC INJECTDLLINSUSPENDEDPROCESS_SECTION_START
PUBLIC INJECTDLLINSUSPENDEDPROCESS_SECTION_END

ALIGN 4
INJECTDLLINSUSPENDEDPROCESS_SECTION_START:

ALIGN 4
InjectDllInSuspendedProcess PROC
_GETPROCADDR_1      EQU 0
_GETMODBASEADDR_1   EQU 4
_HINST_1            EQU 8
_DLLNAME_1          EQU 12
_SZ_KERNEL32DLL_1   EQU 16
_SZ_LOADLIBRARYW_1  EQU 48

    db   4 DUP (0h)                                                  ;offset 0: address of GetProcedureAddress
    db   4 DUP (0h)                                                  ;offset 4: address of GetModuleBaseAddress
    db   4 DUP (0h)                                                  ;offset 8: will hold the dll instance
    db   4 DUP (0h)                                                  ;offset 12: pointer to dll name
    dw   'k','e','r','n','e','l','3','2','.','d','l','l',0,0,0,0     ;offset 16: L"kernel32.dll"
    db   'LoadLibraryW', 0, 0, 0, 0                                  ;offset 48: "LoadLibraryW"

    ;offset 64: code start
    push ebp
    mov  ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    pushfd

    ;get kernel32.dll base address
    GetPtr eax, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _SZ_KERNEL32DLL_1
    push eax
    GetPtr eax, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _GETMODBASEADDR_1
    call DWORD PTR [eax]
    test eax, eax
    je   @@done

    ;get address of LoadLibraryW
    GetPtr ecx, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _SZ_LOADLIBRARYW_1
    push ecx
    push eax ;hinstance
    GetPtr eax, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _GETPROCADDR_1
    call DWORD PTR [eax]
    test eax, eax
    je   @@done

    ;load library
    GetPtr ecx, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _DLLNAME_1
    push DWORD PTR [ecx]
    call eax
    ;save hInstance
    GetPtr ecx, INJECTDLLINSUSPENDEDPROCESS_SECTION_START, _HINST_1
    mov DWORD PTR [ecx], eax

@@done:
    popfd
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    pop  eax
    pop  ebp
    ;jmp to original address
    db   0E9h, 0h, 0h, 0h, 0h
InjectDllInSuspendedProcess ENDP

INJECTDLLINSUSPENDEDPROCESS_SECTION_END:

;---------------------------------------------------------------------------------

PUBLIC INJECTDLLINRUNNINGPROCESS_SECTION_START
PUBLIC INJECTDLLINRUNNINGPROCESS_SECTION_END

ALIGN 4
INJECTDLLINRUNNINGPROCESS_SECTION_START:

ALIGN 4
InjectDllInRunningProcess PROC
_GETPROCADDR_2                    EQU 0
_GETMODBASEADDR_2                 EQU 4
_HINST_2                          EQU 8
_DLLNAME_2                        EQU 12
_READYEVENT_2                     EQU 16
_CONTINUEEVENT_2                  EQU 20
_ADDR_LOADLIBRARYW_2              EQU 24
_ADDR_NTCLOSE_2                   EQU 28
_ADDR_NTSETEVENT_2                EQU 32
_ADDR_NTWAITFORMULTIPLEOBJECTS_2  EQU 36
_SZ_KERNEL32DLL_2                 EQU 40
_SZ_LOADLIBRARYW_2                EQU 72
_SZ_NTDLLDLL_2                    EQU 88
_SZ_NTCLOSE_2                     EQU 120
_SZ_NTSETEVENT_2                  EQU 128
_SZ_NTWAITFORMULTIPLEOBJECTS_2    EQU 144

    db   4 DUP (0h)                                                  ;offset 0: address of GetProcedureAddress
    db   4 DUP (0h)                                                  ;offset 4: address of GetModuleBaseAddress
    db   4 DUP (0h)                                                  ;offset 8: will hold the dll instance
    db   4 DUP (0h)                                                  ;offset 12: pointer to dll name
    db   4 DUP (0h)                                                  ;offset 16: ready event handle
    db   4 DUP (0h)                                                  ;offset 20: continue event handle
    db   4 DUP (0h)                                                  ;offset 24: address of LoadLibraryW
    db   4 DUP (0h)                                                  ;offset 28: address of NtClose
    db   4 DUP (0h)                                                  ;offset 32: address of NtSetEvent
    db   4 DUP (0h)                                                  ;offset 36: address of NtWaitForMultipleObjects
    dw   'k','e','r','n','e','l','3','2','.','d','l','l',0,0,0,0     ;offset 40: L"kernel32.dll"
    db   'LoadLibraryW', 0, 0, 0, 0                                  ;offset 72: "LoadLibraryW"
    dw   'n','t','d','l','l','.','d','l','l', 0,0,0,0,0,0,0          ;offset 88: L"ntdll.dll"
    db   'NtClose', 0                                                ;offset 120: "NtClose"
    db   'NtSetEvent', 0,0,0,0,0,0                                   ;offset 128: "NtSetEvent"
    db   'NtWaitForMultipleObjects', 0,0,0,0,0,0,0,0                 ;offset 144: "NtWaitForMultipleObjects"

    ;offset 176: code start
    push ebp
    mov  ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    pushfd

    ;get kernel32.dll base address
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_KERNEL32DLL_2
    push eax
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _GETMODBASEADDR_2
    call DWORD PTR [eax]
    test eax, eax
    je   @@done

    mov edx, eax ;save hinstance
    GetPtr ebx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _GETPROCADDR_2

    ;get address of LoadLibraryW
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_LOADLIBRARYW_2
    push eax
    push edx ;hinstance
    call DWORD PTR [ebx]
    test eax, eax
    je   @@done
    GetPtr ecx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_LOADLIBRARYW_2
    mov  DWORD PTR [ecx], eax

    ;get ntdll.dll base address
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTDLLDLL_2
    push eax
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _GETMODBASEADDR_2
    call DWORD PTR [eax]
    test eax, eax
    je   @@done

    mov edx, eax ;save hinstance
    GetPtr ebx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _GETPROCADDR_2

    ;get address of NtClose
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTCLOSE_2
    push eax
    push edx ;hinstance
    call DWORD PTR [ebx]
    test eax, eax
    je   @@done
    GetPtr ecx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTCLOSE_2
    mov  DWORD PTR [ecx], eax

    ;get address of NtSetEvent
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTSETEVENT_2
    push eax
    push edx ;hinstance
    call DWORD PTR [ebx]
    test eax, eax
    je   @@done
    GetPtr ecx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTSETEVENT_2
    mov  DWORD PTR [ecx], eax

    ;get address of NtWaitForMultipleObjects
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _SZ_NTWAITFORMULTIPLEOBJECTS_2
    push eax
    push edx ;hinstance
    call DWORD PTR [ebx]
    test eax, eax
    je   @@done
    GetPtr ecx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_2
    mov  DWORD PTR [ecx], eax

    ;wait for ready event ?
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _READYEVENT_2
    cmp  DWORD PTR [eax], 0
    je   @F
    push 0 ;NULL
    push 0 ;FALSE
    push 1 ;WaitAnyObject
    push eax
    push 1
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_2
    call DWORD PTR [eax]

    ;close ready event
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _READYEVENT_2
    push DWORD PTR [eax]
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTCLOSE_2
    call DWORD PTR [eax]
@@:

    ;load library
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _DLLNAME_2
    push DWORD PTR [eax]
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_LOADLIBRARYW_2
    call DWORD PTR [eax]
    ;save hInstance
    GetPtr ecx, INJECTDLLINRUNNINGPROCESS_SECTION_START, _HINST_2
    mov DWORD PTR [ecx], eax

    ;set continue event
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _CONTINUEEVENT_2
    cmp  DWORD PTR [eax], 0
    je   @F
    push 0 ;NULL
    push DWORD PTR [eax] ;READY EVENT HANDLE
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTSETEVENT_2
    call DWORD PTR [eax]

    ;close continue event
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _CONTINUEEVENT_2
    push DWORD PTR [eax]
    GetPtr eax, INJECTDLLINRUNNINGPROCESS_SECTION_START, _ADDR_NTCLOSE_2
    call DWORD PTR [eax]
@@:

@@done:
    popfd
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    pop  eax
    pop  ebp
    xor  eax, eax
    ret  4h
InjectDllInRunningProcess ENDP

INJECTDLLINRUNNINGPROCESS_SECTION_END:

;---------------------------------------------------------------------------------

PUBLIC WAITFOREVENTATSTARTUP_SECTION_START
PUBLIC WAITFOREVENTATSTARTUP_SECTION_END

ALIGN 4
WAITFOREVENTATSTARTUP_SECTION_START:

ALIGN 4
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
    push ebp
    mov  ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    pushfd

    ;get ntdll.dll base address
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTDLLDLL_3
    push eax
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _GETMODBASEADDR_3
    call DWORD PTR [eax]
    test eax, eax
    je   @@done

    mov edx, eax ;save hinstance
    GetPtr ebx, WAITFOREVENTATSTARTUP_SECTION_START, _GETPROCADDR_3

    ;get address of NtClose
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTCLOSE_3
    push eax
    push edx ;hinstance
    call DWORD PTR [ebx]
    test eax, eax
    je   @@done
    GetPtr ecx, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    mov  DWORD PTR [ecx], eax

    ;get address of NtSetEvent
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTSETEVENT_3
    push eax
    push edx ;hinstance
    call DWORD PTR [ebx]
    test eax, eax
    je   @@done
    GetPtr ecx, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTSETEVENT_3
    mov  DWORD PTR [ecx], eax

    ;get address of NtWaitForMultipleObjects
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _SZ_NTWAITFORMULTIPLEOBJECTS_3
    push eax
    push edx ;hinstance
    call DWORD PTR [ebx]
    test eax, eax
    je   @@done
    GetPtr ecx, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_3
    mov  DWORD PTR [ecx], eax

    ;set ready event
    push 0 ;NULL
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _READYEVENT_3
    push DWORD PTR [eax] ;READY EVENT HANDLE
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTSETEVENT_3
    call DWORD PTR [eax]

    ;close ready event
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _READYEVENT_3
    push DWORD PTR [eax]
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    call DWORD PTR [eax]

    ;wait for continue event or controller process termination
    push 0 ;NULL
    push 0 ;FALSE
    push 1 ;WaitAnyObject
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _CONTINUEEVENT_3
    push eax
    push 2
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTWAITFORMULTIPLEOBJECTS_3
    call DWORD PTR [eax]

    ;close continue event
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _CONTINUEEVENT_3
    push DWORD PTR [eax]
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    call DWORD PTR [eax]

    ;close controller process
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _CONTROLLERPROC_3
    push DWORD PTR [eax]
    GetPtr eax, WAITFOREVENTATSTARTUP_SECTION_START, _ADDR_NTCLOSE_3
    call DWORD PTR [eax]

@@done:
    popfd
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    pop  eax
    pop  ebp
    ;jmp to original address
    db   0E9h, 0h, 0h, 0h, 0h
WaitForEventAtStartup ENDP

WAITFOREVENTATSTARTUP_SECTION_END:

;---------------------------------------------------------------------------------

_TEXT ENDS

END
