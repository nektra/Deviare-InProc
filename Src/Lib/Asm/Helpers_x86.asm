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

EXCEPTION_NONCONTINUABLE   EQU 01h
EXCEPTION_UNWINDING        EQU 02h
EXCEPTION_EXIT_UNWIND      EQU 04h
EXCEPTION_STACK_INVALID    EQU 08h
EXCEPTION_NESTED_CALL      EQU 10h
EXCEPTION_TARGET_UNWIND    EQU 20h
EXCEPTION_COLLIDED_UNWIND  EQU 40h
EXCEPTION_UNWIND           EQU 66h

CONTEXT STRUCT
    ;Control flags
    ContextFlags  DWORD ?
    ;Debug registers
    _Dr0          DWORD ?
    _Dr1          DWORD ?
    _Dr2          DWORD ?
    _Dr3          DWORD ?
    _Dr6          DWORD ?
    _Dr7          DWORD ?
    ;Float registres
    FloatSave     BYTE 112 DUP (?)
    ;Segment Registers and processor flags
    SegGs         DWORD ?
    SegFs         DWORD ?
    SegEs         DWORD ?
    SegDs         DWORD ?
    ;Integer registers
    _Edi          DWORD ?
    _Esi          DWORD ?
    _Ebx          DWORD ?
    _Edx          DWORD ?
    _Ecx          DWORD ?
    _Eax          DWORD ?
    _Ebp          DWORD ?
    _Eip          DWORD ?
    SegCs         DWORD ?
    EFlags        DWORD ?
    _Esp          DWORD ?
    SegSs         DWORD ?
    ;The rest is not used
CONTEXT ENDS

EXCEPTION_RECORD STRUCT
    ExceptionCode         DWORD ?
    ExceptionFlags        DWORD ?
    ExceptionRecord       DWORD ?
    ExceptionAddress      DWORD ?
    NumberParameters      DWORD ?
    __unusedAlignment     DWORD ?
    ExceptionInformation  DWORD 15 DUP(?)
EXCEPTION_RECORD ENDS

MYSEH STRUCT
    PrevLink        DWORD ?
    CurrentHandler  DWORD ?
    SafeOffset      DWORD ?
    PrevEsp         DWORD ?
    PrevEbp         DWORD ?
MYSEH ENDS

;---------------------------------------------------------------------------------

PUBLIC NktHookLib_TryMemCopy

NktHookLib_TryMemCopy_SEH PROTO C, :DWORD,:DWORD,:DWORD,:DWORD
.SAFESEH NktHookLib_TryMemCopy_SEH

ALIGN 4
;SIZE_T __stdcall NktHookLib_TryMemCopy(__in LPVOID lpDest, __in LPVOID lpSrc, __in SIZE_T nCount);
NktHookLib_TryMemCopy PROC STDCALL USES ebx ecx esi edi, lpDest:DWORD, lpSrc:DWORD, nCount:DWORD
    ASSUME FS:NOTHING
    push offset NktHookLib_TryMemCopy_SEH
    push fs:[0h]
    mov  fs:[0h], esp ;install SEH

    mov  ebx, DWORD PTR [ebp+10h] ;copy original count
    mov  esi, DWORD PTR [ebp+0Ch] ;source
    mov  edi, DWORD PTR [ebp+8h]  ;destination
    mov  ecx, ebx
    test edi, 7 ;destination aligned?
    jne  slowPath
    test esi, 7 ;source aligned?
    jne  slowPath
    cmp  ecx, 4
    jbe  slowPath
@@:
    mov  eax, DWORD PTR [esi]
    add  esi, 4
    mov  DWORD PTR [edi], eax
    add  edi, 4
    sub  ecx, 4
    cmp  ecx, 4
    jae  @B
slowPath:
    test ecx, ecx
    je   NktHookLib_TryMemCopy_AfterCopy
    mov  al, BYTE PTR [esi]
    inc  esi
    mov  BYTE PTR [edi], al
    inc  edi
    dec  ecx
    jmp  slowPath

NktHookLib_TryMemCopy_AfterCopy::
    pop  fs:[0h] ;uninstall SEH
    pop  eax     ;
    mov  eax, ebx
    sub  eax, ecx
    ret
NktHookLib_TryMemCopy ENDP

NktHookLib_TryMemCopy_SEH PROC C USES ecx, pExcept:DWORD, pFrame:DWORD, pContext:DWORD, pDispatch:DWORD
    mov  ecx, pContext
    lea  eax, OFFSET NktHookLib_TryMemCopy_AfterCopy
    mov  [ecx].CONTEXT._Eip, eax
    xor  eax, eax ;ExceptionContinueExecution
    ret
NktHookLib_TryMemCopy_SEH ENDP

;---------------------------------------------------------------------------------

PUBLIC NktHookLib_TryCallOneParam

NktHookLib_TryCallOneParam_SEH PROTO C, :DWORD,:DWORD,:DWORD,:DWORD
.SAFESEH NktHookLib_TryCallOneParam_SEH

ALIGN 4
;SIZE_T __stdcall NktHookLib_TryCallOneParam(__in LPVOID lpFunc, __in SIZE_T nParam1, __in BOOL bIsCDecl);
NktHookLib_TryCallOneParam PROC STDCALL lpFunc:DWORD, nParam1:DWORD, bIsCDecl:DWORD
.safeseh NktHookLib_TryCallOneParam_SEH
LOCAL seh:MYSEH

    ;install SEH
    ASSUME FS:NOTHING
    push fs:[0h]
    pop  seh.PrevLink
    mov  seh.CurrentHandler, OFFSET NktHookLib_TryCallOneParam_SEH
    mov  seh.SafeOffset, OFFSET NktHookLib_TryCallOneParam_AfterCall
    lea  eax, seh
    mov  fs:[0], eax
    mov  seh.PrevEsp, esp
    mov  seh.PrevEbp, ebp
    ;do call
    mov  eax, nParam1
    push eax
    mov  eax, lpFunc
    cmp  bIsCDecl, 0
    jne  isCDecl
    call eax
    jmp  NktHookLib_TryCallOneParam_AfterCall
isCDecl:
    call eax
    add  esp, 4h
NktHookLib_TryCallOneParam_AfterCall::
    ;uninstall SEH
    push seh.PrevLink
    pop  fs:[0]
    ret
NktHookLib_TryCallOneParam ENDP

NktHookLib_TryCallOneParam_SEH PROC C USES edx, pExcept:DWORD, pFrame:DWORD, pContext:DWORD, pDispatch:DWORD
;@@:
;jmp @B
    mov  edx, pExcept
    ASSUME EDX:ptr EXCEPTION_RECORD
    test [edx].ExceptionFlags, EXCEPTION_UNWINDING
    je   @F
    mov  eax, 1
    jmp  done
@@: mov  edx, pFrame
    ASSUME EDX:ptr MYSEH
    mov  eax, pContext
    ASSUME EAX:ptr CONTEXT
    push [edx].SafeOffset
    pop  [eax]._Eip
    push [edx].PrevEsp
    pop  [eax]._Esp
    push [edx].PrevEbp
    pop  [eax]._Ebp
    xor  eax, eax ;ExceptionContinueExecution
done:
    ret
NktHookLib_TryCallOneParam_SEH ENDP

;---------------------------------------------------------------------------------

_TEXT ENDS

END
