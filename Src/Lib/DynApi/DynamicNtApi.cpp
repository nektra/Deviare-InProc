/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved. Contact: http://www.nektra.com
 *
 *
 * This file is part of Deviare In-Proc
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial Deviare In-Proc licenses may use this
 * file in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and Nektra.  For licensing terms and
 * conditions see http://www.nektra.com/licensing/.  For further information
 * use the contact form at http://www.nektra.com/contact/.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl.html.
 *
 **/

#include "DynamicNtApi.h"
#include <intrin.h>
#include "..\..\..\Include\NktHookLib.h"

#if defined(_M_IX86)
  #pragma intrinsic (_InterlockedExchange)
#elif defined(_M_X64)
  #pragma intrinsic (_InterlockedExchangePointer)
#endif

//-----------------------------------------------------------

static LONG volatile nMutex = 0;
static HINSTANCE volatile hNtDll = NULL;
extern "C" {
  extern void* volatile NktHookLib_fn_vsnprintf;
};

#define NKT_PARSE_NTAPI_NTSTATUS(name, parameters, _notused)  \
  typedef NTSTATUS (__stdcall *lpfn_##name)parameters;        \
  lpfn_##name volatile NktHookLib_fn_##name = NULL;
#define NKT_PARSE_NTAPI_VOID(name, parameters, _notused)      \
  typedef VOID (__stdcall *lpfn_##name)parameters;            \
  lpfn_##name volatile NktHookLib_fn_##name = NULL;
#define NKT_PARSE_NTAPI_PVOID(name, parameters, _notused)     \
  typedef PVOID (__stdcall *lpfn_##name)parameters;           \
  lpfn_##name volatile NktHookLib_fn_##name = NULL;
#define NKT_PARSE_NTAPI_BOOLEAN(name, parameters, _notused)   \
  typedef BOOLEAN (__stdcall *lpfn_##name)parameters;         \
  lpfn_##name volatile NktHookLib_fn_##name = NULL;
#define NKT_PARSE_NTAPI_ULONG(name, parameters, _notused)     \
  typedef ULONG (__stdcall *lpfn_##name)parameters;           \
  lpfn_##name volatile NktHookLib_fn_##name = NULL;
extern "C"
{
#include "NtApiDeclarations.h"
};
#undef NKT_PARSE_NTAPI_NTSTATUS
#undef NKT_PARSE_NTAPI_VOID
#undef NKT_PARSE_NTAPI_PVOID
#undef NKT_PARSE_NTAPI_BOOLEAN
#undef NKT_PARSE_NTAPI_ULONG

//-----------------------------------------------------------

static VOID InitializeInternals();

#define NKT_PARSE_NTAPI_NTSTATUS(name, parameters, paramCall) \
NTSTATUS __stdcall Nkt##name parameters                       \
{                                                             \
  if (hNtDll == NULL)                                         \
    InitializeInternals();                                    \
  if (NktHookLib_fn_##name == NULL)                           \
    return STATUS_NOT_IMPLEMENTED;                            \
  return NktHookLib_fn_##name paramCall;                      \
}
#define NKT_PARSE_NTAPI_VOID(name, parameters, paramCall)     \
VOID __stdcall Nkt##name parameters                           \
{                                                             \
  if (hNtDll == NULL)                                         \
    InitializeInternals();                                    \
  if (NktHookLib_fn_##name != NULL)                           \
    NktHookLib_fn_##name paramCall;                           \
  return;                                                     \
}
#define NKT_PARSE_NTAPI_PVOID(name, parameters, paramCall)    \
PVOID __stdcall Nkt##name parameters                          \
{                                                             \
  if (hNtDll == NULL)                                         \
    InitializeInternals();                                    \
  if (NktHookLib_fn_##name == NULL)                           \
    return NULL;                                              \
  return NktHookLib_fn_##name paramCall;                      \
}
#define NKT_PARSE_NTAPI_BOOLEAN(name, parameters, paramCall)  \
BOOLEAN __stdcall Nkt##name parameters                        \
{                                                             \
  if (hNtDll == NULL)                                         \
    InitializeInternals();                                    \
  if (NktHookLib_fn_##name == NULL)                           \
    return FALSE;                                             \
  return NktHookLib_fn_##name paramCall;                      \
}
#define NKT_PARSE_NTAPI_ULONG(name, parameters, paramCall)    \
ULONG __stdcall Nkt##name parameters                          \
{                                                             \
  if (hNtDll == NULL)                                         \
    InitializeInternals();                                    \
  if (NktHookLib_fn_##name == NULL)                           \
    return 0;                                                 \
  return NktHookLib_fn_##name paramCall;                      \
}
namespace NktHookLib {
#include "NtApiDeclarations.h"
} //NktHookLib
#undef NKT_PARSE_NTAPI_NTSTATUS
#undef NKT_PARSE_NTAPI_VOID
#undef NKT_PARSE_NTAPI_PVOID
#undef NKT_PARSE_NTAPI_BOOLEAN
#undef NKT_PARSE_NTAPI_ULONG

//-----------------------------------------------------------

static VOID InitializeInternals()
{
  //because we are using NKTHOOKLIB_CurrentProcess and ScanMappedImages to FALSE, we are avoiding the recursion
  LPVOID _hNtDll = ::NktHookLib::GetRemoteModuleBaseAddress(NKTHOOKLIB_CurrentProcess, L"ntdll.dll", FALSE);
  if (_hNtDll != NULL)
  {
    #define NKT_PARSE_NTAPI_NTSTATUS(name, _notused, _notused2)                                                   \
      lpfn_##name __fn_##name = (lpfn_##name)::NktHookLib::GetRemoteProcedureAddress(NKTHOOKLIB_CurrentProcess,    \
                                                                                    _hNtDll, # name);
    #define NKT_PARSE_NTAPI_VOID NKT_PARSE_NTAPI_NTSTATUS
    #define NKT_PARSE_NTAPI_PVOID NKT_PARSE_NTAPI_NTSTATUS
    #define NKT_PARSE_NTAPI_BOOLEAN NKT_PARSE_NTAPI_NTSTATUS
    #define NKT_PARSE_NTAPI_ULONG NKT_PARSE_NTAPI_NTSTATUS
    #include "NtApiDeclarations.h"
    #undef NKT_PARSE_NTAPI_NTSTATUS
    #undef NKT_PARSE_NTAPI_VOID
    #undef NKT_PARSE_NTAPI_PVOID
    #undef NKT_PARSE_NTAPI_BOOLEAN
    #undef NKT_PARSE_NTAPI_ULONG

#if defined(_M_IX86)
    #define NKT_PARSE_NTAPI_NTSTATUS(name, _notused, _notused2)  \
      _InterlockedExchange((long volatile*)&(NktHookLib_fn_##name), (long)(__fn_##name));
#elif defined(_M_X64)
    #define NKT_PARSE_NTAPI_NTSTATUS(name, _notused, _notused2)  \
      _InterlockedExchangePointer((void* volatile*)&(NktHookLib_fn_##name), (__fn_##name));
#endif
    #define NKT_PARSE_NTAPI_VOID NKT_PARSE_NTAPI_NTSTATUS
    #define NKT_PARSE_NTAPI_PVOID NKT_PARSE_NTAPI_NTSTATUS
    #define NKT_PARSE_NTAPI_BOOLEAN NKT_PARSE_NTAPI_NTSTATUS
    #define NKT_PARSE_NTAPI_ULONG NKT_PARSE_NTAPI_NTSTATUS
    #include "NtApiDeclarations.h"
    #undef NKT_PARSE_NTAPI_NTSTATUS
    #undef NKT_PARSE_NTAPI_VOID
    #undef NKT_PARSE_NTAPI_PVOID
    #undef NKT_PARSE_NTAPI_BOOLEAN
    #undef NKT_PARSE_NTAPI_ULONG
    //----
    NktHookLib_fn_vsnprintf = ::NktHookLib::GetRemoteProcedureAddress(NKTHOOKLIB_CurrentProcess, _hNtDll, "_vsnprintf");
  }
#if defined(_M_IX86)
  _InterlockedExchange((long volatile*)&hNtDll, (long)_hNtDll);
#elif defined(_M_X64)
  _InterlockedExchangePointer((volatile PVOID*)&hNtDll, _hNtDll);
#endif
  return;
}
