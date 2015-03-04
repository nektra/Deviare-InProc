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

#include "..\..\Include\NktHookLib.h"
#include "DynamicNtApi.h"
#include <intrin.h>

#pragma intrinsic (_InterlockedIncrement)

using namespace NktHookLib;

//-----------------------------------------------------------

#define XISALIGNED(x)  ((((SIZE_T)(x)) & (sizeof(SIZE_T)-1)) == 0)

#if defined(_M_X64) || defined(_M_IA64) || defined(_M_AMD64)
  #define NKT_UNALIGNED __unaligned
#else
  #define NKT_UNALIGNED
#endif

#define SystemProcessorInformation                         1

#define ThreadBasicInformation                             0
#define ThreadBasePriority                                 3

//-----------------------------------------------------------

typedef struct {
  USHORT ProcessorArchitecture;
  USHORT ProcessorLevel;
  USHORT ProcessorRevision;
  USHORT Reserved;
  ULONG ProcessorFeatureBits;
} NKT_SYSTEM_PROCESSOR_INFORMATION;

//-----------------------------------------------------------

namespace NktHookLibHelpers {

lpfnInternalApiResolver fnInternalApiResolver = NULL;
LPVOID lpUserParam = NULL;

} //namespace NktHookLibHelpers

extern "C" {
  size_t __stdcall NktHookLib_TryMemCopy(__out const void *lpDest, __in const void *lpSrc, __in size_t nCount);
  SIZE_T __stdcall NktHookLib_TryCallOneParam(__in LPVOID lpFunc, __in SIZE_T nParam1, __in BOOL bIsCDecl);
  int NktHookLib_vsnprintf(__out_z char *lpDest, __in size_t nMaxCount, __in_z const char *szFormatA,
                           __in va_list lpArgList);
  int NktHookLib_sprintf(__out_z char *lpDest, __in_z const char *szFormatA, ...);
  extern void* volatile NktHookLib_fn_vsnwprintf;
  extern void* volatile NktHookLib_fn_DbgPrint;
};

//-----------------------------------------------------------

static DWORD CreateProcessWithDll_Common(__inout LPPROCESS_INFORMATION lpPI, __in DWORD dwCreationFlags,
                                         __in_z LPCWSTR szDllNameW);

//-----------------------------------------------------------

namespace NktHookLibHelpers {

HINSTANCE GetModuleBaseAddress(__in_z LPCWSTR szDllNameW)
{
  return (HINSTANCE)::NktHookLib::GetRemoteModuleBaseAddress(NKTHOOKLIB_CurrentProcess, szDllNameW, FALSE);
}

LPVOID GetProcedureAddress(__in HINSTANCE hDll, __in LPCSTR szProcNameA)
{
  return ::NktHookLib::GetRemoteProcedureAddress(NKTHOOKLIB_CurrentProcess, (LPVOID)hDll, szProcNameA);
}

HINSTANCE GetRemoteModuleBaseAddress(__in HANDLE hProcess, __in_z LPCWSTR szDllNameW, __in BOOL bScanMappedImages)
{
  return (HINSTANCE)::NktHookLib::GetRemoteModuleBaseAddress(hProcess, szDllNameW, bScanMappedImages);
}

LPVOID GetRemoteProcedureAddress(__in HANDLE hProcess, __in HINSTANCE hDll, __in_z LPCSTR szProcNameA)
{
  return ::NktHookLib::GetRemoteProcedureAddress(hProcess, (LPVOID)hDll, szProcNameA);
}

int sprintf_s(__out_z char *lpDest, __in size_t nMaxCount, __in_z const char *szFormatA, ...)
{
  va_list argptr;
  int ret;

  va_start(argptr, szFormatA);
  ret = vsnprintf(lpDest, nMaxCount, szFormatA, argptr);
  va_end(argptr);
  return ret;
}

int vsnprintf(__out_z char *lpDest, __in size_t nMaxCount, __in_z const char *szFormatA, __in va_list lpArgList)
{
  //NOTE: To simplify C <-> C++ jumping (because C usage of vsnprintf), we do a lightweight call to
  //      RtlNtStatusToDosError to ensure 'vsnprintf' routine was loaded.
  NktRtlNtStatusToDosError(0);
  return NktHookLib_vsnprintf(lpDest, nMaxCount, szFormatA, lpArgList);
}

int swprintf_s(__out_z wchar_t *lpDest, __in size_t nMaxCount, __in_z const wchar_t *szFormatW, ...)
{
  va_list argptr;
  int ret;

  va_start(argptr, szFormatW);
  ret = vsnwprintf(lpDest, nMaxCount, szFormatW, argptr);
  va_end(argptr);
  return ret;
}

int vsnwprintf(__out_z wchar_t *lpDest, __in size_t nMaxCount, __in_z const wchar_t *szFormatW, __in va_list lpArgList)
{
  typedef int (__cdecl *lpfn_vsnwprintf)(_Out_cap_(_MaxCount) wchar_t * _DstBuf, _In_ size_t _MaxCount,
                                         _In_z_ _Printf_format_string_ const wchar_t * _Format, va_list _ArgList);

  //NOTE: To simplify C <-> C++ jumping (because C usage of vsnprintf), we do a lightweight call to
  //      RtlNtStatusToDosError to ensure 'vsnwprintf' routine was loaded.
  NktRtlNtStatusToDosError(0);
  if (lpDest != NULL && nMaxCount > 0)
    *lpDest = 0;
  if (NktHookLib_fn_vsnwprintf == NULL)
    return 0;
  return ((lpfn_vsnwprintf)NktHookLib_fn_vsnwprintf)(lpDest, nMaxCount, szFormatW, lpArgList);
}

LONG GetProcessorArchitecture()
{
  static LONG volatile nProcessorArchitecture = -1;

  if (nProcessorArchitecture == -1)
  {
    NKT_SYSTEM_PROCESSOR_INFORMATION sProcInfo;
    NTSTATUS nNtStatus;

    nNtStatus = NktRtlGetNativeSystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo,
                                                  sizeof(sProcInfo), NULL);
    if (nNtStatus == STATUS_NOT_IMPLEMENTED)
    {
      nNtStatus = NktNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo,
                                              sizeof(sProcInfo), NULL);
    }
    if (NT_SUCCESS(nNtStatus))
      _InterlockedExchange(&nProcessorArchitecture, (LONG)(sProcInfo.ProcessorArchitecture));
  }
  return nProcessorArchitecture;
}

HANDLE OpenProcess(__in DWORD dwDesiredAccess, __in BOOL bInheritHandle, __in DWORD dwProcessId)
{
  OBJECT_ATTRIBUTES sObjAttr;
  NKT_HK_CLIENT_ID sClientId;
  HANDLE hProc;
  NTSTATUS nNtStatus;

  sClientId.UniqueProcess = (SIZE_T)(ULONG_PTR)(dwProcessId);
  sClientId.UniqueThread = 0;
  InitializeObjectAttributes(&sObjAttr, NULL, ((bInheritHandle != FALSE) ? OBJ_INHERIT : 0), NULL, NULL);
  nNtStatus = NktNtOpenProcess(&hProc, dwDesiredAccess, &sObjAttr, &sClientId);
  if (!NT_SUCCESS(nNtStatus))
    return NULL;
  return hProc;
}

HANDLE OpenThread(__in DWORD dwDesiredAccess, __in BOOL bInheritHandle, __in DWORD dwThreadId)
{
  OBJECT_ATTRIBUTES sObjAttr;
  NKT_HK_CLIENT_ID sClientId;
  HANDLE hThread;
  NTSTATUS nNtStatus;

  sClientId.UniqueProcess = 0;
  sClientId.UniqueThread = (SIZE_T)(ULONG_PTR)(dwThreadId);
  InitializeObjectAttributes(&sObjAttr, NULL, ((bInheritHandle != FALSE) ? OBJ_INHERIT : 0), NULL, NULL);
  nNtStatus = NktNtOpenThread(&hThread, dwDesiredAccess, &sObjAttr, &sClientId);
  if (!NT_SUCCESS(nNtStatus))
    return NULL;
  return hThread;
}

NTSTATUS GetProcessPlatform(__in HANDLE hProcess)
{
  if (hProcess == NKTHOOKLIB_CurrentProcess)
  {
#if defined(_M_IX86)
    return NKTHOOKLIB_ProcessPlatformX86;
#elif defined(_M_X64)
    return NKTHOOKLIB_ProcessPlatformX64;
#endif
  }
  switch (GetProcessorArchitecture())
  {
    case PROCESSOR_ARCHITECTURE_INTEL:
      return NKTHOOKLIB_ProcessPlatformX86;

    case PROCESSOR_ARCHITECTURE_AMD64:
      //check on 64-bit platforms
      ULONG_PTR nWow64;
      NTSTATUS nNtStatus;

      nNtStatus = NktNtQueryInformationProcess(hProcess, ProcessWow64Information, &nWow64, sizeof(nWow64), NULL);
      if (NT_SUCCESS(nNtStatus))
      {
#if defined(_M_IX86)
        return (nWow64 == 0) ? NKTHOOKLIB_ProcessPlatformX64 : NKTHOOKLIB_ProcessPlatformX86;
#elif defined(_M_X64)
        return (nWow64 != 0) ? NKTHOOKLIB_ProcessPlatformX86 : NKTHOOKLIB_ProcessPlatformX64;
#endif
      }
#if defined(_M_IX86)
      return NKTHOOKLIB_ProcessPlatformX86;
#elif defined(_M_X64)
      return NKTHOOKLIB_ProcessPlatformX64;
#endif
      break;
    //case PROCESSOR_ARCHITECTURE_IA64:
    //case PROCESSOR_ARCHITECTURE_ALPHA64:
  }
  return STATUS_NOT_SUPPORTED;
}

SIZE_T ReadMem(__in HANDLE hProcess, __in LPVOID lpDest, __in LPVOID lpSrc, __in SIZE_T nBytesCount)
{
  NTSTATUS nStatus;
  SIZE_T nReaded;

  if (nBytesCount == 0)
    return 0;
  if (hProcess == NKTHOOKLIB_CurrentProcess)
    return TryMemCopy(lpDest, lpSrc, nBytesCount);
  nStatus = NktNtReadVirtualMemory(hProcess, lpSrc, lpDest, nBytesCount, &nReaded);
  if (nStatus == STATUS_PARTIAL_COPY)
    return nReaded;
  return (NT_SUCCESS(nStatus)) ? nBytesCount : 0;
}

BOOL WriteMem(__in HANDLE hProcess, __in LPVOID lpDest, __in LPVOID lpSrc, __in SIZE_T nBytesCount)
{
  NTSTATUS nStatus;
  SIZE_T nWritten;

  if (nBytesCount == 0)
    return TRUE;
  if (hProcess == NKTHOOKLIB_CurrentProcess)
    return (TryMemCopy(lpDest, lpSrc, nBytesCount) == nBytesCount) ? TRUE : FALSE;
  nStatus = NktNtWriteVirtualMemory(hProcess, lpDest, lpSrc, nBytesCount, &nWritten);
  return (NT_SUCCESS(nStatus) ||
          (nStatus == STATUS_PARTIAL_COPY && nWritten == nBytesCount)) ? TRUE : FALSE;
}

NTSTATUS GetThreadPriority(__in HANDLE hThread, __out int *lpnPriority)
{
  NKT_HK_THREAD_BASIC_INFORMATION sTbi;
  NTSTATUS nNtStatus;

  nNtStatus = NktNtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadBasicInformation, &sTbi, sizeof(sTbi), NULL);
  if (NT_SUCCESS(nNtStatus))
  {
    if (sTbi.BasePriority == THREAD_BASE_PRIORITY_LOWRT+1)
      *lpnPriority = (int)THREAD_PRIORITY_TIME_CRITICAL;
    else if (sTbi.BasePriority == THREAD_BASE_PRIORITY_IDLE-1)
      *lpnPriority = (int)THREAD_PRIORITY_IDLE;
    else
      *lpnPriority = (int)(sTbi.BasePriority);
  }
  return nNtStatus;
}

NTSTATUS SetThreadPriority(__in HANDLE hThread, __in int _nPriority)
{
  LONG nPriority = _nPriority;
 
  if (nPriority == THREAD_PRIORITY_TIME_CRITICAL)
    nPriority = THREAD_BASE_PRIORITY_LOWRT + 1;
  else if (nPriority == THREAD_PRIORITY_IDLE)
    nPriority = THREAD_BASE_PRIORITY_IDLE - 1;
  return NktNtSetInformationThread(hThread, (THREADINFOCLASS)ThreadBasePriority, &nPriority, sizeof(nPriority));
}

DWORD GetCurrentThreadId()
{
  LPBYTE lpPtr;
  DWORD dw;

#if defined(_M_IX86)
  lpPtr = (LPBYTE)__readfsdword(0x18); //get TEB
  dw = *((DWORD*)(lpPtr+0x24));        //TEB.ClientId.UniqueThread
#elif defined(_M_X64)
  lpPtr = (LPBYTE)__readgsqword(0x30); //get TEB
  dw = *((DWORD*)(lpPtr+0x48));        //TEB.ClientId.UniqueThread
#endif
  return dw;
}

DWORD GetCurrentProcessId()
{
  LPBYTE lpPtr;
  DWORD dw;

#if defined(_M_IX86)
  lpPtr = (LPBYTE)__readfsdword(0x18);     //get TEB
  dw = (DWORD)*((ULONGLONG*)(lpPtr+0x20)); //TEB.ClientId.UniqueProcess
#elif defined(_M_X64)
  lpPtr = (LPBYTE)__readgsqword(0x30);     //get TEB
  dw = (DWORD)*((ULONGLONG*)(lpPtr+0x40)); //TEB.ClientId.UniqueProcess
#endif
  return dw;
}

HANDLE GetProcessHeap()
{
  LPBYTE lpPtr;
  HANDLE h;

#if defined(_M_IX86)
  lpPtr = (LPBYTE)__readfsdword(0x18); //get TEB
  lpPtr = *((LPBYTE*)(lpPtr+0x30));    //TEB.Peb
  h = *((HANDLE*)(lpPtr+0x18));        //PEB.ProcessHeap
#elif defined(_M_X64)
  lpPtr = (LPBYTE)__readgsqword(0x30); //get TEB
  lpPtr = *((LPBYTE*)(lpPtr+0x60));    //TEB.Peb
  h = *((HANDLE*)(lpPtr+0x30));        //PEB.ProcessHeap
#endif
  return h;
}

LPVOID MemAlloc(__in SIZE_T nSize)
{
  if (nSize == 0)
    nSize = 1;
  return NktRtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, nSize);
}

VOID MemFree(__in LPVOID lpPtr)
{
  if (lpPtr != NULL)
    NktRtlFreeHeap(GetProcessHeap(), 0, lpPtr);
  return;
}

VOID MemSet(__out void *lpDest, __in int nVal, __in SIZE_T nCount)
{
  LPBYTE d;
  SIZE_T n;

  d = (LPBYTE)lpDest;
  nVal &= 0xFF;
  if (XISALIGNED(d))
  {
    n = ((SIZE_T)nVal) | (((SIZE_T)nVal) << 8);
    n = n | (n << 16);
#if defined(_M_X64) || defined(_M_IA64) || defined(_M_AMD64)
    n = n | (n << 32);
#endif //_M_X64 || _M_IA64 || _M_AMD64
    while (nCount >= sizeof(SIZE_T))
    {
      *((SIZE_T*)d) = n;
      d += sizeof(SIZE_T);
      nCount -= sizeof(SIZE_T);
    }
  }
  //the following code is not fully optimized but avoid VC compiler to insert undesired "_memset" calls
  if (nCount > 0)
  {
    do
    {
      *d = (BYTE)nVal;
    }
    while (--nCount > 0);
  }
  return;
}

VOID MemCopy(__out void *lpDest, __in const void *lpSrc, __in SIZE_T nCount)
{
  LPBYTE s, d;

  s = (LPBYTE)lpSrc;
  d = (LPBYTE)lpDest;
  if (XISALIGNED(s) && XISALIGNED(d))
  {
    while (nCount >= sizeof(SIZE_T))
    {
      *((SIZE_T*)d) = *((SIZE_T*)s);
      s += sizeof(SIZE_T);
      d += sizeof(SIZE_T);
      nCount -= sizeof(SIZE_T);
    }
  }
  while (nCount > 0)
  {
    *d++ = *s++;
    nCount--;
  }
  return;
}

VOID MemMove(__out void *lpDest, __in const void *lpSrc, __in SIZE_T nCount)
{
  LPBYTE s, d;

  s = (LPBYTE)lpSrc;
  d = (LPBYTE)lpDest;
  if (d <= s || d >= (s+nCount))
  {
    //dest is before source or non-overlapping buffers
    //copy from lower to higher addresses
    if (d+sizeof(SIZE_T) <= s && XISALIGNED(s) && XISALIGNED(d))
    {
      while (nCount >= sizeof(SIZE_T))
      {
        *((SIZE_T*)d) = *((SIZE_T*)s);
        s += sizeof(SIZE_T);
        d += sizeof(SIZE_T);
        nCount -= sizeof(SIZE_T);
      }
    }
    while ((nCount--) > 0)
      *d++ = *s++;
  }
  else
  {
    //dest is past source or overlapping buffers
    //copy from higher to lower addresses
    if (nCount >= sizeof(SIZE_T) && XISALIGNED(s) && XISALIGNED(d))
    {
      s += nCount;
      d += nCount;
      while (nCount>0 && (!XISALIGNED(nCount))) {
        --s;
        --d;
        *d = *s;
        nCount--;
      }
      while (nCount > 0)
      {
        s -= sizeof(SIZE_T);
        d -= sizeof(SIZE_T);
        *((SIZE_T*)d) = *((SIZE_T*)s);
        nCount -= sizeof(SIZE_T);
      }
    }
    else
    {
      s += nCount;
      d += nCount;
      while (nCount > 0)
      {
        --s;
        --d;
        *d = *s;
        nCount--;
      }
    }
  }
  return;
}

SIZE_T TryMemCopy(__out void *lpDest, __in const void *lpSrc, __in SIZE_T nCount)
{
  return NktHookLib_TryMemCopy(lpDest, lpSrc, nCount);
}

int MemCompare(__in const void *lpBuf1, __in const void *lpBuf2, __in SIZE_T nCount)
{
  LPBYTE b1, b2;

  if (nCount == 0)
    return 0;
  b1 = (LPBYTE)lpBuf1;
  b2 = (LPBYTE)lpBuf2;
  while ((--nCount) > 0 && b1[0] == b2[0])
  {
    b1++;
    b2++;
  }
  return (int)(b1[0] - b2[0]);
}

VOID DebugPrint(__in LPCSTR szFormatA, ...)
{
  va_list argptr;

  va_start(argptr, szFormatA);
  DebugVPrint(szFormatA, argptr);
  va_end(argptr);
  return;
}

VOID DebugVPrint(__in LPCSTR szFormatA, __in va_list argptr)
{
  typedef int (__cdecl *lpfnDbgPrint)(char *Format, ...);
  CHAR szTempA[2048];
  EXCEPTION_RECORD sExcRec;
  SIZE_T i;

  i = (SIZE_T)vsnprintf(szTempA, 2047, szFormatA, argptr);
  szTempA[2047] = 0;
  if (i > 2047)
    i = 2047;
  if (NktHookLib_fn_DbgPrint != NULL)
  {
    ((lpfnDbgPrint)NktHookLib_fn_DbgPrint)("%s", szTempA);
  }
  else
  {
    MemSet(&sExcRec, 0, sizeof(sExcRec));
    sExcRec.ExceptionCode = DBG_PRINTEXCEPTION_C;
    sExcRec.NumberParameters = 2;
    sExcRec.ExceptionInformation[0] = (ULONG_PTR)(i+1); //include end of string
    sExcRec.ExceptionInformation[1] = (ULONG_PTR)szTempA;
    sExcRec.ExceptionAddress = (PVOID)NktRtlRaiseException;
    //avoid compiler stuff for try/except blocks
    NktHookLib_TryCallOneParam(NktRtlRaiseException, (SIZE_T)&sExcRec, FALSE);
  }
  return;
}

VOID SetInternalApiResolverCallback(__in lpfnInternalApiResolver _fnInternalApiResolver, __in LPVOID _lpUserParam)
{
  fnInternalApiResolver = _fnInternalApiResolver;
  lpUserParam = _lpUserParam;
  return;
}

DWORD GetWin32LastError(__in_opt HANDLE hThread)
{
  NKT_HK_THREAD_BASIC_INFORMATION sTbi;
  LPBYTE lpPtr;
  NTSTATUS nNtStatus;
  DWORD dwErr, dwProcId;
  HANDLE hProc;

  if (hThread == NULL || hThread == NKTHOOKLIB_CurrentThread)
  {
#if defined(_M_IX86)
    lpPtr = (LPBYTE)__readfsdword(0x18); //get TEB
    dwErr = *((DWORD*)(lpPtr+0x34));        //TEB.LastErrorValue
#elif defined(_M_X64)
    lpPtr = (LPBYTE)__readgsqword(0x30); //get TEB
    dwErr = *((DWORD*)(lpPtr+0x68));        //TEB.LastErrorValue
#endif
  }
  else
  {
    nNtStatus = NktNtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadBasicInformation, &sTbi, sizeof(sTbi),
                                            NULL);
    if (!NT_SUCCESS(nNtStatus))
      return 0xFFFFFFFFUL;
    dwProcId = (DWORD)(sTbi.ClientId.UniqueProcess);
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ, FALSE, dwProcId);
    if (hProc == NULL)
      hProc = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwProcId);
    if (hProc == NULL)
      return 0xFFFFFFFFUL;
    switch (GetProcessPlatform(hProc))
    {
      case NKTHOOKLIB_ProcessPlatformX86:
        if (ReadMem(hProc, &dwErr, (LPBYTE)sTbi.TebBaseAddress + 0x34, sizeof(DWORD)) != sizeof(DWORD))
          dwErr = 0xFFFFFFFFUL;
        break;
#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        if (ReadMem(hProc, &dwErr, (LPBYTE)sTbi.TebBaseAddress + 0x68, sizeof(DWORD)) != sizeof(DWORD))
          dwErr = 0xFFFFFFFFUL;
        break;
#endif //_M_X64
      default:
        dwErr = 0xFFFFFFFFUL;
        break;
    }
    NktNtClose(hProc);
  }
  return dwErr;
}

DWORD CreateProcessWithDllW(__in_z_opt LPCWSTR lpApplicationName, __inout_z_opt LPWSTR lpCommandLine,
                            __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
                            __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
                            __in DWORD dwCreationFlags, __in_z_opt LPCWSTR lpEnvironment,
                            __in_z_opt LPCWSTR lpCurrentDirectory, __in LPSTARTUPINFOW lpStartupInfo,
                            __out LPPROCESS_INFORMATION lpProcessInformation, __in_z LPCWSTR szDllNameW)
{
  typedef BOOL (WINAPI *lpfnCreateProcessW)(__in_z_opt LPCWSTR lpApplicationName, __inout_z_opt LPWSTR lpCommandLine,
                                            __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                            __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                            __in BOOL bInheritHandles, __in DWORD dwCreationFlags,
                                            __in_opt LPVOID lpEnvironment, __in_z_opt LPCWSTR lpCurrentDirectory,
                                            __in LPSTARTUPINFOW lpStartupInfo,
                                            __out LPPROCESS_INFORMATION lpProcessInformation);
  HINSTANCE hKernel32Dll;
  lpfnCreateProcessW fnCreateProcessW;

  //check parameters
  if (szDllNameW == NULL || szDllNameW[0] == 0)
    return ERROR_INVALID_PARAMETER;
  //get needed api from kernel32
  hKernel32Dll = GetModuleBaseAddress(L"kernel32.dll");
  if (hKernel32Dll == NULL)
    return ERROR_PROC_NOT_FOUND;
  fnCreateProcessW = (lpfnCreateProcessW)GetProcedureAddress(hKernel32Dll, "CreateProcessW");
  if (fnCreateProcessW == NULL)
    return ERROR_PROC_NOT_FOUND;
  //create process
  if (lpApplicationName != NULL && lpApplicationName[0] == 0)
    lpApplicationName = NULL;
  if (lpCommandLine != NULL && lpCommandLine[0] == 0 && lpApplicationName == NULL)
    lpCommandLine = NULL;
  if (lpEnvironment != NULL)
  {
    if (lpEnvironment[0] != 0)
      dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    else
      lpEnvironment = NULL;
  }
  if (lpCurrentDirectory != NULL && lpCurrentDirectory[0] == 0)
    lpCurrentDirectory = NULL;
  if (fnCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
                       dwCreationFlags|CREATE_SUSPENDED, (LPVOID)lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                       lpProcessInformation) == FALSE)
    return GetWin32LastError();
  //inject dll load at entrypoint
  return CreateProcessWithDll_Common(lpProcessInformation, dwCreationFlags, szDllNameW);
}

DWORD CreateProcessWithLogonAndDllW(__in_z LPCWSTR lpUsername, __in_z_opt LPCWSTR lpDomain, __in_z LPCWSTR lpPassword,
                                    __in DWORD dwLogonFlags, __in_opt LPCWSTR lpApplicationName,
                                    __inout_opt LPWSTR lpCommandLine, __in DWORD dwCreationFlags,
                                    __in_z_opt LPCWSTR lpEnvironment, __in_z_opt LPCWSTR lpCurrentDirectory,
                                    __in LPSTARTUPINFOW lpStartupInfo,
                                    __out LPPROCESS_INFORMATION lpProcessInformation, __in_z LPCWSTR szDllNameW)
{
  typedef HMODULE (WINAPI *lpfnLoadLibraryW)(__in_z LPCWSTR lpFileNameW);
  typedef HMODULE (WINAPI *lpfnFreeLibrary)(__in HMODULE hLibModule);
  typedef BOOL (WINAPI *lpfnCreateProcessWithLogonW)(__in_z LPCWSTR lpUsername, __in_z_opt LPCWSTR lpDomain,
                                         __in_z LPCWSTR lpPassword, __in DWORD dwLogonFlags,
                                         __in_opt LPCWSTR lpApplicationName, __inout_opt LPWSTR lpCommandLine,
                                         __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment,
                                         __in_z_opt LPCWSTR lpCurrentDirectory, __in LPSTARTUPINFOW lpStartupInfo,
                                         __out LPPROCESS_INFORMATION lpProcessInformation);
  HINSTANCE hKernel32Dll, hAdvApi32Dll;
  lpfnLoadLibraryW fnLoadLibraryW;
  lpfnFreeLibrary fnFreeLibrary;
  lpfnCreateProcessWithLogonW fnCreateProcessWithLogonW;
  LPCWSTR sW;
  DWORD dwOsErr;

  if (szDllNameW == NULL || szDllNameW[0] == 0)
    return ERROR_INVALID_PARAMETER;
  //get needed api from kernel32
  hKernel32Dll = GetModuleBaseAddress(L"kernel32.dll");
  if (hKernel32Dll == NULL)
    return ERROR_PROC_NOT_FOUND;
  fnLoadLibraryW = (lpfnLoadLibraryW)GetProcedureAddress(hKernel32Dll, "LoadLibraryW");
  fnFreeLibrary = (lpfnFreeLibrary)GetProcedureAddress(hKernel32Dll, "FreeLibrary");
  if (fnLoadLibraryW == NULL || fnFreeLibrary == NULL)
    return ERROR_PROC_NOT_FOUND;
  //load advapi32.dll
  hAdvApi32Dll = fnLoadLibraryW(L"advapi32.dll");
  if (hAdvApi32Dll == NULL)
    return ERROR_PROC_NOT_FOUND;
  fnCreateProcessWithLogonW = (lpfnCreateProcessWithLogonW)GetProcedureAddress(hAdvApi32Dll, "CreateProcessWithLogonW");
  if (fnCreateProcessWithLogonW == NULL)
  {
    fnFreeLibrary(hAdvApi32Dll);
    return ERROR_PROC_NOT_FOUND;
  }
  //create process
  if (lpUsername == NULL)
    lpUsername = L"";
  if (lpDomain == NULL)
  {
    for (sW=lpUsername; *sW != 0 && *sW != L'@'; sW++);
    if (*sW == 0)
      lpDomain = L"";
  }
  if (lpPassword == NULL)
    lpPassword = L"";
  if (lpApplicationName != NULL && lpApplicationName[0] == 0)
    lpApplicationName = NULL;
  if (lpCommandLine != NULL && lpCommandLine[0] == 0 && lpApplicationName == NULL)
    lpCommandLine = NULL;
  if (lpEnvironment != NULL)
  {
    if (lpEnvironment[0] != 0)
      dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    else
      lpEnvironment = NULL;
  }
  if (lpCurrentDirectory != NULL && lpCurrentDirectory[0] == 0)
    lpCurrentDirectory = NULL;
  if (fnCreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine,
                                dwCreationFlags|CREATE_SUSPENDED, (LPVOID)lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                                lpProcessInformation) == FALSE)
  {
    dwOsErr = GetWin32LastError();
    fnFreeLibrary(hAdvApi32Dll);
    return dwOsErr;
  }
  fnFreeLibrary(hAdvApi32Dll);
  //inject dll load at entrypoint
  return CreateProcessWithDll_Common(lpProcessInformation, dwCreationFlags, szDllNameW);
}

DWORD CreateProcessWithTokenAndDllW(__in HANDLE hToken, __in DWORD dwLogonFlags, __in_z_opt LPCWSTR lpApplicationName,
                                    __inout_opt LPWSTR lpCommandLine, __in DWORD dwCreationFlags,
                                    __in_z_opt LPCWSTR lpEnvironment, __in_z_opt LPCWSTR lpCurrentDirectory,
                                    __in LPSTARTUPINFOW lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation,
                                    __in_z LPCWSTR szDllNameW)
{
  typedef HMODULE (WINAPI *lpfnLoadLibraryW)(__in_z LPCWSTR lpFileNameW);
  typedef HMODULE (WINAPI *lpfnFreeLibrary)(__in HMODULE hLibModule);
  typedef BOOL (WINAPI *lpfnCreateProcessWithTokenW)(__in HANDLE hToken, __in DWORD dwLogonFlags,
                                         __in_z_opt LPCWSTR lpApplicationName, __inout_opt LPWSTR lpCommandLine,
                                         __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment,
                                         __in_z_opt LPCWSTR lpCurrentDirectory, __in LPSTARTUPINFOW lpStartupInfo,
                                         __out LPPROCESS_INFORMATION lpProcessInformation);
  HINSTANCE hKernel32Dll, hAdvApi32Dll;
  lpfnLoadLibraryW fnLoadLibraryW;
  lpfnFreeLibrary fnFreeLibrary;
  lpfnCreateProcessWithTokenW fnCreateProcessWithTokenW;
  DWORD dwOsErr;

  if (szDllNameW == NULL || szDllNameW[0] == 0)
    return ERROR_INVALID_PARAMETER;
  //get needed api from kernel32
  hKernel32Dll = GetModuleBaseAddress(L"kernel32.dll");
  if (hKernel32Dll == NULL)
    return ERROR_PROC_NOT_FOUND;
  fnLoadLibraryW = (lpfnLoadLibraryW)GetProcedureAddress(hKernel32Dll, "LoadLibraryW");
  fnFreeLibrary = (lpfnFreeLibrary)GetProcedureAddress(hKernel32Dll, "FreeLibrary");
  if (fnLoadLibraryW == NULL || fnFreeLibrary == NULL)
    return ERROR_PROC_NOT_FOUND;
  //load advapi32.dll
  hAdvApi32Dll = fnLoadLibraryW(L"advapi32.dll");
  if (hAdvApi32Dll == NULL)
    return ERROR_PROC_NOT_FOUND;
  fnCreateProcessWithTokenW = (lpfnCreateProcessWithTokenW)GetProcedureAddress(hAdvApi32Dll, "CreateProcessWithTokenW");
  if (fnCreateProcessWithTokenW == NULL)
  {
    fnFreeLibrary(hAdvApi32Dll);
    return ERROR_PROC_NOT_FOUND;
  }
  //create process
  if (lpApplicationName != NULL && lpApplicationName[0] == 0)
    lpApplicationName = NULL;
  if (lpCommandLine != NULL && lpCommandLine[0] == 0 && lpApplicationName == NULL)
    lpCommandLine = NULL;
  if (lpEnvironment != NULL)
  {
    if (lpEnvironment[0] != 0)
      dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    else
      lpEnvironment = NULL;
  }
  if (lpCurrentDirectory != NULL && lpCurrentDirectory[0] == 0)
    lpCurrentDirectory = NULL;
  if (fnCreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine,
                                dwCreationFlags|CREATE_SUSPENDED, (LPVOID)lpEnvironment, lpCurrentDirectory,
                                lpStartupInfo, lpProcessInformation) == FALSE)
  {
    dwOsErr = GetWin32LastError();
    fnFreeLibrary(hAdvApi32Dll);
    return dwOsErr;
  }
  fnFreeLibrary(hAdvApi32Dll);
  //inject dll load at entrypoint
  return CreateProcessWithDll_Common(lpProcessInformation, dwCreationFlags, szDllNameW);
}

} //namespace NktHookLibHelpers

//-----------------------------------------------------------

static DWORD CreateProcessWithDll_Common(__inout LPPROCESS_INFORMATION lpPI, __in DWORD dwCreationFlags,
                                         __in_z LPCWSTR szDllNameW)
{
  typedef NTSTATUS (NTAPI *lpfnNtGetContextThread)(__in HANDLE hThread, __inout PCONTEXT lpContext);
  typedef NTSTATUS (NTAPI *lpfnNtSetContextThread)(__in HANDLE hThread, __in CONST PCONTEXT lpContext);
#if defined(_M_X64)
  typedef NTSTATUS (NTAPI *lpfnRtlWow64GetThreadContext)(__in HANDLE hThread, __inout PWOW64_CONTEXT lpContext);
  typedef NTSTATUS (NTAPI *lpfnRtlWow64SetThreadContext)(__in HANDLE hThread, __in CONST PWOW64_CONTEXT lpContext);
#endif //_M_X64
  DWORD dwOsErr;
  HINSTANCE hNtDll, hRemNtDll;
  LPVOID fnRemLdrLoadDll;
  lpfnNtGetContextThread fnNtGetContextThread;
  lpfnNtSetContextThread fnNtSetContextThread;
#if defined(_M_X64)
  lpfnRtlWow64GetThreadContext fnRtlWow64GetThreadContext;
  lpfnRtlWow64SetThreadContext fnRtlWow64SetThreadContext;
#endif //_M_X64
  BYTE aLocalCode[1024], *lpRemCode;
  LONG nProcPlatform;
  SIZE_T nSize, nDllLen;
  CONTEXT sCtx;
#if defined(_M_X64)
  WOW64_CONTEXT sWow64Ctx, *lpWow64Ctx = NULL;
#endif //_M_X64

  hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
  hRemNtDll = NktHookLibHelpers::GetRemoteModuleBaseAddress(lpPI->hProcess, L"ntdll.dll", TRUE);
  if (hNtDll == NULL || hRemNtDll != NULL)
  {
    fnRemLdrLoadDll = NktHookLibHelpers::GetRemoteProcedureAddress(lpPI->hProcess, hRemNtDll, "LdrLoadDll");
    fnNtGetContextThread = (lpfnNtGetContextThread)NktHookLibHelpers::GetProcedureAddress(hNtDll, "NtGetContextThread");
    fnNtSetContextThread = (lpfnNtSetContextThread)NktHookLibHelpers::GetProcedureAddress(hNtDll, "NtSetContextThread");
#if defined(_M_X64)
    fnRtlWow64GetThreadContext = (lpfnRtlWow64GetThreadContext)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                     "RtlWow64GetThreadContext");
    fnRtlWow64SetThreadContext = (lpfnRtlWow64SetThreadContext)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                     "RtlWow64SetThreadContext");
#endif //_M_X64
    dwOsErr = (fnRemLdrLoadDll != NULL && fnNtGetContextThread != NULL &&
               fnNtSetContextThread != NULL) ? ERROR_SUCCESS : ERROR_PROC_NOT_FOUND;
  }
  else
  {
    dwOsErr = ERROR_PROC_NOT_FOUND;
  }
  //allocate memory in remote process
  if (dwOsErr == ERROR_SUCCESS)
  {
    //calculate dll name length
    for (nDllLen=0; nDllLen<16384 && szDllNameW[nDllLen]!=0; nDllLen++);
    nDllLen *= sizeof(WCHAR);
    if (nDllLen >= 32768)
      return E_INVALIDARG;
    nSize = 48 + 256 + nDllLen;
    nSize = ((nSize + 4095) & (~4095));
    lpRemCode = NULL;
    if (!NT_SUCCESS(NktNtAllocateVirtualMemory(lpPI->hProcess, (PVOID*)&lpRemCode, 0, &nSize, MEM_COMMIT,
                                               PAGE_EXECUTE_READWRITE)))
      dwOsErr = ERROR_ACCESS_DENIED;
  }
  //check process platform and retrieve main thread's entrypoint
  if (dwOsErr == ERROR_SUCCESS)
  {
    switch (nProcPlatform = NktHookLibHelpers::GetProcessPlatform(lpPI->hProcess))
    {
      case NKTHOOKLIB_ProcessPlatformX86:
#if defined(_M_IX86)
        sCtx.ContextFlags = CONTEXT_FULL;
        if (!NT_SUCCESS(fnNtGetContextThread(lpPI->hThread, &sCtx)))
          dwOsErr = ERROR_ACCESS_DENIED;

#elif defined(_M_X64)
        if (fnRtlWow64GetThreadContext != NULL && fnRtlWow64SetThreadContext != NULL)
        {
          sWow64Ctx.ContextFlags = CONTEXT_FULL;
          if (!NT_SUCCESS(fnRtlWow64GetThreadContext(lpPI->hThread, &sWow64Ctx)))
            dwOsErr = ERROR_ACCESS_DENIED;
        }
        else
        {
          //try to locate the pointer to the WOW64_CONTEXT data by reading the thread's TLS slot 1
          NKT_HK_THREAD_BASIC_INFORMATION sTbi;
          LPBYTE lpTlsSlot;

          if (NT_SUCCESS(NktNtQueryInformationThread(lpPI->hThread, (THREADINFOCLASS)ThreadBasicInformation, &sTbi,
                                                     sizeof(sTbi), NULL)))
          {
            lpTlsSlot = (LPBYTE)(sTbi.TebBaseAddress) + 0x0E10 + 1*sizeof(DWORD);
            if (NktHookLibHelpers::ReadMem(lpPI->hProcess, &lpWow64Ctx, lpTlsSlot,
                                           sizeof(lpWow64Ctx)) != sizeof(lpWow64Ctx) ||
                NktHookLibHelpers::ReadMem(lpPI->hProcess, &sWow64Ctx, lpWow64Ctx,
                                           sizeof(sWow64Ctx)) != sizeof(sWow64Ctx))
            {
              dwOsErr = ERROR_ACCESS_DENIED;
            }
          }
          else
          {
            dwOsErr = ERROR_ACCESS_DENIED;
          }
        }
#endif
        break;

#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        sCtx.ContextFlags = CONTEXT_FULL;
        if (!NT_SUCCESS(fnNtGetContextThread(lpPI->hThread, &sCtx)))
          dwOsErr = ERROR_ACCESS_DENIED;
        break;
#endif //_M_X64

      default:
        dwOsErr = ERROR_UNSUPPORTED_TYPE;
        break;
    }
  }
  //build code
  if (dwOsErr == ERROR_SUCCESS)
  {
    NktHookLibHelpers::MemSet(aLocalCode, 0, sizeof(aLocalCode));
    //search path (lpRemCode + 16)
    aLocalCode[16] = '.';
    //dll characteristics (lpRemCode + 24)
    //dll to load UNICODE_STRING (lpRemCode + 32 / buffer pointer will be stored later)
    *((USHORT NKT_UNALIGNED*)(aLocalCode+32)) = (USHORT)nDllLen;
    *((USHORT NKT_UNALIGNED*)(aLocalCode+34)) = (USHORT)nDllLen;
    nSize = 48; //offset to code start
    //remote code starts at offset 48
    switch (nProcPlatform)
    {
      case NKTHOOKLIB_ProcessPlatformX86:
        aLocalCode[nSize++] = 0x55;                                       //push    ebp
        aLocalCode[nSize++] = 0x8B; aLocalCode[nSize++] = 0xEC;           //mov     ebp, esp
        aLocalCode[nSize++] = 0x50;                                       //push    eax
        aLocalCode[nSize++] = 0x53;                                       //push    ebx
        aLocalCode[nSize++] = 0x51;                                       //push    ecx
        aLocalCode[nSize++] = 0x52;                                       //push    edx
        aLocalCode[nSize++] = 0x56;                                       //push    esi
        aLocalCode[nSize++] = 0x57;                                       //push    edi
        aLocalCode[nSize++] = 0x9C;                                       //pushf
        //----
        aLocalCode[nSize++] = 0xB8;                                       //mov     eax, lpRemCode (hInst*)
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = (DWORD)lpRemCode;
        nSize += 4;
        aLocalCode[nSize++] = 0x50;                                       //push    eax
        //----
        aLocalCode[nSize++] = 0xB8;                                       //mov     eax, lpRemCode+32 (DllName)
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = (DWORD)lpRemCode + 32;
        nSize += 4;
        aLocalCode[nSize++] = 0x50;                                       //push    eax
        //----
        aLocalCode[nSize++] = 0xB8;                                       //mov     eax, lpRemCode+24 (DllCharact)
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = (DWORD)lpRemCode + 24;
        nSize += 4;
        aLocalCode[nSize++] = 0x50;                                       //push    eax
        //----
        aLocalCode[nSize++] = 0xB8;                                       //mov     eax, lpRemCode+16 (SearchPath)
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = (DWORD)lpRemCode + 16;
        nSize += 4;
        aLocalCode[nSize++] = 0x50;                                       //push    eax
        //----
        aLocalCode[nSize++] = 0xB8;                                       //mov     eax, ADDRESS OF LdrLoadDll
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = (DWORD)fnRemLdrLoadDll;
        nSize += 4;
        aLocalCode[nSize++] = 0xFF; aLocalCode[nSize++] = 0xD0;           //call    eax
        //----
        aLocalCode[nSize++] = 0x9D;                                       //popf
        aLocalCode[nSize++] = 0x5F;                                       //pop     edi
        aLocalCode[nSize++] = 0x5E;                                       //pop     esi
        aLocalCode[nSize++] = 0x5A;                                       //pop     edx
        aLocalCode[nSize++] = 0x59;                                       //pop     ecx
        aLocalCode[nSize++] = 0x5B;                                       //pop     ebx
        aLocalCode[nSize++] = 0x58;                                       //pop     eax
        aLocalCode[nSize++] = 0x5D;                                       //pop     ebp
        aLocalCode[nSize++] = 0xE9;                                       //jmp     original entrypoint
#if defined(_M_IX86)
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = (DWORD)(sCtx.Eax) - (DWORD)(lpRemCode+nSize+4);
#elif defined(_M_X64)
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = (DWORD)(sWow64Ctx.Eax) - (DWORD)(lpRemCode+nSize+4);
#endif
        nSize += 4;
        break;

#if defined _M_X64
      case NKTHOOKLIB_ProcessPlatformX64:
        aLocalCode[nSize++] = 0x50;                                       //push    rax
        aLocalCode[nSize++] = 0x53;                                       //push    rbx
        aLocalCode[nSize++] = 0x51;                                       //push    rcx
        aLocalCode[nSize++] = 0x52;                                       //push    rdx
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x50;           //push    r8
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x51;           //push    r9
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x52;           //push    r10
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x53;           //push    r11
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x54;           //push    r12
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x55;           //push    r13
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x56;           //push    r14
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x57;           //push    r15
        aLocalCode[nSize++] = 0x56;                                       //push    rsi
        aLocalCode[nSize++] = 0x57;                                       //push    rdi
        aLocalCode[nSize++] = 0x9C;                                       //pushfq
        aLocalCode[nSize++] = 0x48; aLocalCode[nSize++] = 0x83;           //sub     rsp, 40h
        aLocalCode[nSize++] = 0xEC; aLocalCode[nSize++] = 0x40;
        //----
        aLocalCode[nSize++] = 0x48; aLocalCode[nSize++] = 0xB9;           //mov     rcx, lpRemCode+16 (SearchPath)
        *((ULONGLONG NKT_UNALIGNED*)(aLocalCode+nSize)) = (ULONGLONG)lpRemCode + 16;
        nSize += 8;
        //----
        aLocalCode[nSize++] = 0x48; aLocalCode[nSize++] = 0xBA;           //mov     rdx, lpRemCode+24 (DllCharact)
        *((ULONGLONG NKT_UNALIGNED*)(aLocalCode+nSize)) = (ULONGLONG)lpRemCode + 24;
        nSize += 8;
        //----
        aLocalCode[nSize++] = 0x49; aLocalCode[nSize++] = 0xB8;           //mov     r8, lpRemCode+32 (DllName)
        *((ULONGLONG NKT_UNALIGNED*)(aLocalCode+nSize)) = (ULONGLONG)lpRemCode + 32;
        nSize += 8;
        //----
        aLocalCode[nSize++] = 0x49; aLocalCode[nSize++] = 0xB9;           //mov     r9, lpRemCode (hInst*)
        *((ULONGLONG NKT_UNALIGNED*)(aLocalCode+nSize)) = (ULONGLONG)lpRemCode;
        nSize += 8;
        //----
        aLocalCode[nSize++] = 0x48; aLocalCode[nSize++] = 0xB8;           //mov     rax, ADDRESS OF LdrLoadDll
        *((ULONGLONG NKT_UNALIGNED*)(aLocalCode+nSize)) = (ULONGLONG)fnRemLdrLoadDll;
        nSize += 8;
        aLocalCode[nSize++] = 0xFF; aLocalCode[nSize++] = 0xD0;           //call    rax
        //----
        aLocalCode[nSize++] = 0x48; aLocalCode[nSize++] = 0x83;           //add     rsp, 40h
        aLocalCode[nSize++] = 0xC4; aLocalCode[nSize++] = 0x40;
        aLocalCode[nSize++] = 0x9D;                                       //popfq
        aLocalCode[nSize++] = 0x5F;                                       //pop     rdi
        aLocalCode[nSize++] = 0x5E;                                       //pop     rsi
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x5F;           //pop     r15
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x5E;           //pop     r14
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x5D;           //pop     r13
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x5C;           //pop     r12
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x5B;           //pop     r11
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x5A;           //pop     r10
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x59;           //pop     r9
        aLocalCode[nSize++] = 0x41; aLocalCode[nSize++] = 0x58;           //pop     r8
        aLocalCode[nSize++] = 0x5A;                                       //pop     rdx
        aLocalCode[nSize++] = 0x59;                                       //pop     rcx
        aLocalCode[nSize++] = 0x5B;                                       //pop     rbx
        aLocalCode[nSize++] = 0x58;                                       //pop     rax
        //----
        aLocalCode[nSize++] = 0x48; aLocalCode[nSize++] = 0xFF; aLocalCode[nSize++] = 0x25;
        *((DWORD NKT_UNALIGNED*)(aLocalCode+nSize)) = 0;
        nSize += 4;
        *((ULONGLONG NKT_UNALIGNED*)(aLocalCode+nSize)) = (ULONGLONG)(sCtx.Rcx);
        nSize += 8;
        break;
#endif //_M_X64
    }
    //store dll unicode buffer pointer
    switch (nProcPlatform)
    {
      case NKTHOOKLIB_ProcessPlatformX86:
        *((DWORD NKT_UNALIGNED*)(aLocalCode+36)) = (DWORD)(lpRemCode + nSize);
        break;
#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        *((ULONGLONG NKT_UNALIGNED*)(aLocalCode+40)) = (ULONGLONG)(lpRemCode + nSize);
        break;
#endif //_M_X64
    }
    //write code and dll name on target process
    if (NktHookLibHelpers::WriteMem(lpPI->hProcess, lpRemCode, aLocalCode, nSize) == FALSE ||
        NktHookLibHelpers::WriteMem(lpPI->hProcess, lpRemCode+nSize, (LPVOID)szDllNameW, nDllLen) == FALSE)
      dwOsErr = ERROR_ACCESS_DENIED;
  }
  //change main thread's entrypoint
  if (dwOsErr == ERROR_SUCCESS)
  {
    switch (nProcPlatform)
    {
      case NKTHOOKLIB_ProcessPlatformX86:
#if defined(_M_IX86)
        sCtx.Eax = (DWORD)(lpRemCode + 48);
        if (!NT_SUCCESS(fnNtSetContextThread(lpPI->hThread, &sCtx)))
          dwOsErr = ERROR_ACCESS_DENIED;
#elif defined(_M_X64)
        sWow64Ctx.Eax = (DWORD)(lpRemCode + 48);
        if (fnRtlWow64GetThreadContext != NULL && fnRtlWow64SetThreadContext != NULL)
        {
          if (!NT_SUCCESS(fnRtlWow64SetThreadContext(lpPI->hThread, &sWow64Ctx)))
            dwOsErr = ERROR_ACCESS_DENIED;
        }
        else
        {
          if (NktHookLibHelpers::WriteMem(lpPI->hProcess, lpWow64Ctx, &sWow64Ctx, sizeof(sWow64Ctx)) != sizeof(sWow64Ctx))
            dwOsErr = ERROR_ACCESS_DENIED;
        }
#endif
        break;

#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        sCtx.Rcx = (DWORD64)(lpRemCode + 48);
        if (!NT_SUCCESS(fnNtSetContextThread(lpPI->hThread, &sCtx)))
          dwOsErr = ERROR_ACCESS_DENIED;
        break;
#endif //_M_X64
    }
  }
  if (dwOsErr == ERROR_SUCCESS)
  {
    if ((dwCreationFlags & CREATE_SUSPENDED) == 0)
      NktNtResumeThread(lpPI->hThread, NULL);
  }
  else
  {
    typedef NTSTATUS (NTAPI *lpfnNtTerminateProcess)(__in_opt HANDLE ProcessHandle, __in NTSTATUS ExitStatus);
    lpfnNtTerminateProcess fnNtTerminateProcess;
    HINSTANCE hNtDll;

    hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
    if (hNtDll != NULL)
    {
      fnNtTerminateProcess = (lpfnNtTerminateProcess)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                            "NtTerminateProcess");
      if (fnNtTerminateProcess != NULL)
        fnNtTerminateProcess(lpPI->hProcess, STATUS_UNSUCCESSFUL);
    }
    NktNtClose(lpPI->hProcess);
    NktNtClose(lpPI->hThread);
    NktHookLibHelpers::MemSet(lpPI, 0, sizeof(PROCESS_INFORMATION));
  }
  return dwOsErr;
}
