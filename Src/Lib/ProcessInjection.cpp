/*
 * Copyright (C) 2010-2015 Nektra S.A., Buenos Aires, Argentina.
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
#include "WaitableObjects.h"
#include "RelocatableCode.h"
#include "AutoPtr.h"
#include "ThreadSuspend.h"
#include "ProcessEntry.h"

#pragma intrinsic (_InterlockedIncrement)

using namespace NktHookLib::Internals;

//-----------------------------------------------------------

#define _DOALIGN(x, _align) (((SIZE_T)(x) + (_align-1)) & (~(_align-1)))

#if defined(_M_X64) || defined(_M_IA64) || defined(_M_AMD64)
  #define NKT_UNALIGNED __unaligned
#else
  #define NKT_UNALIGNED
#endif

#define SystemProcessorInformation                         1

#define ThreadBasicInformation                             0
#define ThreadBasePriority                                 3
#define ThreadImpersonationToken                           5

#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE                    3
#define SE_IMPERSONATE_PRIVILEGE                          29

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED      0x00000001

//-----------------------------------------------------------

typedef struct {
  USHORT ProcessorArchitecture;
  USHORT ProcessorLevel;
  USHORT ProcessorRevision;
  USHORT Reserved;
  ULONG ProcessorFeatureBits;
} NKT_SYSTEM_PROCESSOR_INFORMATION;

typedef struct {
  BYTE Revision;
  BYTE SubAuthorityCount;
  SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
  DWORD SubAuthority[SID_MAX_SUB_AUTHORITIES];
} NKT_SID;

typedef struct {
  UCHAR AceType;
  UCHAR AceFlags;
  USHORT AceSize;
} NKT_ACE_HEADER;

typedef struct {
  NKT_ACE_HEADER Header;
  ACCESS_MASK AccessMask;
} NKT_ACE;

typedef struct {
  ULONG Size;
  ULONG Unknown1;
  ULONG Unknown2;
  PULONG Unknown3;
  ULONG Unknown4;
  ULONG Unknown5;
  ULONG Unknown6;
  PULONG Unknown7;
  ULONG Unknown8;
} NKT_NTCREATETHREADEXBUFFER;

typedef struct {
  SIZE_T UniqueProcess;
  SIZE_T UniqueThread;
} NKT_CLIENT_ID;

//-----------------------------------------------------------

static DWORD CreateProcessWithDll_Common(__inout LPPROCESS_INFORMATION lpPI, __in DWORD dwCreationFlags,
                                         __in_z LPCWSTR szDllNameW);

static DWORD IsProcessInitialized(__in HANDLE hProcess, __out LPBOOL lpbIsInitialized);

static DWORD InstallWaitForEventAtStartup(__out LPHANDLE lphReadyEvent, __out LPHANDLE lphContinueEvent,
                                          __in HANDLE hSuspendedProc, __in HANDLE hSuspendedMainThread);

static DWORD InjectDllInRunningProcess(__in HANDLE hProcess, __in_z LPCWSTR szDllNameW);
static DWORD InjectDllInSuspendedProcess(__in HANDLE hProcess, __in HANDLE hMainThread, __in_z LPCWSTR szDllNameW);

static DWORD CreateThreadInRunningProcess(__in HANDLE hProcess, __in LPVOID lpCodeStart, __in LPVOID lpThreadParam,
                                          __out LPHANDLE lphNewThread);

static NTSTATUS GenerateRestrictedThreadToken(__in HANDLE hProcess, __out HANDLE *lphThreadToken);

static NTSTATUS MyCreateRestrictedToken(__in HANDLE hToken, __out HANDLE *lphRestrictedToken);
static NTSTATUS SetTokenIntegrityLevel(__in HANDLE hToken, __in MANDATORY_LEVEL nLevel);
static NTSTATUS GetTokenIntegrityLevel(__in HANDLE hToken, __out MANDATORY_LEVEL *lpnLevel);
static NTSTATUS QueryTokenInfo(__in HANDLE hToken, __in TOKEN_INFORMATION_CLASS nClass, __out LPVOID *lplpInfo);

static NTSTATUS GetPrimaryThread(__in HANDLE hProcess, __out HANDLE *lphThread);

//-----------------------------------------------------------

namespace NktHookLibHelpers {

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

  if (lpProcessInformation != NULL)
    MemSet(lpProcessInformation, 0, sizeof(PROCESS_INFORMATION));
  //check parameters
  if (szDllNameW == NULL || szDllNameW[0] == 0 || lpProcessInformation == NULL)
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

  if (lpProcessInformation != NULL)
    MemSet(lpProcessInformation, 0, sizeof(PROCESS_INFORMATION));
  //check parameters
  if (szDllNameW == NULL || szDllNameW[0] == 0 || lpProcessInformation == NULL)
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

  if (lpProcessInformation != NULL)
    MemSet(lpProcessInformation, 0, sizeof(PROCESS_INFORMATION));
  //check parameters
  if (szDllNameW == NULL || szDllNameW[0] == 0 || lpProcessInformation == NULL)
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

DWORD InjectDllByPidW(__in DWORD dwPid, __in_z LPCWSTR szDllNameW)
{
  HANDLE hProc;
  DWORD dwOsErr;

  hProc = CProcessesHandles::CreateHandle(dwPid, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | PROCESS_CREATE_THREAD |
                                                 PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                                 PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION |
                                                 PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME);
  if (hProc != NULL)
  {
    dwOsErr = InjectDllByHandleW(hProc, szDllNameW);
    NktNtClose(hProc);
  }
  else
  {
    dwOsErr = ERROR_ACCESS_DENIED;
  }
  return dwOsErr;
}

DWORD InjectDllByHandleW(__in HANDLE hProcess, __in_z LPCWSTR szDllNameW)
{
  return InjectDllInRunningProcess(hProcess, szDllNameW);
}

} //namespace NktHookLibHelpers

//-----------------------------------------------------------

static DWORD CreateProcessWithDll_Common(__inout LPPROCESS_INFORMATION lpPI, __in DWORD dwCreationFlags,
                                         __in_z LPCWSTR szDllNameW)
{
  DWORD dwOsErr;

  dwOsErr = InjectDllInSuspendedProcess(lpPI->hProcess, lpPI->hThread, szDllNameW);
  if (dwOsErr == ERROR_SUCCESS)
  {
    if ((dwCreationFlags & CREATE_SUSPENDED) == 0)
      NktNtResumeThread(lpPI->hThread, NULL);
  }
  else
  {
    typedef NTSTATUS (NTAPI *lpfnNtTerminateProcess)(__in_opt HANDLE ProcessHandle, __in NTSTATUS ExitStatus);
    LPVOID fnNtTerminateProcess;
    HINSTANCE hNtDll;

    hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
    if (hNtDll != NULL)
    {
      fnNtTerminateProcess = NktHookLibHelpers::GetProcedureAddress(hNtDll, "NtTerminateProcess");
      if (fnNtTerminateProcess != NULL)
        ((lpfnNtTerminateProcess)fnNtTerminateProcess)(lpPI->hProcess, STATUS_UNSUCCESSFUL);
    }
    NktNtClose(lpPI->hProcess);
    NktNtClose(lpPI->hThread);
    NktHookLibHelpers::MemSet(lpPI, 0, sizeof(PROCESS_INFORMATION));
  }
  return dwOsErr;
}

static DWORD IsProcessInitialized(__in HANDLE hProcess, __out LPBOOL lpbIsInitialized)
{
  LONG nNtStatus;
  PROCESS_BASIC_INFORMATION sPbi;
#if defined(_M_X64)
  ULONG_PTR nWow64;
#endif //_M_X64
  LPBYTE lpPeb;
  LONG nProcPlatform;

  *lpbIsInitialized = FALSE;
  //get remote process' PEB
#if defined(_M_IX86)
  nNtStatus = NktNtQueryInformationProcess(hProcess, ProcessBasicInformation, &sPbi, (ULONG)sizeof(sPbi), NULL);
  if (!NT_SUCCESS(nNtStatus))
    return NktRtlNtStatusToDosError(nNtStatus);
  lpPeb = (LPBYTE)(sPbi.PebBaseAddress);
  nProcPlatform = NKTHOOKLIB_ProcessPlatformX86;

#elif defined(_M_X64)
  nNtStatus = NktNtQueryInformationProcess(hProcess, ProcessWow64Information, &nWow64, sizeof(nWow64), NULL);
  if (!NT_SUCCESS(nNtStatus))
    return NktRtlNtStatusToDosError(nNtStatus);
  if (nWow64 != 0)
  {
    lpPeb = (LPBYTE)nWow64;
    nProcPlatform = NKTHOOKLIB_ProcessPlatformX86;
  }
  else
  {
    nNtStatus = NktNtQueryInformationProcess(hProcess, ProcessBasicInformation, &sPbi, (ULONG)sizeof(sPbi), NULL);
    if (!NT_SUCCESS(nNtStatus))
      return NktRtlNtStatusToDosError(nNtStatus);
    lpPeb = (LPBYTE)(sPbi.PebBaseAddress);
    nProcPlatform = NKTHOOKLIB_ProcessPlatformX64;
  }
#endif
  //now check if process is really initialized
  switch (nProcPlatform)
  {
    case NKTHOOKLIB_ProcessPlatformX86:
      {
      DWORD dw;

      if (NktHookLibHelpers::ReadMem(hProcess, &dw, lpPeb+0x0C, sizeof(dw)) != sizeof(dw))
        return ERROR_ACCESS_DENIED;
      if (dw != 0)
      {
        if (NktHookLibHelpers::ReadMem(hProcess, lpbIsInitialized, (LPBYTE)((ULONG_PTR)dw+4), sizeof(BOOLEAN)) != sizeof(BOOLEAN))
          return ERROR_ACCESS_DENIED;
      }
      }
      break;

#if defined(_M_X64)
    case NKTHOOKLIB_ProcessPlatformX64:
      {
      ULONGLONG ull;

      if (NktHookLibHelpers::ReadMem(hProcess, &ull, lpPeb+0x18, sizeof(ull)) != sizeof(ull))
        return ERROR_ACCESS_DENIED;
      if (ull != 0)
      {
        if (NktHookLibHelpers::ReadMem(hProcess, lpbIsInitialized, (LPBYTE)ull+4, sizeof(BOOLEAN)) != sizeof(BOOLEAN))
          return ERROR_ACCESS_DENIED;
      }
      }
      break;
#endif //_M_X64
  }
  return ERROR_SUCCESS;
}

static DWORD InstallWaitForEventAtStartup(__out LPHANDLE lphReadyEvent, __out LPHANDLE lphContinueEvent,
                                          __in HANDLE hSuspendedProc, __in HANDLE hSuspendedMainThread)
{
#if defined(_M_X64)
  typedef NTSTATUS (NTAPI *lpfnRtlWow64GetThreadContext)(__in HANDLE hThread, __inout PWOW64_CONTEXT lpContext);
  typedef NTSTATUS (NTAPI *lpfnRtlWow64SetThreadContext)(__in HANDLE hThread, __in CONST PWOW64_CONTEXT lpContext);
#endif //_M_X64
  DWORD dwOsErr;
  HINSTANCE hNtDll;
#if defined(_M_X64)
  lpfnRtlWow64GetThreadContext fnRtlWow64GetThreadContext;
  lpfnRtlWow64SetThreadContext fnRtlWow64SetThreadContext;
#endif //_M_X64
  LONG nProcPlatform;
  CONTEXT sCtx;
#if defined(_M_X64)
  WOW64_CONTEXT sWow64Ctx, *lpWow64Ctx = NULL;
#endif //_M_X64
  CNktEvent cReadyEv, cContinueEv;
  SIZE_T k, nSize;
  LPBYTE lpRemCode;
  HANDLE hRemContinueEvent, hRemReadyEvent, hRemSelfProc;
  NTSTATUS nNtStatus;

  if (lphReadyEvent != NULL)
    *lphReadyEvent = NULL;
  if (lphContinueEvent != NULL)
    *lphContinueEvent = NULL;
  if (lphReadyEvent == NULL || lphContinueEvent == NULL)
    return ERROR_INVALID_PARAMETER;
  lpRemCode = NULL;
  hRemContinueEvent = hRemReadyEvent = hRemSelfProc = NULL;
  //locate needed functions
  hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
  if (hNtDll != NULL)
  {
#if defined(_M_X64)
    fnRtlWow64GetThreadContext = (lpfnRtlWow64GetThreadContext)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                     "RtlWow64GetThreadContext");
    fnRtlWow64SetThreadContext = (lpfnRtlWow64SetThreadContext)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                     "RtlWow64SetThreadContext");
#endif //_M_X64
    dwOsErr = ERROR_SUCCESS;
  }
  else
  {
    dwOsErr = ERROR_PROC_NOT_FOUND;
  }
  //get suspended thread execution context
  if (dwOsErr == ERROR_SUCCESS)
  {
    switch (nProcPlatform = NktHookLibHelpers::GetProcessPlatform(hSuspendedProc))
    {
      case NKTHOOKLIB_ProcessPlatformX86:
#if defined(_M_IX86)
        sCtx.ContextFlags = CONTEXT_FULL;
        nNtStatus = NktNtGetContextThread(hSuspendedMainThread, &sCtx);

#elif defined(_M_X64)
        if (fnRtlWow64GetThreadContext != NULL && fnRtlWow64SetThreadContext != NULL)
        {
          sWow64Ctx.ContextFlags = CONTEXT_FULL;
          nNtStatus = fnRtlWow64GetThreadContext(hSuspendedMainThread, &sWow64Ctx);
        }
        else
        {
          //try to locate the pointer to the WOW64_CONTEXT data by reading the thread's TLS slot 1
          NKT_HK_THREAD_BASIC_INFORMATION sTbi;
          LPBYTE lpTlsSlot;

          nNtStatus = NktNtQueryInformationThread(hSuspendedMainThread, (THREADINFOCLASS)ThreadBasicInformation,
                                                  &sTbi, sizeof(sTbi), NULL);
          if (NT_SUCCESS(nNtStatus))
          {
            lpTlsSlot = (LPBYTE)(sTbi.TebBaseAddress) + 0x0E10 + 1*sizeof(DWORD);
            if (NktHookLibHelpers::ReadMem(hSuspendedProc, &lpWow64Ctx, lpTlsSlot,
                                           sizeof(lpWow64Ctx)) != sizeof(lpWow64Ctx) ||
                NktHookLibHelpers::ReadMem(hSuspendedProc, &sWow64Ctx, lpWow64Ctx,
                                           sizeof(sWow64Ctx)) != sizeof(sWow64Ctx))
            {
              nNtStatus = STATUS_UNSUCCESSFUL;
            }
          }
        }
#endif
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;

#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        sCtx.ContextFlags = CONTEXT_FULL;
        nNtStatus = NktNtGetContextThread(hSuspendedMainThread, &sCtx);
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;
#endif //_M_X64

      default:
        dwOsErr = ERROR_CALL_NOT_IMPLEMENTED;
        break;
    }
  }
  //create "ready" and "continue" events
  if (dwOsErr == ERROR_SUCCESS)
  {
    if (cReadyEv.Create(TRUE, FALSE) != FALSE && cContinueEv.Create(TRUE, FALSE) != FALSE)
    {
      nNtStatus = NktNtDuplicateObject(NKTHOOKLIB_CurrentProcess, cReadyEv.GetEventHandle(), hSuspendedProc,
                                       &hRemReadyEvent, 0, 0, DUPLICATE_SAME_ACCESS);
      if (NT_SUCCESS(nNtStatus))
      {
        nNtStatus = NktNtDuplicateObject(NKTHOOKLIB_CurrentProcess, cContinueEv.GetEventHandle(), hSuspendedProc,
                                         &hRemContinueEvent, 0, 0, DUPLICATE_SAME_ACCESS);
      }
      if (NT_SUCCESS(nNtStatus))
      {
        nNtStatus = NktNtDuplicateObject(NKTHOOKLIB_CurrentProcess, NKTHOOKLIB_CurrentProcess, hSuspendedProc,
                                         &hRemSelfProc, 0, 0, DUPLICATE_SAME_ACCESS);
      }
      if (!NT_SUCCESS(nNtStatus))
        dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
    }
    else
    {
      dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
    }
  }
  //allocate memory in remote process
  if (dwOsErr == ERROR_SUCCESS)
  {
    nSize = _DOALIGN(RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform), 8);
    nSize += _DOALIGN(RelocatableCode::WaitForEventAtStartup_GetSize(nProcPlatform), 8);
    nNtStatus = NktNtAllocateVirtualMemory(hSuspendedProc, (PVOID*)&lpRemCode, 0, &nSize, MEM_RESERVE|MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(nNtStatus))
      dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
  }
  //write remote code
  if (dwOsErr == ERROR_SUCCESS)
  {
    RelocatableCode::GETMODULEANDPROCADDR_DATA gmpa_data;
    LPBYTE d, s;

    d = lpRemCode;
    //write get module address and get procedure address code
    k = RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform);
    s = RelocatableCode::GetModuleAndProcAddr_GetCode(nProcPlatform, gmpa_data);
    if (NktHookLibHelpers::WriteMem(hSuspendedProc, d, s, k) == FALSE)
      dwOsErr = ERROR_ACCESS_DENIED;
    //write code
    if (dwOsErr == ERROR_SUCCESS)
    {
      d += _DOALIGN(k, 8);
      k = RelocatableCode::WaitForEventAtStartup_GetSize(nProcPlatform);
      s = RelocatableCode::WaitForEventAtStartup_GetCode(nProcPlatform);
      if (NktHookLibHelpers::WriteMem(hSuspendedProc, d, s, k) == FALSE)
        dwOsErr = ERROR_ACCESS_DENIED;
    }
    //write data
    if (dwOsErr == ERROR_SUCCESS)
    {
      DWORD dw[6];
#if defined(_M_X64)
      ULONGLONG ull[6];
#endif //_M_X64

      switch (nProcPlatform)
      {
        case NKTHOOKLIB_ProcessPlatformX86:
          dw[0] = (DWORD)((ULONG_PTR)(lpRemCode + gmpa_data.nOffset_GetProcedureAddress));
          dw[1] = (DWORD)((ULONG_PTR)(lpRemCode + gmpa_data.nOffset_GetModuleBaseAddress));
          dw[2] = (DWORD)((ULONG_PTR)hRemReadyEvent);
          dw[3] = (DWORD)((ULONG_PTR)hRemContinueEvent);
          dw[4] = (DWORD)((ULONG_PTR)hRemSelfProc);
#if defined(_M_IX86)
          dw[5] = (DWORD)sCtx.Eip;
#elif defined(_M_X64)
          dw[5] = (DWORD)sWow64Ctx.Eip;
#endif
          dw[5] -= (DWORD)((ULONG_PTR)(d+k));
          if (NktHookLibHelpers::WriteMem(hSuspendedProc, d, &dw[0], 4) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+8, &dw[1], 4) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+16, &dw[2], 4) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+24, &dw[3], 4) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+32, &dw[4], 4) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+k-4, &dw[5], 4) == FALSE)
            dwOsErr = ERROR_ACCESS_DENIED;
          break;

#if defined(_M_X64)
        case NKTHOOKLIB_ProcessPlatformX64:
          ull[0] = (ULONGLONG)(lpRemCode + gmpa_data.nOffset_GetProcedureAddress);
          ull[1] = (ULONGLONG)(lpRemCode + gmpa_data.nOffset_GetModuleBaseAddress);
          ull[2] = (ULONGLONG)hRemReadyEvent;
          ull[3] = (ULONGLONG)hRemContinueEvent;
          ull[4] = (ULONGLONG)hRemSelfProc;
          ull[5] = (ULONGLONG)sCtx.Rip;
          if (NktHookLibHelpers::WriteMem(hSuspendedProc, d, &ull[0], 8) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+8, &ull[1], 8) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+16, &ull[2], 8) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+24, &ull[3], 8) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+32, &ull[4], 8) == FALSE ||
              NktHookLibHelpers::WriteMem(hSuspendedProc, d+k-8, &ull[5], 8) == FALSE)
            dwOsErr = ERROR_ACCESS_DENIED;
          break;
#endif //_M_X64
      }
      d += _DOALIGN(k, 8);
    }
    //flush instruction cache
    if (dwOsErr == ERROR_SUCCESS)
      NktNtFlushInstructionCache(hSuspendedProc, lpRemCode, (ULONG)(d-lpRemCode));
  }
  //change main thread's entrypoint
  if (dwOsErr == ERROR_SUCCESS)
  {
    LPBYTE d = lpRemCode + _DOALIGN(RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform), 8) + 136;

    switch (nProcPlatform)
    {
      case NKTHOOKLIB_ProcessPlatformX86:
#if defined(_M_IX86)
        sCtx.Eip = (DWORD)d;
        nNtStatus = NktNtSetContextThread(hSuspendedMainThread, &sCtx);
#elif defined(_M_X64)
        sWow64Ctx.Eip = (DWORD)((ULONG_PTR)d);
        if (fnRtlWow64GetThreadContext != NULL && fnRtlWow64SetThreadContext != NULL)
        {
          nNtStatus = fnRtlWow64SetThreadContext(hSuspendedMainThread, &sWow64Ctx);
        }
        else
        {
          if (NktHookLibHelpers::WriteMem(hSuspendedProc, lpWow64Ctx, &sWow64Ctx, sizeof(sWow64Ctx)) != FALSE)
            nNtStatus = STATUS_ACCESS_DENIED;
        }
#endif
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;

#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        sCtx.Rip = (DWORD64)d;
        nNtStatus = NktNtSetContextThread(hSuspendedMainThread, &sCtx);
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;
#endif //_M_X64
    }
  }
  //done
  if (dwOsErr == ERROR_SUCCESS)
  {
    *lphReadyEvent = cReadyEv.Detach();
    *lphContinueEvent = cContinueEv.Detach();
  }
  else
  {
    //cleanup on error
    if (hRemContinueEvent != NULL)
      NktNtDuplicateObject(hSuspendedProc, hRemContinueEvent, hSuspendedProc, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (hRemReadyEvent != NULL)
      NktNtDuplicateObject(hSuspendedProc, hRemReadyEvent, hSuspendedProc, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (hRemSelfProc != NULL)
      NktNtDuplicateObject(hSuspendedProc, hRemSelfProc, hSuspendedProc, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (lpRemCode != NULL)
    {
      nSize = 0;
      NktNtFreeVirtualMemory(hSuspendedProc, (PVOID*)&lpRemCode, &nSize, MEM_RELEASE);
    }
  }
  return dwOsErr;
}

static DWORD InjectDllInRunningProcess(__in HANDLE hProcess, __in_z LPCWSTR szDllNameW)
{
  CNktThreadSuspend cProcSusp;
  PROCESS_BASIC_INFORMATION sPbi;
  CNktEvent cReadyEv, cContinueEv;
  DWORD dwOsErr;
  SIZE_T k, nSize, nDllLen;
  LPBYTE lpRemCode;
  BOOL bIsInitialized;
  LONG nProcPlatform;
  HANDLE hNewThread, hRemReadyEvent, hRemContinueEvent;
  NTSTATUS nNtStatus;

  //calculate dll name length
  if (szDllNameW == NULL)
    return ERROR_INVALID_PARAMETER;
  for (nDllLen=0; nDllLen<16384 && szDllNameW[nDllLen]!=0; nDllLen++);
  nDllLen *= sizeof(WCHAR);
  if (nDllLen == 0 || nDllLen >= 32768)
    return ERROR_INVALID_PARAMETER;
  lpRemCode = NULL;
  hNewThread = hRemReadyEvent = hRemContinueEvent = NULL;
  //get process id and suspend
  nNtStatus = NktNtQueryInformationProcess(hProcess, ProcessBasicInformation, &sPbi, sizeof(sPbi), NULL);
  if (NT_SUCCESS(nNtStatus))
    dwOsErr = cProcSusp.SuspendAll((DWORD)(sPbi.UniqueProcessId), NULL, 0);
  else
    dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
  //query if process is initialized
  if (dwOsErr == ERROR_SUCCESS)
    dwOsErr = IsProcessInitialized(hProcess, &bIsInitialized);
  //query for process platform
  if (dwOsErr == ERROR_SUCCESS)
  {
    switch (nProcPlatform = NktHookLibHelpers::GetProcessPlatform(hProcess))
    {
      case NKTHOOKLIB_ProcessPlatformX86:
#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
#endif //_M_X64
        break;
      default:
        dwOsErr = ERROR_CALL_NOT_IMPLEMENTED;
        break;
    }
  }
  //allocate memory in remote process
  if (dwOsErr == ERROR_SUCCESS)
  {
    nSize = _DOALIGN(RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform), 8);
    nSize += _DOALIGN(RelocatableCode::InjectDllInRunningProcess_GetSize(nProcPlatform), 8);
    nSize += _DOALIGN(nDllLen, 8);
    nSize = _DOALIGN(nSize, 4096);
    nNtStatus = NktNtAllocateVirtualMemory(hProcess, (PVOID*)&lpRemCode, 0, &nSize, MEM_RESERVE|MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(nNtStatus))
      dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
  }
  //write remote code
  if (dwOsErr == ERROR_SUCCESS)
  {
    RelocatableCode::GETMODULEANDPROCADDR_DATA gmpa_data;
    LPBYTE d, s;

    d = lpRemCode;
    //write get module address and get procedure address code
    k = RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform);
    s = RelocatableCode::GetModuleAndProcAddr_GetCode(nProcPlatform, gmpa_data);
    if (NktHookLibHelpers::WriteMem(hProcess, d, s, k) == FALSE)
      dwOsErr = ERROR_ACCESS_DENIED;
    //write thread code
    if (dwOsErr == ERROR_SUCCESS)
    {
      d += _DOALIGN(k, 8);
      k = RelocatableCode::InjectDllInRunningProcess_GetSize(nProcPlatform);
      s = RelocatableCode::InjectDllInRunningProcess_GetCode(nProcPlatform);
      if (NktHookLibHelpers::WriteMem(hProcess, d, s, k) == FALSE)
        dwOsErr = ERROR_ACCESS_DENIED;
    }
    //write new startup data
    if (dwOsErr == ERROR_SUCCESS)
    {
      DWORD dw[3];
#if defined(_M_X64)
      ULONGLONG ull[3];
#endif //_M_X64

      switch (nProcPlatform)
      {
        case NKTHOOKLIB_ProcessPlatformX86:
          dw[0] = (DWORD)((ULONG_PTR)(lpRemCode + gmpa_data.nOffset_GetProcedureAddress));
          dw[1] = (DWORD)((ULONG_PTR)(lpRemCode + gmpa_data.nOffset_GetModuleBaseAddress));
          dw[2] = (DWORD)((ULONG_PTR)(d + _DOALIGN(k, 8)));
          if (NktHookLibHelpers::WriteMem(hProcess, d, &dw[0], 2*sizeof(DWORD)) == FALSE ||
              NktHookLibHelpers::WriteMem(hProcess, d+12, &dw[2], 4) == FALSE)
            dwOsErr = ERROR_ACCESS_DENIED;
          break;

#if defined(_M_X64)
        case NKTHOOKLIB_ProcessPlatformX64:
          ull[0] = (ULONGLONG)(lpRemCode + gmpa_data.nOffset_GetProcedureAddress);
          ull[1] = (ULONGLONG)(lpRemCode + gmpa_data.nOffset_GetModuleBaseAddress);
          ull[2] = (ULONGLONG)(d + _DOALIGN(k, 8));
          if (NktHookLibHelpers::WriteMem(hProcess, d, &ull[0], 2*sizeof(ULONGLONG)) == FALSE ||
              NktHookLibHelpers::WriteMem(hProcess, d+24, &ull[2], 8) == FALSE)
            dwOsErr = ERROR_ACCESS_DENIED;
          break;
#endif //_M_X64
      }
      d += _DOALIGN(k, 8);
    }
    //write dll name
    if (dwOsErr == ERROR_SUCCESS)
    {
      if (NktHookLibHelpers::WriteMem(hProcess, d, (LPVOID)szDllNameW, nDllLen) != FALSE)
      {
        //if dll name ends with x86.dll, x64.dll, 32.dll or 64.dll, change the number to reflect the correct platform
        k = nDllLen / sizeof(WCHAR);
        if (k >= 4 && szDllNameW[k - 4] == L'.'  &&
            (szDllNameW[k - 3] == L'd' || szDllNameW[k - 3] == L'd') &&
            (szDllNameW[k - 2] == L'l' || szDllNameW[k - 2] == L'l') &&
            (szDllNameW[k - 1] == L'l' || szDllNameW[k - 1] == L'l'))
        {
          switch (nProcPlatform)
          {
            case NKTHOOKLIB_ProcessPlatformX86:
              if (k >= 7 && (szDllNameW[k - 7] == L'x' || szDllNameW[k - 7] == L'X') &&
                  szDllNameW[k - 6] == L'6' && szDllNameW[k - 5] == L'4')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"86", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              else if (k >= 6 && szDllNameW[k - 6] == L'6' && szDllNameW[k - 5] == L'4')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"32", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              break;

#if defined(_M_X64)
            case NKTHOOKLIB_ProcessPlatformX64:
              if (k >= 7 && (szDllNameW[k - 7] == L'x' || szDllNameW[k - 7] == L'X') &&
                  szDllNameW[k - 6] == L'8' && szDllNameW[k - 5] == L'6')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"64", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              else if (k >= 6 && szDllNameW[k - 6] == L'3' && szDllNameW[k - 5] == L'2')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"64", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              break;
#endif //_M_X64
          }
        }
      }
      else
      {
        dwOsErr = ERROR_ACCESS_DENIED;
      }
      d += _DOALIGN(nDllLen, 8);
    }
    //flush instruction cache
    if (dwOsErr == ERROR_SUCCESS)
      NktNtFlushInstructionCache(hProcess, lpRemCode, (ULONG)(d-lpRemCode));
  }
  //if the process is not initialized, create a new "waiter" entrypoint
  if (dwOsErr == ERROR_SUCCESS && bIsInitialized == FALSE)
  {
    HANDLE hThread;

    nNtStatus = GetPrimaryThread(hProcess, &hThread);
    if (NT_SUCCESS(nNtStatus))
    {
      dwOsErr = InstallWaitForEventAtStartup(&cReadyEv, &cContinueEv, hProcess, hThread);
      NktNtClose(hThread);
    }
    else
    {
      dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
    }
    if (dwOsErr == ERROR_SUCCESS)
    {
      nNtStatus = NktNtDuplicateObject(NKTHOOKLIB_CurrentProcess, cReadyEv.GetEventHandle(), hProcess,
                                       &hRemReadyEvent, 0, 0, DUPLICATE_SAME_ACCESS);
      if (NT_SUCCESS(nNtStatus))
      {
        nNtStatus = NktNtDuplicateObject(NKTHOOKLIB_CurrentProcess, cContinueEv.GetEventHandle(), hProcess,
                                         &hRemContinueEvent, 0, 0, DUPLICATE_SAME_ACCESS);
      }
      if (!NT_SUCCESS(nNtStatus))
        dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
    }
  }
  //write event duplicates
  if (dwOsErr == ERROR_SUCCESS && bIsInitialized == FALSE)
  {
    DWORD dw[2];
#if defined(_M_X64)
    ULONGLONG ull[2];
#endif //_M_X64
    LPBYTE d;

    d = lpRemCode + _DOALIGN(RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform), 8);
    switch (nProcPlatform)
    {
      case NKTHOOKLIB_ProcessPlatformX86:
        dw[0] = (DWORD)((ULONG_PTR)hRemReadyEvent);
        dw[1] = (DWORD)((ULONG_PTR)hRemContinueEvent);
        if (NktHookLibHelpers::WriteMem(hProcess, d+16, dw, 2*sizeof(DWORD)) == FALSE)
          dwOsErr = ERROR_ACCESS_DENIED;
        break;

#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        ull[0] = (ULONGLONG)hRemReadyEvent;
        ull[1] = (ULONGLONG)hRemContinueEvent;
        if (NktHookLibHelpers::WriteMem(hProcess, d+32, ull, 2*sizeof(ULONGLONG)) == FALSE)
          dwOsErr = ERROR_ACCESS_DENIED;
        break;
#endif //_M_X64
    }
    //flush instruction cache (flushing a data write?)
    if (dwOsErr == ERROR_SUCCESS)
      NktNtFlushInstructionCache(hProcess, d, 16);
  }
  //create dll loader thread
  if (dwOsErr == ERROR_SUCCESS)
  {
    k = _DOALIGN(RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform), 8);
    switch (nProcPlatform)
    {
      case NKTHOOKLIB_ProcessPlatformX86:
        k += 176;
        break;
#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        k += 216;
        break;
#endif //_M_X64
    }
    dwOsErr = CreateThreadInRunningProcess(hProcess, lpRemCode+k, NULL, &hNewThread);
  }
  //done
  if (dwOsErr == ERROR_SUCCESS)
  {
    cProcSusp.ResumeAll();
    NktNtResumeThread(hNewThread, NULL);
    NktNtClose(hNewThread);
  }
  else
  {
    //cleanup on error
    if (hNewThread != NULL)
      NktNtClose(hNewThread);
    if (hRemContinueEvent != NULL)
      NktNtDuplicateObject(hProcess, hRemContinueEvent, hProcess, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (hRemReadyEvent != NULL)
      NktNtDuplicateObject(hProcess, hRemReadyEvent, hProcess, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (lpRemCode != NULL)
    {
      nSize = 0;
      NktNtFreeVirtualMemory(hProcess, (PVOID*)&lpRemCode, &nSize, MEM_RELEASE);
    }
    if (cContinueEv.GetEventHandle() != NULL)
      cContinueEv.Set();
  }
  return dwOsErr;
}

static DWORD InjectDllInSuspendedProcess(__in HANDLE hProcess, __in HANDLE hMainThread, __in_z LPCWSTR szDllNameW)
{
#if defined(_M_X64)
  typedef NTSTATUS (NTAPI *lpfnRtlWow64GetThreadContext)(__in HANDLE hThread, __inout PWOW64_CONTEXT lpContext);
  typedef NTSTATUS (NTAPI *lpfnRtlWow64SetThreadContext)(__in HANDLE hThread, __in CONST PWOW64_CONTEXT lpContext);
#endif //_M_X64
  DWORD dwOsErr;
  HINSTANCE hNtDll;
#if defined(_M_X64)
  lpfnRtlWow64GetThreadContext fnRtlWow64GetThreadContext;
  lpfnRtlWow64SetThreadContext fnRtlWow64SetThreadContext;
#endif //_M_X64
  LPBYTE lpRemCode;
  LONG nProcPlatform;
  SIZE_T k, nSize, nDllLen;
  CONTEXT sCtx;
#if defined(_M_X64)
  WOW64_CONTEXT sWow64Ctx, *lpWow64Ctx = NULL;
#endif //_M_X64
  NTSTATUS nNtStatus;

  //calculate dll name length
  if (szDllNameW == NULL)
    return ERROR_INVALID_PARAMETER;
  for (nDllLen=0; nDllLen<16384 && szDllNameW[nDllLen]!=0; nDllLen++);
  nDllLen *= sizeof(WCHAR);
  if (nDllLen == 0 || nDllLen >= 32768)
    return ERROR_INVALID_PARAMETER;
  lpRemCode = NULL;
  //locate needed functions
  hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
  if (hNtDll != NULL)
  {
#if defined(_M_X64)
    fnRtlWow64GetThreadContext = (lpfnRtlWow64GetThreadContext)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                     "RtlWow64GetThreadContext");
    fnRtlWow64SetThreadContext = (lpfnRtlWow64SetThreadContext)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                     "RtlWow64SetThreadContext");
#endif //_M_X64
    dwOsErr = ERROR_SUCCESS;
  }
  else
  {
    dwOsErr = ERROR_PROC_NOT_FOUND;
  }
  //check process platform and retrieve main thread's entrypoint
  if (dwOsErr == ERROR_SUCCESS)
  {
    switch (nProcPlatform = NktHookLibHelpers::GetProcessPlatform(hProcess))
    {
      case NKTHOOKLIB_ProcessPlatformX86:
#if defined(_M_IX86)
        sCtx.ContextFlags = CONTEXT_FULL;
        nNtStatus = NktNtGetContextThread(hMainThread, &sCtx);

#elif defined(_M_X64)
        if (fnRtlWow64GetThreadContext != NULL && fnRtlWow64SetThreadContext != NULL)
        {
          sWow64Ctx.ContextFlags = CONTEXT_FULL;
          nNtStatus = fnRtlWow64GetThreadContext(hMainThread, &sWow64Ctx);
        }
        else
        {
          //try to locate the pointer to the WOW64_CONTEXT data by reading the thread's TLS slot 1
          NKT_HK_THREAD_BASIC_INFORMATION sTbi;
          LPBYTE lpTlsSlot;

          nNtStatus = NktNtQueryInformationThread(hMainThread, (THREADINFOCLASS)ThreadBasicInformation,
                                                  &sTbi, sizeof(sTbi), NULL);
          if (NT_SUCCESS(nNtStatus))
          {
            lpTlsSlot = (LPBYTE)(sTbi.TebBaseAddress) + 0x0E10 + 1*sizeof(DWORD);
            if (NktHookLibHelpers::ReadMem(hProcess, &lpWow64Ctx, lpTlsSlot,
                                           sizeof(lpWow64Ctx)) != sizeof(lpWow64Ctx) ||
                NktHookLibHelpers::ReadMem(hProcess, &sWow64Ctx, lpWow64Ctx, sizeof(sWow64Ctx)) != sizeof(sWow64Ctx))
            {
              nNtStatus = STATUS_UNSUCCESSFUL;
            }
          }
        }
#endif
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;

#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        sCtx.ContextFlags = CONTEXT_FULL;
        nNtStatus = NktNtGetContextThread(hMainThread, &sCtx);
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;
#endif //_M_X64

      default:
        dwOsErr = ERROR_CALL_NOT_IMPLEMENTED;
        break;
    }
  }
  //allocate memory in remote process
  if (dwOsErr == ERROR_SUCCESS)
  {
    nSize = _DOALIGN(RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform), 8);
    nSize += _DOALIGN(RelocatableCode::InjectDllInSuspendedProcess_GetSize(nProcPlatform), 8);
    nSize += _DOALIGN(nDllLen, 8);
    nSize = _DOALIGN(nSize, 4096);
    nNtStatus = NktNtAllocateVirtualMemory(hProcess, (PVOID*)&lpRemCode, 0, &nSize, MEM_RESERVE|MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(nNtStatus))
      dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
  }
  //write remote code
  if (dwOsErr == ERROR_SUCCESS)
  {
    RelocatableCode::GETMODULEANDPROCADDR_DATA gmpa_data;
    LPBYTE d, s;

    d = lpRemCode;
    //write get module address and get procedure address code
    k = RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform);
    s = RelocatableCode::GetModuleAndProcAddr_GetCode(nProcPlatform, gmpa_data);
    if (NktHookLibHelpers::WriteMem(hProcess, d, s, k) == FALSE)
      dwOsErr = ERROR_ACCESS_DENIED;
    //write new startup code
    if (dwOsErr == ERROR_SUCCESS)
    {
      d += _DOALIGN(k, 8);
      k = RelocatableCode::InjectDllInSuspendedProcess_GetSize(nProcPlatform);
      s = RelocatableCode::InjectDllInSuspendedProcess_GetCode(nProcPlatform);
      if (NktHookLibHelpers::WriteMem(hProcess, d, s, k) == FALSE)
        dwOsErr = ERROR_ACCESS_DENIED;
    }
    //write new startup data
    if (dwOsErr == ERROR_SUCCESS)
    {
      DWORD dw[4];
#if defined(_M_X64)
      ULONGLONG ull[4];
#endif

      switch (nProcPlatform)
      {
        case NKTHOOKLIB_ProcessPlatformX86:
          dw[0] = (DWORD)((ULONG_PTR)(lpRemCode + gmpa_data.nOffset_GetProcedureAddress));
          dw[1] = (DWORD)((ULONG_PTR)(lpRemCode + gmpa_data.nOffset_GetModuleBaseAddress));
          dw[2] = (DWORD)((ULONG_PTR)(d + _DOALIGN(k, 8)));
#if defined(_M_IX86)
          dw[3] = (DWORD)sCtx.Eax;
#elif defined(_M_X64)
          dw[3] = (DWORD)sWow64Ctx.Eax;
#endif
          dw[3] -= (DWORD)((ULONG_PTR)(d+k));
          if (NktHookLibHelpers::WriteMem(hProcess, d, dw, 2*sizeof(DWORD)) == FALSE ||
              NktHookLibHelpers::WriteMem(hProcess, d+12, &dw[2], 4) == FALSE ||
              NktHookLibHelpers::WriteMem(hProcess, d+k-4, &dw[3], 4) == FALSE)
            dwOsErr = ERROR_ACCESS_DENIED;
          break;

#if defined(_M_X64)
        case NKTHOOKLIB_ProcessPlatformX64:
          ull[0] = (ULONGLONG)(lpRemCode + gmpa_data.nOffset_GetProcedureAddress);
          ull[1] = (ULONGLONG)(lpRemCode + gmpa_data.nOffset_GetModuleBaseAddress);
          ull[2] = (ULONGLONG)(d + _DOALIGN(k, 8));
          ull[3] = (ULONGLONG)sCtx.Rcx;
          if (NktHookLibHelpers::WriteMem(hProcess, d, ull, 2*sizeof(ULONGLONG)) == FALSE ||
              NktHookLibHelpers::WriteMem(hProcess, d+24, &ull[2], 8) == FALSE ||
              NktHookLibHelpers::WriteMem(hProcess, d+k-8, &ull[3], 8) == FALSE)
            dwOsErr = ERROR_ACCESS_DENIED;
          break;
#endif
      }
      d += _DOALIGN(k, 8);
    }
    //write dll name
    if (dwOsErr == ERROR_SUCCESS)
    {
      if (NktHookLibHelpers::WriteMem(hProcess, d, (LPVOID)szDllNameW, nDllLen) != FALSE)
      {
        //if dll name ends with x86.dll, x64.dll, 32.dll or 64.dll, change the number to reflect the correct platform
        k = nDllLen / sizeof(WCHAR);
        if (k >= 4 && szDllNameW[k - 4] == L'.'  &&
            (szDllNameW[k - 3] == L'd' || szDllNameW[k - 3] == L'd') &&
            (szDllNameW[k - 2] == L'l' || szDllNameW[k - 2] == L'l') &&
            (szDllNameW[k - 1] == L'l' || szDllNameW[k - 1] == L'l'))
        {
          switch (nProcPlatform)
          {
            case NKTHOOKLIB_ProcessPlatformX86:
              if (k >= 7 && (szDllNameW[k - 7] == L'x' || szDllNameW[k - 7] == L'X') &&
                  szDllNameW[k - 6] == L'6' && szDllNameW[k - 5] == L'4')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"86", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              else if (k >= 6 && szDllNameW[k - 6] == L'6' && szDllNameW[k - 5] == L'4')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"32", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              break;

#if defined(_M_X64)
            case NKTHOOKLIB_ProcessPlatformX64:
              if (k >= 7 && (szDllNameW[k - 7] == L'x' || szDllNameW[k - 7] == L'X') &&
                  szDllNameW[k - 6] == L'8' && szDllNameW[k - 5] == L'6')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"64", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              else if (k >= 6 && szDllNameW[k - 6] == L'3' && szDllNameW[k - 5] == L'2')
              {
                if (NktHookLibHelpers::WriteMem(hProcess, d + (k-6)*sizeof(WCHAR), L"64", 4) == FALSE)
                  dwOsErr = ERROR_ACCESS_DENIED;
              }
              break;
#endif //_M_X64
          }
        }
      }
      else
      {
        dwOsErr = ERROR_ACCESS_DENIED;
      }
      d += _DOALIGN(nDllLen, 8);
    }
    //flush instruction cache
    if (dwOsErr == ERROR_SUCCESS)
      NktNtFlushInstructionCache(hProcess, lpRemCode, (ULONG)(d-lpRemCode));
  }
  //change main thread's entrypoint
  if (dwOsErr == ERROR_SUCCESS)
  {
    LPBYTE d = lpRemCode + _DOALIGN(RelocatableCode::GetModuleAndProcAddr_GetSize(nProcPlatform), 8);

    switch (nProcPlatform)
    {
      case NKTHOOKLIB_ProcessPlatformX86:
#if defined(_M_IX86)
        sCtx.Eax = (DWORD)(d+64);
        nNtStatus = NktNtSetContextThread(hMainThread, &sCtx);
#elif defined(_M_X64)
        sWow64Ctx.Eax = (DWORD)((ULONG_PTR)(d+64));
        if (fnRtlWow64GetThreadContext != NULL && fnRtlWow64SetThreadContext != NULL)
        {
          nNtStatus = fnRtlWow64SetThreadContext(hMainThread, &sWow64Ctx);
        }
        else
        {
          if (NktHookLibHelpers::WriteMem(hMainThread, lpWow64Ctx, &sWow64Ctx, sizeof(sWow64Ctx)) != FALSE)
            nNtStatus = STATUS_ACCESS_DENIED;
        }
#endif
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;

#if defined(_M_X64)
      case NKTHOOKLIB_ProcessPlatformX64:
        sCtx.Rcx = (DWORD64)(d+80);
        nNtStatus = NktNtSetContextThread(hMainThread, &sCtx);
        if (!NT_SUCCESS(nNtStatus))
          dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
        break;
#endif //_M_X64
    }
  }
  //done
  if (dwOsErr != ERROR_SUCCESS)
  {
    //cleanup on error
    if (lpRemCode != NULL)
    {
      nSize = 0;
      NktNtFreeVirtualMemory(hProcess, (PVOID*)&lpRemCode, &nSize, MEM_RELEASE);
    }
  }
  return dwOsErr;
}

static DWORD CreateThreadInRunningProcess(__in HANDLE hProcess, __in LPVOID lpCodeStart, __in LPVOID lpThreadParam,
                                          __out LPHANDLE lphNewThread)
{
  typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
  } CLIENT_ID;

  typedef HANDLE (WINAPI *lpfnCreateRemoteThread)(__in HANDLE hProcess, __in LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                                  __in SIZE_T dwStackSize, __in LPTHREAD_START_ROUTINE lpStartAddress,
                                                  __in LPVOID lpParameter, __in DWORD dwCreationFlags,
                                                  __out LPDWORD lpThreadId);
  typedef NTSTATUS (WINAPI *lpfnNtCreateThreadEx)(__out PHANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess,
                                                  __in LPVOID ObjectAttributes, __in HANDLE ProcessHandle,
                                                  __in LPTHREAD_START_ROUTINE lpStartAddress, __in LPVOID lpParameter,
                                                  __in ULONG CreateFlags, __in SIZE_T ZeroBits,
                                                  __in SIZE_T SizeOfStackCommit, __in SIZE_T SizeOfStackReserve,
                                                  __in LPVOID lpBytesBuffer);
  typedef NTSTATUS(WINAPI *lpfnRtlCreateUserThread)(__in HANDLE ProcessHandle, __in_opt PSECURITY_DESCRIPTOR lpSecDescr,
                                                    __in BOOLEAN CreateSuspended, __in_opt ULONG StackZeroBits,
                                                    __in_opt SIZE_T StackReserve, __in_opt SIZE_T StackCommit,
                                                    __in LPTHREAD_START_ROUTINE StartAddress, __in_opt PVOID Parameter,
                                                    __out_opt PHANDLE ThreadHandle, __out_opt CLIENT_ID *ClientId);
  lpfnNtCreateThreadEx fnNtCreateThreadEx;
  lpfnCreateRemoteThread fnCreateRemoteThread;
  lpfnRtlCreateUserThread fnRtlCreateUserThread;
  HINSTANCE hNtDll, hKernel32Dll;
  DWORD dwOsErr;
  HANDLE hThreadToken;
  NTSTATUS nNtStatus;

  NKT_ASSERT(lphNewThread != NULL);
  *lphNewThread = NULL;
  fnNtCreateThreadEx = NULL;
  fnRtlCreateUserThread = NULL;
  fnCreateRemoteThread = NULL;
  //locate needed functions
  hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
  if (hNtDll != NULL)
  {
    fnNtCreateThreadEx = (lpfnNtCreateThreadEx)NktHookLibHelpers::GetProcedureAddress(hNtDll, "NtCreateThreadEx");
    fnRtlCreateUserThread = (lpfnRtlCreateUserThread)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                                            "RtlCreateUserThread");
  }
  hKernel32Dll = NktHookLibHelpers::GetModuleBaseAddress(L"kernel32.dll");
  if (hKernel32Dll != NULL)
  {
    fnCreateRemoteThread = (lpfnCreateRemoteThread)NktHookLibHelpers::GetProcedureAddress(hKernel32Dll,
                                                                                          "CreateRemoteThread");
  }
  if (fnNtCreateThreadEx == NULL && fnRtlCreateUserThread == NULL && fnCreateRemoteThread == NULL)
    return ERROR_PROC_NOT_FOUND;
  //create remote thread using 'NtCreateThreadEx' if available
  dwOsErr = 0xFFFFFFFFUL;
  if (fnNtCreateThreadEx != NULL)
  {
    nNtStatus = fnNtCreateThreadEx(lphNewThread, 0x001FFFFFUL, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpCodeStart,
                                    lpThreadParam, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, NULL, NULL, NULL);
    dwOsErr = (NT_SUCCESS(nNtStatus)) ? ERROR_SUCCESS : NktRtlNtStatusToDosError(nNtStatus);
  }
  /*
  //on error, create remote thread using 'RtlCreateUserThread' if available
  if (dwOsErr != ERROR_SUCCESS)
  {
    nNtStatus = fnRtlCreateUserThread(hProcess, NULL, TRUE, 0, 0, 0, (LPTHREAD_START_ROUTINE)lpCodeStart, lpThreadParam,
                                      lphNewThread, NULL);
    dwOsErr = (NT_SUCCESS(nNtStatus)) ? ERROR_SUCCESS : NktRtlNtStatusToDosError(nNtStatus);
  }
  */
  //on error, create remote thread using 'CreateRemoteThread' if available
  if (dwOsErr != ERROR_SUCCESS)
  {
    DWORD dwTid;

    *lphNewThread = fnCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpCodeStart, lpThreadParam,
                                         CREATE_SUSPENDED, &dwTid);
    dwOsErr = (*lphNewThread != NULL) ? ERROR_SUCCESS : NktHookLibHelpers::GetWin32LastError();
  }
  //on success, set restricted token if needed
  if (dwOsErr == ERROR_SUCCESS)
  {
    nNtStatus = GenerateRestrictedThreadToken(hProcess, &hThreadToken);
    //set thread's restricted token if needed
    if (NT_SUCCESS(nNtStatus) && hThreadToken != NULL)
    {
      nNtStatus = NktNtSetInformationThread(*lphNewThread, (THREADINFOCLASS)ThreadImpersonationToken, &hThreadToken,
                                            sizeof(HANDLE));
    }
    if (!NT_SUCCESS(nNtStatus))
      dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
  }
  //done
  return dwOsErr;
}

static NTSTATUS GenerateRestrictedThreadToken(__in HANDLE hProcess, __out HANDLE *lphThreadToken)
{
  typedef NTSTATUS (NTAPI *lpfnRtlCreateAcl)(__out PACL Acl, __in ULONG AclLength, __in ULONG AceRevision);
  typedef NTSTATUS (NTAPI *lpfnRtlAddAccessAllowedAce)(__in PACL Acl, __in ULONG Revision, __in ACCESS_MASK AccessMask,
                                                       __in PSID Sid);
  lpfnRtlCreateAcl fnRtlCreateAcl;
  lpfnRtlAddAccessAllowedAce fnRtlAddAccessAllowedAce;
  HANDLE hToken, hNewToken;
  TOKEN_DEFAULT_DACL sNewDefDacl;
  MANDATORY_LEVEL nLevel;
  TNktAutoFreePtr<TOKEN_USER> cUser;
  TNktAutoFreePtr<TOKEN_GROUPS> cGroups;
  TNktAutoFreePtr<ACL> cAcl;
  OBJECT_ATTRIBUTES sObjAttr;
  SECURITY_QUALITY_OF_SERVICE sSqos;
  RTL_OSVERSIONINFOW sOvi;
  NKT_SID sSid;
  ULONG nSize;
  HINSTANCE hNtDll;
  NTSTATUS nNtStatus;

  *lphThreadToken = NULL;
  //get OS version
  NktHookLibHelpers::MemSet(&sOvi, 0, sizeof(sOvi));
  sOvi.dwOSVersionInfoSize = sizeof(sOvi);
  nNtStatus = NktRtlGetVersion(&sOvi);
  if (!NT_SUCCESS(nNtStatus))
    return nNtStatus;
  if (sOvi.dwPlatformId != VER_PLATFORM_WIN32_NT || sOvi.dwMajorVersion < 5)
    return STATUS_SUCCESS; //return if pre-XP
  if (sOvi.dwMajorVersion == 5 && sOvi.dwMinorVersion < 1)
    return STATUS_SUCCESS;
  //open process token
  nNtStatus = NktNtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
  //query for restricted sids
  if (NT_SUCCESS(nNtStatus))
    nNtStatus = QueryTokenInfo(hToken, TokenRestrictedSids, (LPVOID*)&cGroups);
  //errors?
  if (!NT_SUCCESS(nNtStatus))
  {
    NktNtClose(hToken);
    return nNtStatus;
  }
  //has none?
  if (cGroups->GroupCount == 0)
  {
    NktNtClose(hToken);
    return STATUS_SUCCESS;
  }
  //we need to create a restricted token, first get needed apis
  hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
  if (hNtDll == NULL)
  {
    NktNtClose(hToken);
    return STATUS_PROCEDURE_NOT_FOUND;
  }
  fnRtlCreateAcl = (lpfnRtlCreateAcl)NktHookLibHelpers::GetProcedureAddress(hNtDll, "RtlCreateAcl");
  fnRtlAddAccessAllowedAce = (lpfnRtlAddAccessAllowedAce)NktHookLibHelpers::GetProcedureAddress(hNtDll,
                                                                "RtlAddAccessAllowedAce");
  if (fnRtlCreateAcl == NULL || fnRtlAddAccessAllowedAce == NULL)
  {
    NktNtClose(hToken);
    return STATUS_PROCEDURE_NOT_FOUND;
  }
  //get integrity level
  if (sOvi.dwMajorVersion >= 6)
  {
    nNtStatus = GetTokenIntegrityLevel(hToken, &nLevel);
    if (!NT_SUCCESS(nNtStatus))
    {
      NktNtClose(hToken);
      return nNtStatus;
    }
  }
  NktNtClose(hToken);
  //get process token
  nNtStatus = NktNtOpenProcessToken(NKTHOOKLIB_CurrentProcess, TOKEN_ALL_ACCESS_P, &hToken);
  if (NT_SUCCESS(nNtStatus))
  {
    nNtStatus = MyCreateRestrictedToken(hToken, &hNewToken);
    if (NT_SUCCESS(nNtStatus))
    {
      NktNtClose(hToken);
      hToken = hNewToken;
    }
  }
  //get user
  if (NT_SUCCESS(nNtStatus))
    nNtStatus = QueryTokenInfo(hToken, TokenUser, (LPVOID*)&cUser);
  //create wellknown restricted SID and new ACEs
  if (NT_SUCCESS(nNtStatus))
  {
    NktHookLibHelpers::MemSet(&sSid, 0, sizeof(sSid));
    sSid.Revision = SID_REVISION;
    sSid.IdentifierAuthority.Value[5] = 5; //SECURITY_NT_AUTHORITY
    sSid.SubAuthorityCount = 1;
    sSid.SubAuthority[0] = SECURITY_RESTRICTED_CODE_RID;
    //----
    nSize = (ULONG)(sizeof(ACL) + 2 * sizeof(NKT_ACE));
    nSize += (ULONG)FIELD_OFFSET(SID, SubAuthority[sSid.SubAuthorityCount]);
    nSize += (ULONG)FIELD_OFFSET(SID, SubAuthority[((NKT_SID*)(cUser->User.Sid))->SubAuthorityCount]);
    //----
    cAcl.Attach((ACL*)NktHookLibHelpers::MemAlloc(nSize));
    if (cAcl == NULL)
      nNtStatus = STATUS_NO_MEMORY;
  }
  if (NT_SUCCESS(nNtStatus))
    nNtStatus = fnRtlCreateAcl(cAcl, (ULONG)nSize, ACL_REVISION);
  if (NT_SUCCESS(nNtStatus))
    nNtStatus = fnRtlAddAccessAllowedAce(cAcl, ACL_REVISION, GENERIC_ALL, (PSID)&sSid);
  if (NT_SUCCESS(nNtStatus))
    nNtStatus = fnRtlAddAccessAllowedAce(cAcl, ACL_REVISION, GENERIC_ALL, cUser->User.Sid);
  if (NT_SUCCESS(nNtStatus))
  {
    sNewDefDacl.DefaultDacl = cAcl;
    nNtStatus = NktNtSetInformationToken(hToken, TokenDefaultDacl, &sNewDefDacl, sizeof(sNewDefDacl));
  }
  //set token's integrity level
  if (NT_SUCCESS(nNtStatus) && sOvi.dwMajorVersion >= 6)
    nNtStatus = SetTokenIntegrityLevel(hToken, nLevel);
  //duplicate token for impersonation
  if (NT_SUCCESS(nNtStatus))
  {
    NktHookLibHelpers::MemSet(&sSqos, 0, sizeof(sSqos));
    sSqos.Length = (DWORD)sizeof(SECURITY_QUALITY_OF_SERVICE);
    sSqos.ImpersonationLevel = SecurityImpersonation;
    NktHookLibHelpers::MemSet(&sObjAttr, 0, sizeof(sObjAttr));
    sObjAttr.Length = (ULONG)sizeof(sObjAttr);
    sObjAttr.SecurityQualityOfService = &sSqos;
    nNtStatus = NktNtDuplicateToken(hToken, TOKEN_IMPERSONATE|TOKEN_QUERY, &sObjAttr, FALSE, TokenImpersonation,
                                    &hNewToken);
    if (NT_SUCCESS(nNtStatus))
    {
      NktNtClose(hToken);
      hToken = hNewToken;
    }
  }
  //done
  if (NT_SUCCESS(nNtStatus))
    *lphThreadToken = hToken;
  else
    NktNtClose(hToken);
  return nNtStatus;
}

static NTSTATUS MyCreateRestrictedToken(__in HANDLE hToken, __out HANDLE *lphRestrictedToken)
{
  typedef NTSTATUS (NTAPI *lpfnNtFilterToken)(__in HANDLE ExistingTokenHandle, __in ULONG Flags,
                                              __in_opt PTOKEN_GROUPS SidsToDisable,
                                              __in_opt PTOKEN_PRIVILEGES PrivilegesToDelete,
                                              __in_opt PTOKEN_GROUPS RestrictedSids, __out PHANDLE NewTokenHandle);
  HINSTANCE hNtDll;
  lpfnNtFilterToken fnNtFilterToken;
  TNktAutoFreePtr<TOKEN_USER> cUser;
  TNktAutoFreePtr<TOKEN_GROUPS> cGroups, cRestricted;
  DWORD i, k;
  NTSTATUS nNtStatus;

  *lphRestrictedToken = NULL;
  //get needed apis
  hNtDll = NktHookLibHelpers::GetModuleBaseAddress(L"ntdll.dll");
  if (hNtDll == NULL)
    return STATUS_PROCEDURE_NOT_FOUND;
  fnNtFilterToken = (lpfnNtFilterToken)NktHookLibHelpers::GetProcedureAddress(hNtDll, "NtFilterToken");
  if (fnNtFilterToken == NULL)
    return STATUS_PROCEDURE_NOT_FOUND;
  //first get the restricting SIDs
  //get token user
  nNtStatus = QueryTokenInfo(hToken, TokenUser, (LPVOID*)&cUser);
  //get token groups
  if (NT_SUCCESS(nNtStatus))
    nNtStatus = QueryTokenInfo(hToken, TokenGroups, (LPVOID*)&cGroups);
  //count and allocate for sid & attributes
  if (NT_SUCCESS(nNtStatus))
  {
    for (i=k=0; i<cGroups->GroupCount; i++)
    {
      if ((cGroups->Groups[i].Attributes & SE_GROUP_INTEGRITY) == 0)
        k++;
    }
    cRestricted.Attach((PTOKEN_GROUPS)NktHookLibHelpers::MemAlloc(sizeof(DWORD)+(k+1)*sizeof(SID_AND_ATTRIBUTES)));
    if (cRestricted == NULL)
      return STATUS_NO_MEMORY;
  }
  if (NT_SUCCESS(nNtStatus))
  {
    cRestricted->GroupCount = k + 1;
    cRestricted->Groups[0].Attributes = 0;
    cRestricted->Groups[0].Sid = cUser->User.Sid;
    for (i=k=0; i<cGroups->GroupCount; i++)
    {
      if ((cGroups->Groups[i].Attributes & SE_GROUP_INTEGRITY) == 0)
      {
        k++;
        cRestricted->Groups[k].Attributes = 0;
        cRestricted->Groups[k].Sid = cGroups->Groups[i].Sid;
      }
    }
    //----
    nNtStatus = fnNtFilterToken(hToken, SANDBOX_INERT, NULL, NULL, cRestricted.Get(), lphRestrictedToken);
  }
  return nNtStatus;
}

static NTSTATUS SetTokenIntegrityLevel(__in HANDLE hToken, __in MANDATORY_LEVEL nLevel)
{
  NKT_SID sSid;
  TOKEN_MANDATORY_LABEL sLabel;
  ULONG nSize;

  NktHookLibHelpers::MemSet(&sLabel, 0, sizeof(sLabel));
  sLabel.Label.Attributes = SE_GROUP_INTEGRITY;
  sLabel.Label.Sid = (SID*)&sSid;
  NktHookLibHelpers::MemSet(&sSid, 0, sizeof(sSid));
  sSid.Revision = SID_REVISION;
  sSid.IdentifierAuthority.Value[5] = 16; //SECURITY_MANDATORY_LABEL_AUTHORITY
  sSid.SubAuthorityCount = 1;
  switch (nLevel)
  {
    case MandatoryLevelSecureProcess:
      sSid.SubAuthority[0] = SECURITY_MANDATORY_SYSTEM_RID;
      break;
    case MandatoryLevelSystem:
      sSid.SubAuthority[0] = SECURITY_MANDATORY_SYSTEM_RID;
      break;
    case MandatoryLevelHigh:
      sSid.SubAuthority[0] = SECURITY_MANDATORY_HIGH_RID;
      break;
    case MandatoryLevelMedium:
      sSid.SubAuthority[0] = SECURITY_MANDATORY_MEDIUM_RID;
      break;
    case MandatoryLevelLow:
      sSid.SubAuthority[0] = SECURITY_MANDATORY_LOW_RID;
      break;
    case MandatoryLevelUntrusted:
      sSid.SubAuthority[0] = SECURITY_MANDATORY_UNTRUSTED_RID;
      break;
    default:
      return STATUS_INVALID_PARAMETER;
  }
  nSize = (ULONG)sizeof(TOKEN_MANDATORY_LABEL) + (ULONG)FIELD_OFFSET(SID, SubAuthority[sSid.SubAuthorityCount]);
  return NktNtSetInformationToken(hToken, TokenIntegrityLevel, &sLabel, nSize);
}

static NTSTATUS GetTokenIntegrityLevel(__in HANDLE hToken, __out MANDATORY_LEVEL *lpnLevel)
{
  TNktAutoFreePtr<TOKEN_MANDATORY_LABEL> cIntegrityLevel;
  NKT_SID *lpSid;
  DWORD dwIntegrityLevel;
  NTSTATUS nNtStatus;

  *lpnLevel = MandatoryLevelUntrusted;
  //query for restricted sids
  nNtStatus = QueryTokenInfo(hToken, TokenIntegrityLevel, (LPVOID*)&cIntegrityLevel);
  if (NT_SUCCESS(nNtStatus))
  {
    lpSid = (NKT_SID*)(cIntegrityLevel->Label.Sid);
    dwIntegrityLevel = lpSid->SubAuthority[lpSid->SubAuthorityCount - 1];
    if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID)
      *lpnLevel = MandatoryLevelUntrusted;
    else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
      *lpnLevel = MandatoryLevelLow;
    else if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
      *lpnLevel = MandatoryLevelMedium;
    else if (dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
      *lpnLevel = MandatoryLevelHigh;
    else if (dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
      *lpnLevel = MandatoryLevelSystem;
    else
      *lpnLevel = MandatoryLevelSecureProcess;
  }
  return nNtStatus;
}

static NTSTATUS QueryTokenInfo(__in HANDLE hToken, __in TOKEN_INFORMATION_CLASS nClass, __out LPVOID *lplpInfo)
{
  TNktAutoFreePtr<BYTE> cBuf;
  ULONG nRetLength;
  NTSTATUS nNtStatus;

  *lplpInfo = NULL;
  nNtStatus = NktNtQueryInformationToken(hToken, nClass, NULL, 0, &nRetLength);
  while (nNtStatus == STATUS_BUFFER_TOO_SMALL)
  {
    cBuf.Attach((LPBYTE)NktHookLibHelpers::MemAlloc((SIZE_T)nRetLength));
    if (cBuf == NULL)
      return STATUS_NO_MEMORY;
    nNtStatus = NktNtQueryInformationToken(hToken, nClass, cBuf.Get(), nRetLength, &nRetLength);
  }
  if (NT_SUCCESS(nNtStatus))
    *lplpInfo = cBuf.Detach();
  return nNtStatus;
}

static NTSTATUS GetPrimaryThread(__in HANDLE hProcess, __out HANDLE *lphThread)
{
  TNktAutoFreePtr<NKT_HK_SYSTEM_PROCESS_INFORMATION> cBuf;
  PROCESS_BASIC_INFORMATION sPbi;
  SIZE_T nSize, nMethod;
  DWORD dwTid;
  LPNKT_HK_SYSTEM_PROCESS_INFORMATION lpCurrProc;
  ULONG nRetLength;
  NTSTATUS nNtStatus;

  nNtStatus = NktNtQueryInformationProcess(hProcess, ProcessBasicInformation, &sPbi, (ULONG)sizeof(sPbi), NULL);
  if (!NT_SUCCESS(nNtStatus))
    return NktRtlNtStatusToDosError(nNtStatus);
  nNtStatus = STATUS_NOT_FOUND;
  for (nMethod=0; nMethod<2; nMethod++)
  {
    nNtStatus = NktNtQuerySystemInformation((nMethod == 0) ? (SYSTEM_INFORMATION_CLASS)MySystemProcessInformation :
                                            (SYSTEM_INFORMATION_CLASS)MySystemExtendedProcessInformation,
                                            NULL, 0, &nRetLength);
    while (nNtStatus == STATUS_INFO_LENGTH_MISMATCH || nNtStatus == STATUS_BUFFER_TOO_SMALL)
    {
      cBuf.Attach((LPNKT_HK_SYSTEM_PROCESS_INFORMATION)NktHookLibHelpers::MemAlloc((SIZE_T)nRetLength));
      if (cBuf == NULL)
        return STATUS_NO_MEMORY;
      nNtStatus = NktNtQuerySystemInformation((nMethod == 0) ? (SYSTEM_INFORMATION_CLASS)MySystemProcessInformation :
                                              (SYSTEM_INFORMATION_CLASS)MySystemExtendedProcessInformation,
                                              cBuf.Get(), nRetLength, &nRetLength);
      if ((nNtStatus == STATUS_INFO_LENGTH_MISMATCH || nNtStatus == STATUS_BUFFER_TOO_SMALL) &&
          nRetLength == 0)
        nNtStatus = STATUS_NOT_FOUND;
    }
    if (NT_SUCCESS(nNtStatus))
      break;
  }
  if (nMethod >= 2)
    return nNtStatus;
  //find process
  lpCurrProc = cBuf.Get();
  nSize = (SIZE_T)FIELD_OFFSET(NKT_HK_SYSTEM_PROCESS_INFORMATION, Threads);
  nSize += (nMethod == 0) ? sizeof(NKT_HK_SYSTEM_THREAD_INFORMATION) :
                            sizeof(NKT_HK_SYSTEM_EXTENDED_THREAD_INFORMATION);
  while ((SIZE_T)lpCurrProc + nSize - (SIZE_T)cBuf.Get() <= (SIZE_T)nRetLength)
  {
    if ((DWORD)((ULONG_PTR)(lpCurrProc->UniqueProcessId)) == (DWORD)((ULONG_PTR)(sPbi.UniqueProcessId)))
    {
      if (lpCurrProc->NumberOfThreads == 0)
        break;
      dwTid = (nMethod == 0) ? (DWORD)(lpCurrProc->Threads[0].ClientId.UniqueThread) :
                               (DWORD)(lpCurrProc->ExtThreads[0].ThreadInfo.ClientId.UniqueThread);
      *lphThread = NktHookLibHelpers::OpenThread(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | THREAD_TERMINATE |
                                                 THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                                 THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION |
                                                 THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE |
                                                 THREAD_DIRECT_IMPERSONATION, FALSE, dwTid);
      return ((*lphThread) != NULL) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }
    if (lpCurrProc->NextEntryOffset == 0)
      break;
    lpCurrProc = (LPNKT_HK_SYSTEM_PROCESS_INFORMATION)((LPBYTE)lpCurrProc + (SIZE_T)(lpCurrProc->NextEntryOffset));
  }
  //process not found
  return STATUS_NOT_FOUND;
}
