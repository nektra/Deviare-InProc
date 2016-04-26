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
#include "LinkedList.h"
#include "WaitableObjects.h"
#include "ThreadSuspend.h"
#include "HookEntry.h"
#include "NtHeapBaseObj.h"
#include <intrin.h>

using namespace NktHookLib::Internals;
using namespace NktHookLibHelpers;

//-----------------------------------------------------------

#define MAX_SUSPEND_IPRANGES                              10

#define MemoryBasicInformation                             0

#define X_ARRAYLEN(x)               (sizeof(x)/sizeof(x[0]))

#if defined(_M_X64) || defined(_M_IA64) || defined(_M_AMD64)
  #define NKT_UNALIGNED __unaligned
#else
  #define NKT_UNALIGNED
#endif

//(4096 bytes - 256 bytes of code) / 20 bytes per ministub = 160
#define RETMINISTUBS_COUNT_X86                           160

//(4096 bytes - 256 bytes of code) / 28 bytes per ministub = 137
#define RETMINISTUBS_COUNT_X64                           137

#define VALID_FLAGS (NKTHOOKLIB_DontSkipInitialJumps | NKTHOOKLIB_DontRemoveOnUnhook |     \
                     NKTHOOKLIB_DontSkipAnyJumps | NKTHOOKLIB_SkipNullProcsToHook |        \
                     NKTHOOKLIB_UseAbsoluteIndirectJumps | NKTHOOKLIB_DisallowReentrancy | \
                     NKTHOOKLIB_DontEnableHooks)

#define INTERNALFLAG_CallToOriginalIsPtr2Ptr      0x80000000

#define FlagOn(x, _flag) ((x) & (_flag))

//-----------------------------------------------------------

static DWORD GetProcessIdFromHandle(__in HANDLE hProc);

//-----------------------------------------------------------

namespace NktHookLib {
namespace Internals {

class CInternals : public CNktNtHeapBaseObj
{
public:
  CInternals()
    {
    sOptions.bSuspendThreads = TRUE;
#ifdef _DEBUG
    sOptions.bOutputDebug = TRUE;
#else _DEBUG
    sOptions.bOutputDebug = FALSE;
#endif //_DEBUG
    return;
    };

private:
  friend class CNktHookLib;

  TNktLnkLst<CHookEntry> cHooksList;
  CNktThreadSuspend cThreadSuspender;
  CNktFastMutex cMtx;
  CProcessesHandles cProcHdrMgr;
  struct {
    BOOL bSuspendThreads;
    BOOL bOutputDebug;
    BOOL bSkipJumps;
  } sOptions;
};

} //Internals
} //NktHookLib

#define int_data           ((CInternals*)lpInternals)

//-----------------------------------------------------------

CNktHookLib::CNktHookLib()
{
  lpInternals = new CInternals();
  return;
}

CNktHookLib::~CNktHookLib()
{
  if (lpInternals != NULL)
  {
    UnhookAll();
    delete int_data;
    lpInternals = NULL;
  }
  return;
}

DWORD CNktHookLib::Hook(__out SIZE_T *lpnHookId, __out LPVOID *lplpCallOriginal, __in LPVOID lpProcToHook,
                        __in LPVOID lpNewProcAddr, __in DWORD dwFlags)
{
  HOOK_INFO sHook;
  DWORD dwOsErr;

  if (lpnHookId != NULL)
    *lpnHookId = 0;
  if (lplpCallOriginal != NULL)
    *lplpCallOriginal = NULL;
  if (lpnHookId == NULL || lplpCallOriginal == NULL)
    return ERROR_INVALID_PARAMETER;
  sHook.lpProcToHook = lpProcToHook;
  sHook.lpNewProcAddr = lpNewProcAddr;
  sHook.lpCallOriginal = (LPVOID)lplpCallOriginal;
  dwOsErr = HookCommon(&sHook, 1, NktHookLibHelpers::GetCurrentProcessId(),
                       (dwFlags & VALID_FLAGS) | INTERNALFLAG_CallToOriginalIsPtr2Ptr);
  if (dwOsErr == ERROR_SUCCESS)
  {
    *lpnHookId = sHook.nHookId;
  }
  return dwOsErr;
}

DWORD CNktHookLib::Hook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in DWORD dwFlags)
{
  return HookCommon(aHookInfo, nCount, NktHookLibHelpers::GetCurrentProcessId(), dwFlags & VALID_FLAGS);
}

DWORD CNktHookLib::RemoteHook(__out SIZE_T *lpnHookId, __out LPVOID *lplpCallOriginal, __in DWORD dwPid,
                              __in LPVOID lpProcToHook, __in LPVOID lpNewProcAddr, __in DWORD dwFlags)
{
  HOOK_INFO sHook;
  DWORD dwOsErr;

  if (lpnHookId != NULL)
    *lpnHookId = 0;
  if (lplpCallOriginal != NULL)
    *lplpCallOriginal = NULL;
  if (lpnHookId == NULL || lplpCallOriginal == NULL)
    return ERROR_INVALID_PARAMETER;
  sHook.lpProcToHook = lpProcToHook;
  sHook.lpNewProcAddr = lpNewProcAddr;
  sHook.lpCallOriginal = (LPVOID)lplpCallOriginal;
  dwOsErr = HookCommon(&sHook, 1, dwPid, (dwFlags & VALID_FLAGS) | INTERNALFLAG_CallToOriginalIsPtr2Ptr);
  if (dwOsErr == ERROR_SUCCESS)
    *lpnHookId = sHook.nHookId;
  return dwOsErr;
}

DWORD CNktHookLib::RemoteHook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in DWORD dwPid, __in DWORD dwFlags)
{
  return HookCommon(aHookInfo, nCount, dwPid, dwFlags & VALID_FLAGS);
}

DWORD CNktHookLib::RemoteHook(__out SIZE_T *lpnHookId, __out LPVOID *lplpCallOriginal, __in HANDLE hProcess,
                              __in LPVOID lpProcToHook, __in LPVOID lpNewProcAddr, __in DWORD dwFlags)
{
  HOOK_INFO sHook;
  DWORD dwOsErr, dwPid;

  if (lpnHookId != NULL)
    *lpnHookId = 0;
  if (lplpCallOriginal != NULL)
    *lplpCallOriginal = NULL;
  if (lpnHookId == NULL || lplpCallOriginal == NULL || hProcess == NULL)
    return ERROR_INVALID_PARAMETER;
  dwPid = GetProcessIdFromHandle(hProcess);
  if (dwPid == 0)
    return ERROR_INVALID_PARAMETER;
  sHook.lpProcToHook = lpProcToHook;
  sHook.lpNewProcAddr = lpNewProcAddr;
  sHook.lpCallOriginal = (LPVOID)lplpCallOriginal;
  dwOsErr = HookCommon(&sHook, 1, dwPid, (dwFlags & VALID_FLAGS) | INTERNALFLAG_CallToOriginalIsPtr2Ptr);
  if (dwOsErr == ERROR_SUCCESS)
    *lpnHookId = sHook.nHookId;
  return dwOsErr;
}

DWORD CNktHookLib::RemoteHook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in HANDLE hProcess,
                              __in DWORD dwFlags)
{
  DWORD dwPid;
  SIZE_T nHookIdx;

  dwPid = GetProcessIdFromHandle(hProcess);
  if (dwPid == 0)
  {
    for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
    {
      aHookInfo[nHookIdx].nHookId = 0;
      if (aHookInfo[nHookIdx].lpCallOriginal != NULL)
        aHookInfo[nHookIdx].lpCallOriginal = NULL;
    }
    return ERROR_INVALID_PARAMETER;
  }
  return HookCommon(aHookInfo, nCount, dwPid, dwFlags & VALID_FLAGS);
}

DWORD CNktHookLib::Unhook(__in SIZE_T nHookId)
{
  HOOK_INFO sHook;

  sHook.nHookId = nHookId;
  return Unhook(&sHook, 1);
}

DWORD CNktHookLib::Unhook(__in HOOK_INFO aHookInfo[], __in SIZE_T nCount)
{
  TNktLnkLst<CHookEntry> cToDeleteList;
  CHookEntry *lpHookEntry;

  if (aHookInfo == NULL || nCount == 0)
    return ERROR_INVALID_PARAMETER;
  if (lpInternals != NULL)
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    CNktThreadSuspend::CAutoResume cAutoResume(&(int_data->cThreadSuspender));
    CNktThreadSuspend::IP_RANGE sIpRange[2];
    TNktLnkLst<CHookEntry>::Iterator it;
    BYTE aTempBuf[8], *p;
    SIZE_T nSize, nHookIdx, nIpRangesCount;
    DWORD dw, dwOsErr, dwCurrPid;
    BOOL bOk;
    NTSTATUS nNtStatus;

    dwCurrPid = NktHookLibHelpers::GetCurrentProcessId();
    for (nHookIdx=nIpRangesCount=0; nHookIdx<nCount; nHookIdx++)
    {
      if (aHookInfo[nHookIdx].nHookId == 0)
        continue; //avoid transversing hook entry list
      for (lpHookEntry=it.Begin(int_data->cHooksList); lpHookEntry!=NULL; lpHookEntry=it.Next())
      {
        if (lpHookEntry->nId == aHookInfo[nHookIdx].nHookId)
          break;
      }
      if (lpHookEntry == NULL)
        continue; //hook not found
      //mark the hook as uninstalled
      if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DontRemoveOnUnhook))
      {
        bOk = FALSE;
      }
      else
      {
        if (lpHookEntry->cProcEntry->GetPid() != dwCurrPid)
        {
          BYTE nVal = 1;
          WriteMem(lpHookEntry->cProcEntry, lpHookEntry->lpInjCodeAndData, &nVal, 1);
        }
        else
        {
          _InterlockedOr((LONG volatile *)(lpHookEntry->lpInjCodeAndData), 0x00000001);
        }
        if (lpHookEntry->nInstalledCode != 3)
          lpHookEntry->nInstalledCode = 2;
        //suspend threads if needed
        dwOsErr = ERROR_SUCCESS;
        if (int_data->sOptions.bSuspendThreads != FALSE)
        {
          //set-up ranges
          sIpRange[0].nStart = (SIZE_T)(lpHookEntry->lpOrigProc);
          sIpRange[0].nEnd = sIpRange[0].nStart + 5;
          sIpRange[1].nStart = (SIZE_T)(lpHookEntry->lpInjCodeAndData);
          sIpRange[1].nEnd = sIpRange[1].nStart + lpHookEntry->nInjCodeAndDataSize;
          if (nIpRangesCount > 0)
          {
            //check if a previous thread suspension can be used for the current unhook item
            if (int_data->cThreadSuspender.CheckIfThreadIsInRange(sIpRange[0].nStart, sIpRange[0].nEnd) != FALSE ||
                int_data->cThreadSuspender.CheckIfThreadIsInRange(sIpRange[1].nStart, sIpRange[1].nEnd) != FALSE)
            {
              nIpRangesCount = 0;
              int_data->cThreadSuspender.ResumeAll(); //resume last
            }
          }
          //suspend threads
          if (nIpRangesCount == 0)
          {
            nIpRangesCount = X_ARRAYLEN(sIpRange);
            dwOsErr = int_data->cThreadSuspender.SuspendAll(lpHookEntry->cProcEntry->GetPid(), sIpRange, nIpRangesCount);
          }
        }
        //do unhook
        bOk = FALSE;
        if (dwOsErr == ERROR_SUCCESS)
        {
          p = lpHookEntry->lpOrigProc;
          nSize = lpHookEntry->nOriginalStubSize;
          dw = 0;
          nNtStatus = NktNtProtectVirtualMemory(lpHookEntry->cProcEntry->GetHandle(), (PVOID*)&p, &nSize,
                                                PAGE_EXECUTE_READWRITE, &dw);
          if (!NT_SUCCESS(nNtStatus))
          {
            p = lpHookEntry->lpOrigProc;
            nSize = lpHookEntry->nOriginalStubSize;
            dw = 0;
            nNtStatus = NktNtProtectVirtualMemory(lpHookEntry->cProcEntry->GetHandle(), (PVOID*)&p, &nSize,
                                                  PAGE_EXECUTE_WRITECOPY, &dw);
          }
          if (NT_SUCCESS(nNtStatus))
          {
            if (ReadMem(lpHookEntry->cProcEntry->GetHandle(), aTempBuf, lpHookEntry->lpOrigProc,
                        lpHookEntry->GetJumpToHookBytes()) == lpHookEntry->GetJumpToHookBytes() &&
                MemCompare(aTempBuf, lpHookEntry->aJumpStub, lpHookEntry->GetJumpToHookBytes()) == 0)
            {
              bOk = WriteMem(lpHookEntry->cProcEntry->GetHandle(), lpHookEntry->lpOrigProc,
                             lpHookEntry->aOriginalStub, lpHookEntry->nOriginalStubSize);
            }
            p = lpHookEntry->lpOrigProc;
            nSize = lpHookEntry->nOriginalStubSize;
            NktNtProtectVirtualMemory(lpHookEntry->cProcEntry->GetHandle(), (PVOID*)&p, &nSize, dw, &dw);
            NktNtFlushInstructionCache(lpHookEntry->cProcEntry->GetHandle(), lpHookEntry->lpOrigProc, 32);
          }
        }
      }
      //check result
      if (bOk == FALSE)
      {
        //if cannot release original blocks, mark them as uninstalled
        lpHookEntry->lpInjCodeAndData = NULL;
      }
      //delete entry
      int_data->cHooksList.Remove(lpHookEntry);
      cToDeleteList.PushTail(lpHookEntry);
    }
  }
  //delete when no threads are suspended to avoid deadlocks
  while ((lpHookEntry = cToDeleteList.PopHead()) != NULL)
    delete lpHookEntry;
  return ERROR_SUCCESS;
}

VOID CNktHookLib::UnhookProcess(__in DWORD dwPid)
{
  if (lpInternals != NULL)
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    TNktLnkLst<CHookEntry>::Iterator it;
    CHookEntry *lpHookEntry;
    HOOK_INFO sHooks[256];
    SIZE_T nCount;

    if (dwPid == 0)
      dwPid = NktHookLibHelpers::GetCurrentProcessId();
    do
    {
      nCount = 0;
      for (lpHookEntry=it.Begin(int_data->cHooksList); lpHookEntry!=NULL && nCount<X_ARRAYLEN(sHooks);
           lpHookEntry=it.Next())
      {
        if (lpHookEntry->cProcEntry->GetPid() == dwPid)
          sHooks[nCount++].nHookId = lpHookEntry->nId;
      }
      if (nCount > 0)
        Unhook(sHooks, nCount);
    }
    while (nCount > 0);
  }
  return;
}

VOID CNktHookLib::UnhookAll()
{
  if (lpInternals != NULL)
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    TNktLnkLst<CHookEntry>::Iterator it;
    TNktLnkLst<CHookEntry>::IteratorRev itRev;
    CHookEntry *lpHookEntry;
    HOOK_INFO sHooks[256];
    DWORD dwCurrPid;
    SIZE_T nCount;

    //mark all hooks as uninstalled first
    dwCurrPid = NktHookLibHelpers::GetCurrentProcessId();
    for (lpHookEntry=it.Begin(int_data->cHooksList); lpHookEntry!=NULL; lpHookEntry=it.Next())
    {
      if (lpHookEntry->cProcEntry->GetPid() != dwCurrPid)
      {
        BYTE nVal = 1;
        NktHookLibHelpers::WriteMem(lpHookEntry->cProcEntry, lpHookEntry->lpInjCodeAndData, &nVal, 1);
      }
      else
      {
        _InterlockedOr((LONG volatile *)(lpHookEntry->lpInjCodeAndData), 0x00000001);
      }
      lpHookEntry->nInstalledCode = 3;
    }
    //unhook in reverse order
    while (int_data->cHooksList.IsEmpty() == FALSE)
    {
      for (nCount=0,lpHookEntry=itRev.Begin(int_data->cHooksList); lpHookEntry!=NULL && nCount<X_ARRAYLEN(sHooks);
           lpHookEntry=itRev.Next())
        sHooks[nCount++].nHookId = lpHookEntry->nId;
      if (nCount > 0)
        Unhook(sHooks, nCount);
    }
  }
  return;
}

DWORD CNktHookLib::RemoveHook(__in SIZE_T nHookId, BOOL bDisable)
{
  HOOK_INFO sHook;

  sHook.nHookId = nHookId;
  return RemoveHook(&sHook, 1, bDisable);
}

DWORD CNktHookLib::RemoveHook(__in HOOK_INFO aHookInfo[], __in SIZE_T nCount, BOOL bDisable)
{
  TNktLnkLst<CHookEntry> cToDeleteList;
  CHookEntry *lpHookEntry;

  if (aHookInfo == NULL || nCount == 0)
    return ERROR_INVALID_PARAMETER;
  if (lpInternals == NULL)
    return ERROR_NOT_ENOUGH_MEMORY;
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    TNktLnkLst<CHookEntry>::Iterator it;
    DWORD dwCurrPid;
    SIZE_T nHookIdx;

    //write flags
    dwCurrPid = NktHookLibHelpers::GetCurrentProcessId();
    for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
    {
      if (aHookInfo[nHookIdx].nHookId == 0)
        continue; //avoid transversing hook entry list
      for (lpHookEntry=it.Begin(int_data->cHooksList); lpHookEntry!=NULL; lpHookEntry=it.Next())
      {
        if (lpHookEntry->nId == aHookInfo[nHookIdx].nHookId)
        {
          if (bDisable != FALSE)
          {
            if (lpHookEntry->cProcEntry->GetPid() != dwCurrPid)
            {
              BYTE nVal = 1;
              NktHookLibHelpers::WriteMem(lpHookEntry->cProcEntry, lpHookEntry->lpInjCodeAndData+1, &nVal, 1);
            }
            else
            {
              _InterlockedOr((LONG volatile *)(lpHookEntry->lpInjCodeAndData), 0x00000100);
            }
          }
          //mark entry as uninstalled
          lpHookEntry->lpInjCodeAndData = NULL;
          //delete entry
          int_data->cHooksList.Remove(lpHookEntry);
          cToDeleteList.PushTail(lpHookEntry);
          break;
        }
      }
    }
  }
  //delete when no threads are suspended to avoid deadlocks
  while ((lpHookEntry = cToDeleteList.PopHead()) != NULL)
    delete lpHookEntry;
  return ERROR_SUCCESS;
}

DWORD CNktHookLib::EnableHook(__in SIZE_T nHookId, __in BOOL bEnable)
{
  HOOK_INFO sHook;

  sHook.nHookId = nHookId;
  return EnableHook(&sHook, 1, bEnable);
}

DWORD CNktHookLib::EnableHook(__in HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in BOOL bEnable)
{
  if (aHookInfo == NULL || nCount == 0)
    return ERROR_INVALID_PARAMETER;
  if (lpInternals == NULL)
    return ERROR_NOT_ENOUGH_MEMORY;
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    TNktLnkLst<CHookEntry>::Iterator it;
    CHookEntry *lpHookEntry;
    DWORD dwCurrPid;
    SIZE_T nHookIdx;

    //write flags
    dwCurrPid = NktHookLibHelpers::GetCurrentProcessId();
    for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
    {
      if (aHookInfo[nHookIdx].nHookId == 0)
        continue; //avoid transversing hook entry list
      for (lpHookEntry=it.Begin(int_data->cHooksList); lpHookEntry!=NULL; lpHookEntry=it.Next())
      {
        if (lpHookEntry->nId == aHookInfo[nHookIdx].nHookId)
        {
          if (lpHookEntry->cProcEntry->GetPid() != dwCurrPid)
          {
            BYTE nVal = (bEnable != FALSE) ? 0 : 1;
            NktHookLibHelpers::WriteMem(lpHookEntry->cProcEntry, lpHookEntry->lpInjCodeAndData+1, &nVal, 1);
          }
          else
          {
            if (bEnable != FALSE)
              _InterlockedAnd((LONG volatile *)(lpHookEntry->lpInjCodeAndData), 0xFFFF00FF);
            else
              _InterlockedOr((LONG volatile *)(lpHookEntry->lpInjCodeAndData), 0x00000100);
          }
          break;
        }
      }
    }
  }
  return ERROR_SUCCESS;
}

DWORD CNktHookLib::SetSuspendThreadsWhileHooking(__in BOOL bEnable)
{
  if (lpInternals == NULL)
    return ERROR_NOT_ENOUGH_MEMORY;
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

    int_data->sOptions.bSuspendThreads = bEnable;
  }
  return ERROR_SUCCESS;
}

BOOL CNktHookLib::GetSuspendThreadsWhileHooking()
{
  BOOL b;

  b = TRUE;
  if (lpInternals != NULL)
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

    b = int_data->sOptions.bSuspendThreads;
  }
  return b;
}

DWORD CNktHookLib::SetEnableDebugOutput(__in BOOL bEnable)
{
  if (lpInternals == NULL)
    return ERROR_NOT_ENOUGH_MEMORY;
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

    int_data->sOptions.bOutputDebug = bEnable;
  }
  return ERROR_SUCCESS;
}

BOOL CNktHookLib::GetEnableDebugOutput()
{
  BOOL b;

  b = TRUE;
  if (lpInternals != NULL)
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

    b = int_data->sOptions.bOutputDebug;
  }
  return b;
}

void* __cdecl CNktHookLib::operator new(__in size_t nSize)
{
  return NktHookLibHelpers::MemAlloc(nSize);
};

void* __cdecl CNktHookLib::operator new[](__in size_t nSize)
{
  return NktHookLibHelpers::MemAlloc(nSize);
};

void* __cdecl CNktHookLib::operator new(__in size_t nSize, __inout void* lpInPlace)
{
  return lpInPlace;
};

void __cdecl CNktHookLib::operator delete(__inout void* p)
{
  NktHookLibHelpers::MemFree(p);
  return;
};
void __cdecl CNktHookLib::operator delete[](__inout void* p)
{
  NktHookLibHelpers::MemFree(p);
  return;
};
#if _MSC_VER >= 1200
void __cdecl CNktHookLib::operator delete(__inout void* p, __inout void* lpPlace)
{
  return;
};
#endif //_MSC_VER >= 1200

DWORD CNktHookLib::HookCommon(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in DWORD dwPid, __in DWORD dwFlags)
{
  DWORD dwOsErr;
  SIZE_T nHookIdx;
  BOOL bIsRemoteProcess;

  if (aHookInfo == NULL || nCount == 0 || dwPid == 0)
    return ERROR_INVALID_PARAMETER;
  for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
  {
    aHookInfo[nHookIdx].nHookId = 0;
    if (FlagOn(dwFlags, INTERNALFLAG_CallToOriginalIsPtr2Ptr))
    {
      if (aHookInfo[nHookIdx].lpCallOriginal != NULL)
        *((LPVOID*)aHookInfo[nHookIdx].lpCallOriginal) = NULL;
    }
    else
    {
      aHookInfo[nHookIdx].lpCallOriginal = NULL;
    }
  }
  for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
  {
    if (aHookInfo[nHookIdx].lpProcToHook == NULL)
    {
      if (FlagOn(dwFlags, NKTHOOKLIB_SkipNullProcsToHook))
        return ERROR_INVALID_PARAMETER;
    }
    else
    {
      if (aHookInfo[nHookIdx].lpNewProcAddr == NULL)
        return ERROR_INVALID_PARAMETER;
    }
  }
  bIsRemoteProcess = (dwPid != NktHookLibHelpers::GetCurrentProcessId()) ? TRUE : FALSE;
  if (lpInternals != NULL)
  {
    CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    CProcessesHandles::CEntryPtr cProcEntry;
    TNktLnkLst<CHookEntry> cNewHooksList;
    CHookEntry *lpHookEntry, *lpFirstHookEntryInRound;
    SIZE_T i, k, nSize, nThisRound, nSizeOfSizeT;
    BYTE aCodeBlock[256], *p, *lpRetStubs[2], *lpCallOrigOfs[2];
    DWORD dw;
    NTSTATUS nNtStatus;

    //get process handle
    cProcEntry.Attach(int_data->cProcHdrMgr.Get(dwPid));
    if (cProcEntry == NULL)
      return ERROR_ACCESS_DENIED;
    //process items
    nHookIdx = 0;
    dwOsErr = ERROR_SUCCESS;
    while (nHookIdx < nCount && dwOsErr == ERROR_SUCCESS)
    {
      //skip items with lpProcToHook == NULL
      if (aHookInfo[nHookIdx].lpProcToHook == NULL)
      {
        nHookIdx++;
        continue;
      }
      //count items for this round stopping when we find a proc to hook in conflict (two or more hooks on the
      //same address)
      nThisRound = 1;
      while (nHookIdx+nThisRound < nCount &&
             aHookInfo[nHookIdx+nThisRound].lpProcToHook != aHookInfo[nHookIdx].lpProcToHook &&
             aHookInfo[nHookIdx+nThisRound].lpProcToHook != NULL)
             nThisRound++;
      //process
      lpFirstHookEntryInRound = NULL;
      for (k=0; k<nThisRound; k++)
      {
        //create new entries
        lpHookEntry = new CHookEntry(cProcEntry, dwFlags);
        if (lpHookEntry == NULL)
        {
          dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
          break;
        }
        if (lpFirstHookEntryInRound == NULL)
          lpFirstHookEntryInRound = lpHookEntry;
        //add to the new hooks list
        cNewHooksList.PushTail(lpHookEntry);
        //calculate real proc to hook
        lpHookEntry->lpOrigProc = (LPBYTE)(aHookInfo[nHookIdx+k].lpProcToHook);
        if (!FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DontSkipInitialJumps))
        {
          lpHookEntry->lpOrigProc = lpHookEntry->SkipJumpInstructions(lpHookEntry->lpOrigProc);
          if (lpHookEntry->lpOrigProc == NULL)
          {
            dwOsErr = ERROR_ACCESS_DENIED;
            break;
          }
        }
        lpHookEntry->lpNewProc = (LPBYTE)(aHookInfo[nHookIdx+k].lpNewProcAddr);
        //read original stub and create new one
        dwOsErr = lpHookEntry->CreateStub(int_data->sOptions.bOutputDebug);
        if (dwOsErr != ERROR_SUCCESS)
          break;
        //allocate memory for inject code in target process
        lpHookEntry->lpInjCodeAndData =
          cProcEntry->AllocateStub(lpHookEntry->lpOrigProc, FlagOn(lpHookEntry->dwFlags,
                                                                   NKTHOOKLIB_DisallowReentrancy) ? 4096 : 256);
        if (lpHookEntry->lpInjCodeAndData == NULL)
        {
          dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
          break;
        }
        lpRetStubs[0] = lpRetStubs[1] = NULL;
        //calculate the size of a size_t value
        nSizeOfSizeT = 0;
        switch (cProcEntry->GetPlatform())
        {
          case NKTHOOKLIB_ProcessPlatformX86:
            nSizeOfSizeT = 4;
            break;
#if defined(_M_X64)
          case NKTHOOKLIB_ProcessPlatformX64:
            nSizeOfSizeT = 8;
            break;
#endif //_M_X64
        }
        //build new code and begin with flags location
        p = aCodeBlock;
        //flags
        MemSet(p, 0, nSizeOfSizeT);
        if (bIsRemoteProcess == FALSE || FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DontEnableHooks))
        {
          //if current process, hooks are initially disabled to avoid issues when hooking api's used by this routine
          *(p+1) = 0x01; //disable flag
        }
        p += nSizeOfSizeT;
        //if we use indirect jumps, store the pointer to our code start here
        if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_UseAbsoluteIndirectJumps))
        {
          //calculate code start
          switch (cProcEntry->GetPlatform())
          {
            case NKTHOOKLIB_ProcessPlatformX86:
              *((ULONG NKT_UNALIGNED*)p) = (ULONG)(ULONG_PTR)(lpHookEntry->lpInjCodeAndData + 2 * nSizeOfSizeT);
              p += sizeof(ULONG);
              break;
#if defined(_M_X64)
            case NKTHOOKLIB_ProcessPlatformX64:
              *((ULONGLONG NKT_UNALIGNED*)p) = (ULONGLONG)(lpHookEntry->lpInjCodeAndData + 2 * nSizeOfSizeT);
              p += sizeof(ULONGLONG);
              break;
#endif //_M_X64
          }
        }
        //write some NOPs for hot-patching double hooks
        MemSet(p, 0x90, 8);
        p += 8;
        //bridge
        lpCallOrigOfs[0] = lpCallOrigOfs[1] = NULL;
        switch (cProcEntry->GetPlatform())
        {
          case NKTHOOKLIB_ProcessPlatformX86:
            *p++ = 0x52;                                                         //push  edx
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              *p++ = 0x50;                                                       //push  eax
              *p++ = 0x53;                                                       //push  ebx
              *p++ = 0x51;                                                       //push  ecx
            }
            //----
            *p++ = 0xBA;                                                         //mov   edx, OFFSET lpInjCode
            *((ULONG NKT_UNALIGNED*)p) = (ULONG)(ULONG_PTR)(lpHookEntry->lpInjCodeAndData);
            p += sizeof(ULONG);
            //----
            *p++ = 0xF7;  *p++ = 0x02;                                           //test  DWORD PTR [edx], 00000101h
            *((ULONG NKT_UNALIGNED*)p) = 0x00000101;
            p += sizeof(ULONG);
            //----
            *p++ = 0x75;                                                         //jne   CALL_ORIGINAL
            lpCallOrigOfs[0] = p++;
            //check for reentranct
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              *p++ = 0x64;  *p++ = 0xA1;                                         //mov   eax, fs:[18h]
              *((ULONG NKT_UNALIGNED*)p) = 0x18;
              p += sizeof(ULONG);
              //----
              *p++ = 0x8B;  *p++ = 0x40;  *p++ = 0x24;                           //mov   eax, DWORD PTR [eax+24h]
              //----
              *p++ = 0xBA;                                                       //mov   edx, OFFSET lpReturn
              lpRetStubs[0] = p;
              p += sizeof(ULONG);
              //----
              *p++ = 0xB9;                                                       //mov   ecx, RETMINISTUBS_COUNT_X86
              *((ULONG NKT_UNALIGNED*)p) = RETMINISTUBS_COUNT_X86;
              p += sizeof(ULONG);
              //----  L1:
              *p++ = 0x3B;  *p++ = 0x02;                                         //cmp   eax, DWORD PTR [edx]
              //----
              *p++ = 0x74;                                                       //jz    CALL_ORIGINAL
              lpCallOrigOfs[1] = p++;
              //----
              *p++ = 0x81;  *p++ = 0xC2;                                         //add   edx, 14h
              *((ULONG NKT_UNALIGNED*)p) = 0x0014;
              p += sizeof(ULONG);
              //----
              *p++ = 0xE2;  *p++ = 0xF4;                                         //loop  L1
              //----
              *p++ = 0x8B;  *p++ = 0xD8;                                         //mov   ebx, eax
              //----
              *p++ = 0xBA;                                                       //mov   edx, OFFSET lpReturn
              lpRetStubs[1] = p;
              p += sizeof(ULONG);
              //----
              *p++ = 0xB9;                                                       //mov   ecx, RETMINISTUBS_COUNT_X86
              *((ULONG NKT_UNALIGNED*)p) = RETMINISTUBS_COUNT_X86;
              p += sizeof(ULONG);
              //---- L2:
              *p++ = 0x33;  *p++ = 0xC0;                                         //xor   eax, eax
              //----
              *p++ = 0xF0;  *p++ = 0x0F;  *p++ = 0xB1;  *p++ = 0x1A;             //lock cmpxchg DWORD PTR [edx], ebx
              //----
              *p++ = 0x74;  *p++ = 0x0A;                                         //jz    CHG_RETADDR
              //----
              *p++ = 0x81;  *p++ = 0xC2;                                         //add   edx, 14h
              *((ULONG NKT_UNALIGNED*)p) = 0x0014;
              p += sizeof(ULONG);
              //----
              *p++ = 0xE2;  *p++ = 0xF0;                                         //loop  L2
              //----
              *p++ = 0xEB;  *p++ = 0x17;                                         //jmp   call_hooked
              //---- CHG_RETADDR:
              *p++ = 0x8B;  *p++ = 0x44;  *p++ = 0x24;  *p++ = 0x10;             //mov   eax, DWORD PTR [esp+10h]
              //----
              *p++ = 0x89;  *p++ = 0x42;  *p++ = 0x05;                           //mov   DWORD PTR [edx+5], eax
              //----
              *p++ = 0x8D;  *p++ = 0x42;  *p++ = 0x04;                           //lea   eax, DWORD PTR [edx+4]
              //----
              *p++ = 0x89;  *p++ = 0x44;  *p++ = 0x24;  *p++ = 0x10;             //mov   DWORD PTR [esp+10h], eax
              //----
              *p++ = 0x59;                                                       //pop   ecx
              *p++ = 0x5B;                                                       //pop   ebx
              *p++ = 0x58;                                                       //pop   eax
            }
            *p++ = 0x5A;                                                         //pop   edx
            //----
            *p++ = 0xE9;                                                         //jmp   hooked proc
            *((ULONG NKT_UNALIGNED*)p) = (ULONG)(ULONG_PTR)(lpHookEntry->lpNewProc) -
              ((ULONG)(ULONG_PTR)(lpHookEntry->lpInjCodeAndData) +
              (ULONG)(ULONG_PTR)(p+4-aCodeBlock));
            p += sizeof(ULONG);
            //---- CALL_ORIGINAL:
            *lpCallOrigOfs[0] = (BYTE)(p - (lpCallOrigOfs[0]+1));
            if (lpCallOrigOfs[1] != NULL)
              *lpCallOrigOfs[1] = (BYTE)(p - (lpCallOrigOfs[1]+1));
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              *p++ = 0x59;                                                       //pop   ecx
              *p++ = 0x5B;                                                       //pop   ebx
              *p++ = 0x58;                                                       //pop   eax
            }
            *p++ = 0x5A;                                                         //pop   edx
            lpHookEntry->lpCall2Orig = lpHookEntry->lpInjCodeAndData + (SIZE_T)(p-aCodeBlock);
            MemCopy(p, lpHookEntry->aNewStub, lpHookEntry->nNewStubSize); //new stub
            p += lpHookEntry->nNewStubSize;
            //----
            *p++ = 0xE9;                                                         //jmp original proc after stub
            *((ULONG NKT_UNALIGNED*)p) = ((ULONG)(ULONG_PTR)(lpHookEntry->lpOrigProc) +
                                          (ULONG)(ULONG_PTR)(lpHookEntry->nOriginalStubSize)) -
                                          ((ULONG)(ULONG_PTR)(lpHookEntry->lpInjCodeAndData) +
                                          (ULONG)(ULONG_PTR)(p+4-aCodeBlock));
            p += sizeof(ULONG);
            //----
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              p = (LPBYTE)(((SIZE_T)p + 3) & (~3)); //align 4
              *((ULONG NKT_UNALIGNED*)lpRetStubs[0]) = *((ULONG NKT_UNALIGNED*)lpRetStubs[1]) =
                (ULONG)((ULONG_PTR)(lpHookEntry->lpInjCodeAndData + (SIZE_T)(p-aCodeBlock)));
            }
            break;

#if defined(_M_X64)
          case NKTHOOKLIB_ProcessPlatformX64:
            *p++ = 0x52;                                                         //push  rdx
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              *p++ = 0x50;                                                       //push  rax
              *p++ = 0x53;                                                       //push  rbx
              *p++ = 0x51;                                                       //push  rcx
            }
            //----
            *p++ = 0x48;  *p++ = 0xBA;                                           //mov   rdx, OFFSET lpInjCode
            *((ULONGLONG NKT_UNALIGNED*)p) = (ULONGLONG)(lpHookEntry->lpInjCodeAndData);
            p += sizeof(ULONGLONG);
            //----
            *p++ = 0x48;  *p++ = 0xF7;  *p++ = 0x02;                             //test  QWORD PTR [rdx], 00000101h
            *((ULONG NKT_UNALIGNED*)p) = 0x00000101;
            p += sizeof(ULONG);
            //----
            *p++ = 0x75;                                                         //jne   CALL_ORIGINAL
            lpCallOrigOfs[0] = p++;
            //check for reentranct
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              *p++ = 0x65;  *p++ = 0x48;  *p++ = 0x8B;  *p++ = 0x04;             //mov   rax, gs:[30h]
              *p++ = 0x25;
              *((ULONG NKT_UNALIGNED*)p) = 0x30;
              p += sizeof(ULONG);
              //----
              *p++ = 0x8B;  *p++ = 0x40;  *p++ = 0x48;                           //mov   eax, DWORD PTR [rax+48h]
              //----
              *p++ = 0x48;  *p++ = 0xBA;                                         //mov   rdx, OFFSET lpReturn
              lpRetStubs[0] = p;
              p += sizeof(ULONGLONG);
              //----
              *p++ = 0x48;  *p++ = 0xC7;  *p++ = 0xC1;                           //mov   rcx, RETMINISTUBS_COUNT_X64
              *((ULONG NKT_UNALIGNED*)p) = RETMINISTUBS_COUNT_X64;
              p += sizeof(ULONG);
              //----  L1:
              *p++ = 0x3B;  *p++ = 0x02;                                         //cmp   eax, DWORD PTR [rdx]
              //----
              *p++ = 0x74;                                                       //jz    CALL_ORIGINAL
              lpCallOrigOfs[1] = p++;
              //----
              *p++ = 0x48;  *p++ = 0x81;  *p++ = 0xC2;                           //add   rdx, 1Ch
              *((ULONG NKT_UNALIGNED*)p) = 0x001C;
              p += sizeof(ULONG);
              //----
              *p++ = 0xE2;  *p++ = 0xF3;                                         //loop  L1
              //----
              *p++ = 0x8B;  *p++ = 0xD8;                                         //mov   ebx, eax
              //----
              *p++ = 0x48;  *p++ = 0xBA;                                         //mov   rdx, OFFSET lpReturn
              lpRetStubs[1] = p;
              p += sizeof(ULONGLONG);
              //----
              *p++ = 0x48;  *p++ = 0xC7;  *p++ = 0xC1;                           //mov   rcx, RETMINISTUBS_COUNT_X64
              *((ULONG NKT_UNALIGNED*)p) = RETMINISTUBS_COUNT_X64;
              p += sizeof(ULONG);
              //---- L2:
              *p++ = 0x48;  *p++ = 0x33;  *p++ = 0xC0;                           //xor   rax, rax
              //----
              *p++ = 0xF0;  *p++ = 0x0F;  *p++ = 0xB1;  *p++ = 0x1A;             //lock cmpxchg DWORD PTR [rdx], ebx
              //----
              *p++ = 0x74;  *p++ = 0x0B;                                         //jz    CHG_RETADDR
              //----
              *p++ = 0x48;  *p++ = 0x81;  *p++ = 0xC2;                           //add   rdx, 1Ch
              *((ULONG NKT_UNALIGNED*)p) = 0x001C;
              p += sizeof(ULONG);
              //----
              *p++ = 0xE2;  *p++ = 0xEE;                                         //loop  L2
              //----
              *p++ = 0xEB;  *p++ = 0x2A;                                         //jmp   call_hooked
              //---- CHG_RETADDR:
              *p++ = 0x48;  *p++ = 0x8B;  *p++ = 0x44;  *p++ = 0x24;             //mov   rax, QWORD PTR [rsp+20h]
              *p++ = 0x20;
              //----
              *p++ = 0x89;  *p++ = 0x42;  *p++ = 0x05;                           //mov   DWORD PTR [rdx+5], eax
              //----
              *p++ = 0x48;  *p++ = 0xC1;  *p++ = 0xE8;  *p++ = 0x20;             //shr   rax, 20h
              //----
              *p++ = 0x89;  *p++ = 0x42;  *p++ = 0x0D;                           //mov   DWORD PTR [rdx+13], eax
              //----
              *p++ = 0x48;  *p++ = 0x8D;  *p++ = 0x42;  *p++ = 0x04;             //lea   rax, QWORD PTR [rdx+4]
              //----
              *p++ = 0x48;  *p++ = 0x89;  *p++ = 0x44;  *p++ = 0x24;             //mov   QWORD PTR [rsp+20h], rax
              *p++ = 0x20;
              //----
              *p++ = 0x59;                                                       //pop   rcx
              *p++ = 0x5B;                                                       //pop   rbx
              *p++ = 0x58;                                                       //pop   rax
            }
            *p++ = 0x5A;                                                         //pop   rdx
            //----
            *p++ = 0xFF;  *p++ = 0x25;                                           //jmp   hooked proc
            *((ULONG NKT_UNALIGNED*)p) = 0;
            p += sizeof(ULONG);
            *((ULONGLONG NKT_UNALIGNED*)p) = (ULONGLONG)(lpHookEntry->lpNewProc);
            p += sizeof(ULONGLONG);
            //---- CALL_ORIGINAL:
            *lpCallOrigOfs[0] = (BYTE)(p - (lpCallOrigOfs[0]+1));
            if (lpCallOrigOfs[1] != NULL)
              *lpCallOrigOfs[1] = (BYTE)(p - (lpCallOrigOfs[1]+1));
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              *p++ = 0x59;                                                       //pop   rcx
              *p++ = 0x5B;                                                       //pop   rbx
              *p++ = 0x58;                                                       //pop   rax
            }
            *p++ = 0x5A;                                                         //pop   rdx
            lpHookEntry->lpCall2Orig = lpHookEntry->lpInjCodeAndData + (SIZE_T)(p-aCodeBlock);
            MemCopy(p, lpHookEntry->aNewStub, lpHookEntry->nNewStubSize); //new stub
            p += lpHookEntry->nNewStubSize;
            //----
            *p++ = 0xFF;  *p++ = 0x25;                                          //jmp original proc after stub
            *((ULONG NKT_UNALIGNED*)p) = 0;
            p += sizeof(ULONG);
            *((ULONGLONG NKT_UNALIGNED*)p) = (ULONGLONG)(lpHookEntry->lpOrigProc + lpHookEntry->nOriginalStubSize);
            p += sizeof(ULONGLONG);
            //----
            if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
            {
              p = (LPBYTE)(((SIZE_T)p + 3) & (~3)); //align 4
              *((ULONGLONG NKT_UNALIGNED*)lpRetStubs[0]) = *((ULONGLONG NKT_UNALIGNED*)lpRetStubs[1]) =
                ((ULONGLONG)(lpHookEntry->lpInjCodeAndData) + (ULONGLONG)(p-aCodeBlock));
            }
            break;
#endif //_M_X64
        }
        //calculate injected code size
        lpHookEntry->nInjCodeAndDataSize = (SIZE_T)(p - aCodeBlock);
        NKT_ASSERT(lpHookEntry->nInjCodeAndDataSize < sizeof(aCodeBlock));
        //write inject code
        if (WriteMem(cProcEntry->GetHandle(), lpHookEntry->lpInjCodeAndData, aCodeBlock,
          lpHookEntry->nInjCodeAndDataSize) == FALSE)
        {
          dwOsErr = ERROR_ACCESS_DENIED;
          break;
        }
        NktNtFlushInstructionCache(cProcEntry->GetHandle(), lpHookEntry->lpInjCodeAndData,
                                   (ULONG)(lpHookEntry->nInjCodeAndDataSize));
        //write return mini stubs
        if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_DisallowReentrancy))
        {
          p = lpHookEntry->lpInjCodeAndData + lpHookEntry->nInjCodeAndDataSize;
          switch (cProcEntry->GetPlatform())
          {
            case NKTHOOKLIB_ProcessPlatformX86:
              for (i=0; i<RETMINISTUBS_COUNT_X86; i++)
              {
                *((ULONG NKT_UNALIGNED*)&aCodeBlock[0]) = 0;                          //DD    0h
                //----
                aCodeBlock[4] = 0x68;                                                 //push  0h
                *((ULONG NKT_UNALIGNED*)&aCodeBlock[5]) = 0;
                //----
                aCodeBlock[9] = 0xF0;  aCodeBlock[10] = 0x83;  aCodeBlock[11] = 0x25; //lock and DWORD PTR [ministub], 0
                *((ULONG NKT_UNALIGNED*)&aCodeBlock[12]) = (ULONG)((ULONG_PTR)p);
                aCodeBlock[16] = 0x00;
                //----
                aCodeBlock[17] = 0xC3;                                                //ret
                //fill with NOPs
                aCodeBlock[18] = aCodeBlock[19] = 0x90;
                //write
                if (WriteMem(cProcEntry->GetHandle(), p, aCodeBlock, 20) == FALSE)
                {
                  dwOsErr = ERROR_ACCESS_DENIED;
                  break;
                }
                p += 20;
              }
              lpHookEntry->nInjCodeAndDataSize += RETMINISTUBS_COUNT_X86 * 20;
              break;

#if defined(_M_X64)
            case NKTHOOKLIB_ProcessPlatformX64:
              for (i=0; i<RETMINISTUBS_COUNT_X64; i++)
              {
                *((ULONG NKT_UNALIGNED*)&aCodeBlock[0]) = 0;                          //DD    0h
                //----
                aCodeBlock[4] = 0x68;                                                 //push  0h
                *((ULONG NKT_UNALIGNED*)&aCodeBlock[5]) = 0;
                //----
                aCodeBlock[9] = 0xC7;  aCodeBlock[10] = 0x44;  aCodeBlock[11] = 0x24; //mov   dword ptr [rsp+4], 0h
                aCodeBlock[12] = 0x04;
                *((ULONG NKT_UNALIGNED*)&aCodeBlock[13]) = 0;
                //----
                aCodeBlock[17] = 0xF0;  aCodeBlock[18] = 0x83;  aCodeBlock[19] = 0x25; //lock and [ministub], 0
                *((ULONG NKT_UNALIGNED*)&aCodeBlock[20]) = 0xFFFFFFE7;
                aCodeBlock[24] = 0x00;
                //----
                aCodeBlock[25] = 0xC3;                                                //ret
                //fill with NOPs
                aCodeBlock[26] = aCodeBlock[27] = 0x90;
                //write
                if (WriteMem(cProcEntry->GetHandle(), p, aCodeBlock, 28) == FALSE)
                {
                  dwOsErr = ERROR_ACCESS_DENIED;
                  break;
                }
                p += 28;
              }
              lpHookEntry->nInjCodeAndDataSize += RETMINISTUBS_COUNT_X64 * 28;
              break;
#endif //_M_X64
          }
          if (dwOsErr != ERROR_SUCCESS)
            break;
        }
        //create "jump" stub to insert in the original proc
        if (FlagOn(lpHookEntry->dwFlags, NKTHOOKLIB_UseAbsoluteIndirectJumps))
        {
          lpHookEntry->aJumpStub[0] = 0xFF; lpHookEntry->aJumpStub[1] = 0x25;  //JMP DWORD/QWORD PTR [mem32/64]
          switch (cProcEntry->GetPlatform())
          {
            case NKTHOOKLIB_ProcessPlatformX86:
              //32-bit jumps are absolute
              dw = (DWORD)((ULONG_PTR)(lpHookEntry->lpInjCodeAndData + nSizeOfSizeT));
              break;
#if defined(_M_X64)
            case NKTHOOKLIB_ProcessPlatformX64:
              //64-bit jumps are relative
              dw = (DWORD)((ULONG_PTR)(lpHookEntry->lpInjCodeAndData+nSizeOfSizeT)) -
                (DWORD)((ULONG_PTR)(lpHookEntry->lpOrigProc+6));
              break;
#endif //_M_X64
          }
          *((DWORD NKT_UNALIGNED*)(lpHookEntry->aJumpStub+2)) = dw;
        }
        else
        {
          //32-bit & 64-bit jumps are relative
          lpHookEntry->aJumpStub[0] = 0xE9; //JMP
          dw = (DWORD)((ULONG_PTR)(lpHookEntry->lpInjCodeAndData+nSizeOfSizeT)) -
            (DWORD)((ULONG_PTR)(lpHookEntry->lpOrigProc+5));
          *((DWORD NKT_UNALIGNED*)(lpHookEntry->aJumpStub+1)) = dw;
        }
        //set id
#if defined(_M_IX86)
        lpHookEntry->nId = (SIZE_T)lpHookEntry ^ 0x34B68363UL; //odd number to avoid result of zero
#elif defined(_M_X64)
        lpHookEntry->nId = (SIZE_T)lpHookEntry ^ 0x34B68364A3CE19F3ui64; //odd number to avoid result of zero
#endif
        //done
        aHookInfo[nHookIdx+k].nHookId = lpHookEntry->nId;
        if (FlagOn(dwFlags, INTERNALFLAG_CallToOriginalIsPtr2Ptr))
        {
          if (aHookInfo[nHookIdx].lpCallOriginal != NULL)
            *((LPVOID*)aHookInfo[nHookIdx].lpCallOriginal) = lpHookEntry->lpCall2Orig;
        }
        else
        {
          aHookInfo[nHookIdx].lpCallOriginal = lpHookEntry->lpCall2Orig;
        }
      }
      //do actual hooking
      if (dwOsErr == ERROR_SUCCESS)
      {
        CNktThreadSuspend::CAutoResume cAutoResume(&(int_data->cThreadSuspender));
        CNktThreadSuspend::IP_RANGE sIpRanges[MAX_SUSPEND_IPRANGES];
        MEMORY_BASIC_INFORMATION sMbi;
        DWORD dwNewProt, dwOldProt;
        BOOL bThreadsSuspended;

        bThreadsSuspended = FALSE;
        for (lpHookEntry=lpFirstHookEntryInRound, k=0; k<nThisRound; k++, lpHookEntry=lpHookEntry->GetNextEntry())
        {
          //suspend threads if not done yet taking into account until 'MAX_SUSPEND_IPRANGES' ahead items
          if (bThreadsSuspended == FALSE && int_data->sOptions.bSuspendThreads != FALSE)
          {
            CHookEntry *lpHookEntry2;
            SIZE_T i;

            for (i=0, lpHookEntry2=lpHookEntry; i<nThisRound && i<MAX_SUSPEND_IPRANGES;
                 i++, lpHookEntry2=lpHookEntry2->GetNextEntry())
            {
              sIpRanges[i].nStart = (SIZE_T)(lpHookEntry2->lpOrigProc);
              sIpRanges[i].nEnd = sIpRanges[i].nStart + lpHookEntry2->GetJumpToHookBytes();
            }
            dwOsErr = int_data->cThreadSuspender.SuspendAll(cProcEntry->GetPid(), sIpRanges, i);
            if (dwOsErr != ERROR_SUCCESS)
              break;
            bThreadsSuspended = TRUE;
          }
          //do actual hooking
          MemSet(&sMbi, 0, sizeof(sMbi));
          nSize = 0;
          nNtStatus = NktNtQueryVirtualMemory(cProcEntry->GetHandle(), lpHookEntry->lpOrigProc,
                                              MyMemoryBasicInformation, &sMbi, sizeof(sMbi), &nSize);
          dwNewProt = PAGE_EXECUTE_WRITECOPY;
          if (NT_SUCCESS(nNtStatus))
          {
            switch (sMbi.Protect & 0xFF)
            {
              case PAGE_NOACCESS:
              case PAGE_READONLY:
              case PAGE_READWRITE:
                dwNewProt = PAGE_READWRITE;
                break;
              case PAGE_WRITECOPY:
                dwNewProt = PAGE_WRITECOPY;
                break;
              case PAGE_EXECUTE:
              case PAGE_EXECUTE_READ:
              case PAGE_EXECUTE_READWRITE:
                dwNewProt = PAGE_EXECUTE_READWRITE;
                break;
            }
          }
          //change protection if needed
          if (dwNewProt != (sMbi.Protect & 0xFF))
          {
            p = lpHookEntry->lpOrigProc;
            nSize = lpHookEntry->GetJumpToHookBytes();
            dwOldProt = 0;
            nNtStatus = NktNtProtectVirtualMemory(cProcEntry->GetHandle(), (PVOID*)&p, &nSize, dwNewProt, &dwOldProt);
            if (!NT_SUCCESS(nNtStatus))
            {
              dwOsErr = NktRtlNtStatusToDosError(nNtStatus);
              if (dwOsErr == 0)
                dwOsErr = ERROR_NOT_SUPPORTED;
              break;
            }
          }
          //replace entry point
          if (WriteMem(cProcEntry->GetHandle(), lpHookEntry->lpOrigProc, lpHookEntry->aJumpStub,
            lpHookEntry->GetJumpToHookBytes()) == FALSE)
            dwOsErr = ERROR_ACCESS_DENIED;
          //restore protection
          if (dwNewProt != (sMbi.Protect & 0xFF))
          {
            p = lpHookEntry->lpOrigProc;
            nSize = lpHookEntry->GetJumpToHookBytes();
            NktNtProtectVirtualMemory(cProcEntry->GetHandle(), (PVOID*)&p, &nSize, dwOldProt, &dw);
          }
          //check write operation result
          if (dwOsErr != ERROR_SUCCESS)
            break;
          //flush instruction cache
          NktNtFlushInstructionCache(cProcEntry->GetHandle(), lpHookEntry->lpOrigProc, 32);
          //mark as installed
          lpHookEntry->nInstalledCode = 1;
          //check if next item to hook is outside any suspended thread range
          if (int_data->sOptions.bSuspendThreads != FALSE && k+1 < nThisRound)
          {
            CHookEntry *lpHookEntry2 = lpHookEntry->GetNextEntry();
            SIZE_T nAddrS, nAddrE;

            nAddrS = (SIZE_T)(lpHookEntry2->lpOrigProc);
            nAddrE = nAddrS + lpHookEntry2->GetJumpToHookBytes();
            if (int_data->cThreadSuspender.CheckIfThreadIsInRange(nAddrS, nAddrE) != FALSE)
            {
              //resume threads
              int_data->cThreadSuspender.ResumeAll();
              bThreadsSuspended = FALSE;
            }
          }
        }
      }
      //advance count
      if (dwOsErr == ERROR_SUCCESS)
        nHookIdx += nThisRound;
    }
    //done... move to the final list or delete on error
    if (dwOsErr == ERROR_SUCCESS)
    {
      while ((lpHookEntry = cNewHooksList.PopHead()) != NULL)
      {
        if (int_data->sOptions.bOutputDebug != FALSE)
        {
          DebugPrint("NktHookLib: Hook installed. Proc @ 0x%IX -> 0x%IX (Stub @ 0x%IX) \r\n",
                     (SIZE_T)(lpHookEntry->lpOrigProc), (SIZE_T)(lpHookEntry->lpNewProc),
                     (SIZE_T)(lpHookEntry->lpInjCodeAndData));
        }
        int_data->cHooksList.PushTail(lpHookEntry);
      }
    }
    else
    {
      HOOK_INFO sHooks[64];
      SIZE_T nCount;

      nCount = 0;
      while ((lpHookEntry = cNewHooksList.PopHead()) != NULL)
      {
        if (lpHookEntry->nInstalledCode == 0)
        {
          delete lpHookEntry;
        }
        else
        {
          //temporary add the hook entry to the final list in order to remove it later
          int_data->cHooksList.PushTail(lpHookEntry);
          sHooks[nCount++].nHookId = lpHookEntry->nId;
          if (nCount >= X_ARRAYLEN(sHooks))
          {
            Unhook(sHooks, nCount);
            nCount = 0;
          }
        }
      }
      if (nCount > 0)
        Unhook(sHooks, nCount);
    }
  }
  else
  {
    dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
  }
  //enable hooks if installed locally
  if (dwOsErr == ERROR_SUCCESS && bIsRemoteProcess == FALSE && (!FlagOn(dwFlags, NKTHOOKLIB_DontEnableHooks)))
  {
    EnableHook(aHookInfo, nCount, TRUE); //this will always succeed
  }
  return dwOsErr;
}

//-----------------------------------------------------------

static DWORD GetProcessIdFromHandle(__in HANDLE hProc)
{
  PROCESS_BASIC_INFORMATION sPbi;

  if (hProc != NULL)
  {
    if (hProc == NKTHOOKLIB_CurrentProcess)
      return NktHookLibHelpers::GetCurrentProcessId();
    NktHookLibHelpers::MemSet(&sPbi, 0, sizeof(sPbi));
    if (NktNtQueryInformationProcess(hProc, (PROCESSINFOCLASS)MyProcessBasicInformation, &sPbi, sizeof(sPbi),
                                     NULL) >= 0)
      return (DWORD)sPbi.UniqueProcessId;
  }
  return 0;
}
