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
#include "LinkedList.h"
#include "WaitableObjects.h"
#include "ThreadSuspend.h"
#include "HookEntry.h"
#include "NtHeapBaseObj.h"

//-----------------------------------------------------------

#define MAX_SUSPEND_IPRANGES                              10

#define MemoryBasicInformation                             0

#define X_ARRAYLEN(x)               (sizeof(x)/sizeof(x[0]))

#if defined(_M_X64) || defined(_M_IA64) || defined(_M_AMD64)
  #define NKT_UNALIGNED __unaligned
#else
  #define NKT_UNALIGNED
#endif

//-----------------------------------------------------------

static DWORD GetProcessIdFromHandle(__in HANDLE hProc);

//-----------------------------------------------------------

namespace NktHookLib {

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

} //NktHookLib

#define int_data           ((NktHookLib::CInternals*)lpInternals)

//-----------------------------------------------------------

CNktHookLib::CNktHookLib()
{
  lpInternals = new NktHookLib::CInternals();
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
  return RemoteHook(lpnHookId, lplpCallOriginal, NktHookLibHelpers::GetCurrentProcessId(), lpProcToHook,
                    lpNewProcAddr, dwFlags);
}

DWORD CNktHookLib::Hook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in DWORD dwFlags)
{
  return RemoteHook(aHookInfo, nCount, NktHookLibHelpers::GetCurrentProcessId(), dwFlags);
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
  dwOsErr = RemoteHook(&sHook, 1, dwPid, dwFlags);
  if (dwOsErr == NO_ERROR)
  {
    *lpnHookId = sHook.nHookId;
    *lplpCallOriginal = sHook.lpCallOriginal;
  }
  return dwOsErr;
}

DWORD CNktHookLib::RemoteHook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in DWORD dwPid, __in DWORD dwFlags)
{
  DWORD dwOsErr;

  if (dwPid == 0)
    return ERROR_INVALID_PARAMETER;
  if (lpInternals != NULL)
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    NktHookLib::CProcessesHandles::CEntryPtr cProcEntry;
    NktHookLib::CHookEntry *lpHookEntry, **lpNewEntriesList;
    BYTE aNewCode[0x80 + HOOKENG_MAX_STUB_SIZE];
    SIZE_T nSize, nHookIdx;
    LPBYTE lpPtr;
    DWORD dw;
    NTSTATUS nNtStatus;

    if (aHookInfo == 0 || nCount == 0)
      return ERROR_INVALID_PARAMETER;
    for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
    {
      if (aHookInfo[nHookIdx].lpProcToHook == NULL ||
          aHookInfo[nHookIdx].lpNewProcAddr == NULL)
        return ERROR_INVALID_PARAMETER;
      aHookInfo[nHookIdx].nHookId = 0;
      aHookInfo[nHookIdx].lpCallOriginal = NULL;
    }
    //get process handle
    cProcEntry.Attach(int_data->cProcHdrMgr.Get(dwPid));
    if (cProcEntry == NULL)
      return ERROR_ACCESS_DENIED;
    //create entries for each item
    lpNewEntriesList = (NktHookLib::CHookEntry**)NktHookLibHelpers::MemAlloc(nCount*sizeof(NktHookLib::CHookEntry*));
    if (lpNewEntriesList != NULL)
    {
      dwOsErr = NO_ERROR;
      NktHookLibHelpers::MemSet(lpNewEntriesList, 0, nCount * sizeof(NktHookLib::CHookEntry*));
    }
    else
    {
      dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
    }
    for (nHookIdx=0; nHookIdx<nCount && dwOsErr==NO_ERROR; nHookIdx++)
    {
      //allocate new entry
      lpHookEntry = new NktHookLib::CHookEntry(cProcEntry);
      if (lpHookEntry == NULL)
      {
        dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
        continue;
      }
      lpNewEntriesList[nHookIdx] = lpHookEntry;
      lpHookEntry->lpOrigProc = (LPBYTE)(aHookInfo[nHookIdx].lpProcToHook);
      if ((dwFlags & NKTHOOKLIB_DontSkipInitialJumps) == 0)
      {
        lpHookEntry->lpOrigProc = lpHookEntry->SkipJumpInstructions(lpHookEntry->lpOrigProc);
        if (lpHookEntry->lpOrigProc == NULL)
        {
          dwOsErr = ERROR_ACCESS_DENIED;
          continue;
        }
      }
      lpHookEntry->lpNewProc = (LPBYTE)(aHookInfo[nHookIdx].lpNewProcAddr);
      //read original stub and create new one
      dwOsErr = lpHookEntry->CreateStub(int_data->sOptions.bOutputDebug,
                                        ((dwFlags & NKTHOOKLIB_DontSkipAnyJumps) == 0) ? TRUE : FALSE);
      if (dwOsErr != NO_ERROR)
        continue;
      //calculate inject code size and offset to data
      switch (cProcEntry->GetPlatform())
      {
        case NKTHOOKLIB_ProcessPlatformX86:
          lpHookEntry->nInjCodeAndDataSize = 0x2A + lpHookEntry->nNewStubSize;
          break;
#if defined _M_X64
        case NKTHOOKLIB_ProcessPlatformX64:
          lpHookEntry->nInjCodeAndDataSize = 0x41 + lpHookEntry->nNewStubSize;
          break;
#endif //_M_X64
      }
      //allocate memory for inject code in target process
      NKT_ASSERT(lpHookEntry->nInjCodeAndDataSize < NKTHOOKLIB_PROCESS_MEMBLOCK_SIZE);
      lpHookEntry->lpInjCodeAndData = cProcEntry->AllocateStub(lpHookEntry->lpOrigProc);
      if (lpHookEntry->lpInjCodeAndData == NULL)
      {
        dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
        continue;
      }
      //setup code
      switch (cProcEntry->GetPlatform())
      {
        case NKTHOOKLIB_ProcessPlatformX86:
          NktHookLibHelpers::MemSet(aNewCode, 0x00, 8);                            //flags location
          NktHookLibHelpers::MemSet(aNewCode+0x08, 0x90, 8);                       //NOPs for hotpatching double hooks
          aNewCode[0x10] = 0x50;                                                   //push  eax
          aNewCode[0x11] = 0xB8;                                                   //mov   eax, ADDR lpInjCode
          *((ULONG NKT_UNALIGNED*)(aNewCode+0x12)) = (ULONG)(lpHookEntry->lpInjCodeAndData);
          aNewCode[0x16] = 0xF7;                                                   //test  dword ptr [eax], 00000101h
          aNewCode[0x17] = 0x00;
          *((ULONG NKT_UNALIGNED*)(aNewCode+0x18)) = 0x00000101;
          aNewCode[0x1C] = 0x75;                                                   //jne   @@1 ;if disabled/uninst
          aNewCode[0x1D] = 0x06;
          aNewCode[0x1E] = 0x58;                                                   //pop   eax
          aNewCode[0x1F] = 0xE9;                                                   //jmp   hooked proc
          *((ULONG NKT_UNALIGNED*)(aNewCode+0x20)) = (ULONG)(lpHookEntry->lpNewProc) -
                                                     (ULONG)(lpHookEntry->lpInjCodeAndData) - 0x24;
          aNewCode[0x24] = 0x58;                                                   //@@1: pop   eax
          lpHookEntry->lpCall2Orig = lpHookEntry->lpInjCodeAndData + 0x25;
          NktHookLibHelpers::MemCopy(aNewCode+0x25, lpHookEntry->aNewStub, lpHookEntry->nNewStubSize); //new stub
          aNewCode[0x25+lpHookEntry->nNewStubSize] = 0xE9;                         //jmp original proc after stub
          *((ULONG NKT_UNALIGNED*)(aNewCode+0x26+lpHookEntry->nNewStubSize)) =
                                         (ULONG)(lpHookEntry->lpOrigProc) + (ULONG)(lpHookEntry->nOriginalStubSize) -
                                         (ULONG)(lpHookEntry->lpInjCodeAndData+0x2A+lpHookEntry->nNewStubSize);
          break;

#if defined _M_X64
        case NKTHOOKLIB_ProcessPlatformX64:
          NktHookLibHelpers::MemSet(aNewCode, 0x00, 8);                            //flags location
          NktHookLibHelpers::MemSet(aNewCode+0x08, 0x90, 8);                       //NOPs for hotpatching double hooks
          aNewCode[0x10] = 0x50;                                                   //push  rax
          aNewCode[0x11] = 0x48;                                                   //mov   rax, ADDR lpInjCode
          aNewCode[0x12] = 0xB8;
          *((ULONGLONG NKT_UNALIGNED*)(aNewCode+0x13)) = (ULONGLONG)(lpHookEntry->lpInjCodeAndData);
          aNewCode[0x1B] = 0xF7;                                                   //test  dword ptr [rax], 00000101h
          aNewCode[0x1C] = 0x00;
          *((ULONG NKT_UNALIGNED*)(aNewCode+0x1D)) = 0x00000101;
          aNewCode[0x21] = 0x75;                                                   //jne   @@1 ;if disabled/uninst
          aNewCode[0x22] = 0x0F;
          aNewCode[0x23] = 0x58;                                                   //pop   rax
          aNewCode[0x24] = 0xFF;                                                   //jmp   hooked proc
          aNewCode[0x25] = 0x25;
          *((ULONG NKT_UNALIGNED*)(aNewCode+0x26)) = 0;
          *((ULONGLONG NKT_UNALIGNED*)(aNewCode+0x2A)) = (ULONGLONG)(lpHookEntry->lpNewProc);
          aNewCode[0x32] = 0x58;                                                   //@@1: pop   rax
          lpHookEntry->lpCall2Orig = lpHookEntry->lpInjCodeAndData+0x33;
          NktHookLibHelpers::MemCopy(aNewCode+0x33, lpHookEntry->aNewStub, lpHookEntry->nNewStubSize); //new stub
          aNewCode[0x33+lpHookEntry->nNewStubSize] = 0xFF;                         //jmp original proc after stub
          aNewCode[0x34+lpHookEntry->nNewStubSize] = 0x25;
          *((ULONG NKT_UNALIGNED*)(aNewCode+0x35+lpHookEntry->nNewStubSize)) = 0;
          *((ULONGLONG NKT_UNALIGNED*)(aNewCode+0x39+lpHookEntry->nNewStubSize)) =
                                             (ULONGLONG)(lpHookEntry->lpOrigProc + lpHookEntry->nOriginalStubSize);
          break;
#endif //_M_X64
      }
      if (NktHookLibHelpers::WriteMem(cProcEntry->GetHandle(), lpHookEntry->lpInjCodeAndData, aNewCode,
                                      lpHookEntry->nInjCodeAndDataSize) == FALSE)
      {
        dwOsErr = ERROR_ACCESS_DENIED;
        continue;
      }
      //replace original proc with a jump
      dw = (DWORD)(lpHookEntry->lpInjCodeAndData+8) - (DWORD)(lpHookEntry->lpOrigProc) - 5;
      lpHookEntry->aJumpStub[0] = 0xE9; //JMP
      lpHookEntry->aJumpStub[1] = (BYTE)( dw        & 0xFF);
      lpHookEntry->aJumpStub[2] = (BYTE)((dw >>  8) & 0xFF);
      lpHookEntry->aJumpStub[3] = (BYTE)((dw >> 16) & 0xFF);
      lpHookEntry->aJumpStub[4] = (BYTE)((dw >> 24) & 0xFF);
      //set id
#if defined _M_IX86
      lpHookEntry->nId = (SIZE_T)lpHookEntry ^ 0x34B68363UL; //odd number to avoid result of zero
#elif defined _M_X64
      lpHookEntry->nId = (SIZE_T)lpHookEntry ^ 0x34B68364A3CE19F3ui64; //odd number to avoid result of zero
#endif
      //done
      aHookInfo[nHookIdx].nHookId = lpHookEntry->nId;
      aHookInfo[nHookIdx].lpCallOriginal = lpHookEntry->lpCall2Orig;
    }
    //hook new items
    if (dwOsErr == NO_ERROR)
    {
      NktHookLib::CNktThreadSuspend::CAutoResume cAutoResume(&(int_data->cThreadSuspender));
      NktHookLib::CNktThreadSuspend::IP_RANGE sIpRanges[MAX_SUSPEND_IPRANGES];
      SIZE_T k, k2, nThisRoundSuspCount;
      MEMORY_BASIC_INFORMATION sMbi;
      HOOK_INFO sHooks[64];
      DWORD dwNewProt, dwOldProt;

      for (nHookIdx=nThisRoundSuspCount=0; nHookIdx<nCount && dwOsErr==NO_ERROR; )
      {
        if (nThisRoundSuspCount == 0)
        {
          //suspend threads
          nThisRoundSuspCount = (nCount-nHookIdx > MAX_SUSPEND_IPRANGES) ? MAX_SUSPEND_IPRANGES : (nCount-nHookIdx);
          for (k=0; k<nThisRoundSuspCount; k++)
          {
            sIpRanges[k].nStart = (SIZE_T)(lpNewEntriesList[nHookIdx+k]->lpOrigProc);
            sIpRanges[k].nEnd = sIpRanges[k].nStart + HOOKENG_JUMP_TO_HOOK_SIZE;
          }
          dwOsErr = NO_ERROR;
          if (int_data->sOptions.bSuspendThreads != FALSE)
            dwOsErr = int_data->cThreadSuspender.SuspendAll(cProcEntry->GetPid(), sIpRanges, nThisRoundSuspCount);
          if (dwOsErr != NO_ERROR)
          {
err_uninstall_and_destroy:
            for (nHookIdx=k2=0; nHookIdx<nCount; nHookIdx++)
            {
              if (lpNewEntriesList[nHookIdx]->nInstalledCode != 0)
              {
                sHooks[k2++].nHookId = lpNewEntriesList[nHookIdx]->nId;
                if (k2 >= X_ARRAYLEN(sHooks))
                {
                  Unhook(sHooks, k2);
                  k2 = 0;
                }
              }
            }
            if (k2 > 0)
              Unhook(sHooks, k2);
            continue;
          }
        }
        for (k=0; k<nThisRoundSuspCount; k++)
        {
          k2 = 0;
          lpPtr = lpNewEntriesList[nHookIdx+k]->lpOrigProc;
          NktHookLibHelpers::MemSet(&sMbi, 0, sizeof(sMbi));
          nNtStatus = NktHookLib::NktNtQueryVirtualMemory(cProcEntry->GetHandle(), lpPtr, MyMemoryBasicInformation,
                                                         &sMbi, sizeof(sMbi), &k2);
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
            dwOldProt = 0;
            nSize = HOOKENG_JUMP_TO_HOOK_SIZE;
            nNtStatus = NktHookLib::NktNtProtectVirtualMemory(cProcEntry->GetHandle(), (PVOID*)&lpPtr, &nSize,
                                                             dwNewProt, &dwOldProt);
            if (!NT_SUCCESS(nNtStatus))
            {
              dwOsErr = NktHookLib::NktRtlNtStatusToDosError(nNtStatus);
              if (dwOsErr == 0)
                dwOsErr = ERROR_NOT_SUPPORTED;
              int_data->cThreadSuspender.ResumeAll();
              goto err_uninstall_and_destroy;
            }
          }
          //replace each entry point
          k2 = (NktHookLibHelpers::WriteMem(cProcEntry->GetHandle(), lpNewEntriesList[nHookIdx+k]->lpOrigProc,
                                            lpNewEntriesList[nHookIdx+k]->aJumpStub,
                                            HOOKENG_JUMP_TO_HOOK_SIZE) != FALSE) ? 1 : 0;
          //restore protection
          if (dwNewProt != (sMbi.Protect & 0xFF))
          {
            lpPtr = lpNewEntriesList[nHookIdx+k]->lpOrigProc;
            nSize = HOOKENG_JUMP_TO_HOOK_SIZE;
            NktHookLib::NktNtProtectVirtualMemory(cProcEntry->GetHandle(), (PVOID*)&lpPtr, &nSize, dwOldProt, &dw);
          }
          //check write operation result
          if (k2 == 0)
          {
            dwOsErr = ERROR_ACCESS_DENIED;
            int_data->cThreadSuspender.ResumeAll();
            goto err_uninstall_and_destroy;
          }
          //flush instruction cache
          NktHookLib::NktNtFlushInstructionCache(cProcEntry->GetHandle(), lpNewEntriesList[nHookIdx+k]->lpOrigProc, 32);
          //mark as installed
          lpNewEntriesList[nHookIdx+k]->nInstalledCode = 1;
        }
        //advance count
        nHookIdx += nThisRoundSuspCount;
        //check if we can proceed with the next hook with this
        nThisRoundSuspCount = 0;
        for (k=nHookIdx; k<nCount; k++)
        {
          k2 = (SIZE_T)(lpNewEntriesList[k]->lpOrigProc);
          if (int_data->cThreadSuspender.CheckIfThreadIsInRange(k2, k2+HOOKENG_JUMP_TO_HOOK_SIZE) == FALSE)
            break;
          nThisRoundSuspCount++;
        }
        if (nThisRoundSuspCount == 0)
        {
          //resume threads
          int_data->cThreadSuspender.ResumeAll();
        }
      }
    }
    //done... move to the final list or delete on error
    if (dwOsErr == NO_ERROR)
    {
      for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
      {
        lpNewEntriesList[nHookIdx]->dwFlags = dwFlags;
        if (int_data->sOptions.bOutputDebug != FALSE)
        {
          NktHookLibHelpers::DebugPrint("NktHookLib: Hook installed. Proc @ 0x%IX -> 0x%IX (Stub @ 0x%IX) \r\n",
                    (SIZE_T)(lpNewEntriesList[nHookIdx]->lpOrigProc), (SIZE_T)(lpNewEntriesList[nHookIdx]->lpNewProc),
                    (SIZE_T)(lpNewEntriesList[nHookIdx]->lpInjCodeAndData));
        }
        int_data->cHooksList.PushTail(lpNewEntriesList[nHookIdx]);
      }
    }
    else
    {
      for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
        delete lpNewEntriesList[nHookIdx];
    }
    if (lpNewEntriesList != NULL)
      NktHookLibHelpers::MemFree(lpNewEntriesList);
  }
  else
  {
    dwOsErr = ERROR_NOT_ENOUGH_MEMORY;
  }
  return dwOsErr;
}

DWORD CNktHookLib::RemoteHook(__out SIZE_T *lpnHookId, __out LPVOID *lplpCallOriginal, __in HANDLE hProcess,
                              __in LPVOID lpProcToHook, __in LPVOID lpNewProcAddr, __in DWORD dwFlags)
{
  HOOK_INFO sHook;
  DWORD dwOsErr;

  if (lpnHookId != NULL)
    *lpnHookId = 0;
  if (lplpCallOriginal != NULL)
    *lplpCallOriginal = NULL;
  if (lpnHookId == NULL || lplpCallOriginal == NULL || hProcess == NULL)
    return ERROR_INVALID_PARAMETER;
  sHook.lpProcToHook = lpProcToHook;
  sHook.lpNewProcAddr = lpNewProcAddr;
  dwOsErr = RemoteHook(&sHook, 1, hProcess, dwFlags);
  if (dwOsErr == NO_ERROR)
  {
    *lpnHookId = sHook.nHookId;
    *lplpCallOriginal = sHook.lpCallOriginal;
  }
  return dwOsErr;
}


DWORD CNktHookLib::RemoteHook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in HANDLE hProcess,
                              __in DWORD dwFlags)
{
  DWORD dwPid;

  dwPid = GetProcessIdFromHandle(hProcess);
  if (dwPid == 0)
  {
    for (SIZE_T i=0; i<nCount; i++)
    {
      aHookInfo[i].nHookId = 0;
      aHookInfo[i].lpCallOriginal = NULL;
    }
    return ERROR_INVALID_PARAMETER;
  }
  return RemoteHook(aHookInfo, nCount, dwPid, dwFlags);
}

DWORD CNktHookLib::Unhook(__in SIZE_T nHookId)
{
  HOOK_INFO sHook;

  sHook.nHookId = nHookId;
  return Unhook(&sHook, 1);
}

DWORD CNktHookLib::Unhook(__in HOOK_INFO aHookInfo[], __in SIZE_T nCount)
{
  NktHookLib::TNktLnkLst<NktHookLib::CHookEntry> cToDeleteList;
  NktHookLib::CHookEntry *lpHookEntry;

  if (aHookInfo == NULL || nCount == 0)
    return ERROR_INVALID_PARAMETER;
  if (lpInternals != NULL)
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    NktHookLib::CNktThreadSuspend::CAutoResume cAutoResume(&(int_data->cThreadSuspender));
    NktHookLib::CNktThreadSuspend::IP_RANGE sIpRange[2];
    NktHookLib::TNktLnkLst<NktHookLib::CHookEntry>::Iterator it;
    BYTE aTempBuf[HOOKENG_JUMP_TO_HOOK_SIZE];
    SIZE_T nSize, nHookIdx, nIpRangesCount;
    LPBYTE lpPtr;
    DWORD dw, dwOsErr, dwCurrPid;
    BOOL bOk;
    NTSTATUS nNtStatus;

    dwCurrPid = NktHookLibHelpers::GetCurrentProcessId();
    for (nHookIdx=nIpRangesCount=0; nHookIdx<nCount; nHookIdx++)
    {
      for (lpHookEntry=it.Begin(int_data->cHooksList); lpHookEntry!=NULL; lpHookEntry=it.Next())
      {
        if (lpHookEntry->nId == aHookInfo[nHookIdx].nHookId)
          break;
      }
      if (lpHookEntry == NULL)
        continue; //hook not found
      //mark the hook as uninstalled
      if ((lpHookEntry->dwFlags & NKTHOOKLIB_DontRemoveOnUnhook) != 0)
      {
        bOk = FALSE;
      }
      else
      {
        if (lpHookEntry->cProcEntry->GetPid() != dwCurrPid)
        {
          BYTE nVal = 1;
          NktHookLibHelpers::WriteMem(lpHookEntry->cProcEntry, lpHookEntry->lpInjCodeAndData, &nVal, 1);
        }
        else
        {
          _InterlockedExchange((LONG volatile *)(lpHookEntry->lpInjCodeAndData), 1);
        }
        if (lpHookEntry->nInstalledCode != 3)
          lpHookEntry->nInstalledCode = 2;
        //suspend threads if needed
        dwOsErr = NO_ERROR;
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
        if (dwOsErr == NO_ERROR)
        {
          dw = 0;
          lpPtr = lpHookEntry->lpOrigProc;
          nSize = lpHookEntry->nOriginalStubSize;
          nNtStatus = NktHookLib::NktNtProtectVirtualMemory(lpHookEntry->cProcEntry->GetHandle(), (PVOID*)&lpPtr,
                                                           &nSize, PAGE_EXECUTE_READWRITE, &dw);
          if (!NT_SUCCESS(nNtStatus))
          {
            dw = 0;
            lpPtr = lpHookEntry->lpOrigProc;
            nSize = lpHookEntry->nOriginalStubSize;
            nNtStatus = NktHookLib::NktNtProtectVirtualMemory(lpHookEntry->cProcEntry->GetHandle(), (PVOID*)&lpPtr,
                                                             &nSize, PAGE_EXECUTE_WRITECOPY, &dw);
          }
          if (NT_SUCCESS(nNtStatus))
          {
            if (NktHookLibHelpers::ReadMem(lpHookEntry->cProcEntry->GetHandle(), aTempBuf, lpHookEntry->lpOrigProc,
                                           HOOKENG_JUMP_TO_HOOK_SIZE) == HOOKENG_JUMP_TO_HOOK_SIZE &&
                NktHookLibHelpers::MemCompare(aTempBuf, lpHookEntry->aJumpStub, HOOKENG_JUMP_TO_HOOK_SIZE) == 0)
            {
              bOk = NktHookLibHelpers::WriteMem(lpHookEntry->cProcEntry->GetHandle(), lpHookEntry->lpOrigProc,
                                                lpHookEntry->aOriginalStub, lpHookEntry->nOriginalStubSize);
            }
            lpPtr = lpHookEntry->lpOrigProc;
            nSize = lpHookEntry->nOriginalStubSize;
            NktHookLib::NktNtProtectVirtualMemory(lpHookEntry->cProcEntry->GetHandle(), (PVOID*)&lpPtr,
                                                 &nSize, dw, &dw);
            NktHookLib::NktNtFlushInstructionCache(lpHookEntry->cProcEntry->GetHandle(), lpHookEntry->lpOrigProc, 32);
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
  return NO_ERROR;
}

VOID CNktHookLib::UnhookProcess(__in DWORD dwPid)
{
  if (lpInternals != NULL)
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    NktHookLib::TNktLnkLst<NktHookLib::CHookEntry>::Iterator it;
    NktHookLib::CHookEntry *lpHookEntry;
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
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    NktHookLib::TNktLnkLst<NktHookLib::CHookEntry>::Iterator it;
    NktHookLib::TNktLnkLst<NktHookLib::CHookEntry>::IteratorRev itRev;
    NktHookLib::CHookEntry *lpHookEntry;
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
        _InterlockedExchange((LONG volatile *)(lpHookEntry->lpInjCodeAndData), 1);
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
  NktHookLib::TNktLnkLst<NktHookLib::CHookEntry> cToDeleteList;
  NktHookLib::CHookEntry *lpHookEntry;

  if (aHookInfo == NULL || nCount == 0)
    return ERROR_INVALID_PARAMETER;
  if (lpInternals == NULL)
    return ERROR_NOT_ENOUGH_MEMORY;
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    NktHookLib::TNktLnkLst<NktHookLib::CHookEntry>::Iterator it;
    DWORD dwCurrPid;
    SIZE_T nHookIdx;

    //write flags
    dwCurrPid = NktHookLibHelpers::GetCurrentProcessId();
    for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
    {
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
              _InterlockedExchange((LONG volatile *)(lpHookEntry->lpInjCodeAndData+1), 1);
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
  return NO_ERROR;
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
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));
    NktHookLib::TNktLnkLst<NktHookLib::CHookEntry>::Iterator it;
    NktHookLib::CHookEntry *lpHookEntry;
    DWORD dwCurrPid;
    SIZE_T nHookIdx;

    //write flags
    dwCurrPid = NktHookLibHelpers::GetCurrentProcessId();
    for (nHookIdx=0; nHookIdx<nCount; nHookIdx++)
    {
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
            _InterlockedExchange((LONG volatile *)(lpHookEntry->lpInjCodeAndData+1), (bEnable != FALSE) ? 0 : 1);
          }
          break;
        }
      }
    }
  }
  return NO_ERROR;
}

DWORD CNktHookLib::SetSuspendThreadsWhileHooking(__in BOOL bEnable)
{
  if (lpInternals == NULL)
    return ERROR_NOT_ENOUGH_MEMORY;
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

    int_data->sOptions.bSuspendThreads = bEnable;
  }
  return NO_ERROR;
}

BOOL CNktHookLib::GetSuspendThreadsWhileHooking()
{
  BOOL b;

  b = TRUE;
  if (lpInternals != NULL)
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

    b = int_data->sOptions.bSuspendThreads;
  }
  return b;
}

DWORD CNktHookLib::SetEnableDebugOutput(__in BOOL bEnable)
{
  if (lpInternals == NULL)
    return ERROR_NOT_ENOUGH_MEMORY;
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

    int_data->sOptions.bOutputDebug = bEnable;
  }
  return NO_ERROR;
}

BOOL CNktHookLib::GetEnableDebugOutput()
{
  BOOL b;

  b = TRUE;
  if (lpInternals != NULL)
  {
    NktHookLib::CNktAutoFastMutex cAutoLock(&(int_data->cMtx));

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

//-----------------------------------------------------------

static DWORD GetProcessIdFromHandle(__in HANDLE hProc)
{
  PROCESS_BASIC_INFORMATION sPbi;

  if (hProc != NULL)
  {
    if (hProc == NKTHOOKLIB_CurrentProcess)
      return NktHookLibHelpers::GetCurrentProcessId();
    NktHookLibHelpers::MemSet(&sPbi, 0, sizeof(sPbi));
    if (NktHookLib::NktNtQueryInformationProcess(hProc, (PROCESSINFOCLASS)MyProcessBasicInformation, &sPbi,
                                                sizeof(sPbi), NULL) >= 0)
      return (DWORD)sPbi.UniqueProcessId;
  }
  return 0;
}
