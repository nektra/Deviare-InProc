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
#include "ProcessEntry.h"

#pragma intrinsic (_InterlockedExchange)
#pragma intrinsic (_InterlockedIncrement)
#pragma intrinsic (_InterlockedDecrement)

namespace NktHookLib {
namespace Internals {

//-----------------------------------------------------------

#define MemoryBasicInformation                             0
#define ThreadImpersonationToken                           5

#define MY_SE_DEBUG_PRIVILEGE                             20

//-----------------------------------------------------------

CProcessesHandles::CProcessesHandles()
{
  return;
}

CProcessesHandles::~CProcessesHandles()
{
  CNktAutoFastMutex cLock(&cMtx);
  CEntry *lpEntry;

  while ((lpEntry=cEntries.PopHead()) != NULL)
    lpEntry->Release();
  return;
}

CProcessesHandles::CEntry* CProcessesHandles::Get(__in DWORD dwPid)
{
  CNktAutoFastMutex cLock(&cMtx);
  TNktLnkLst<CEntry>::Iterator it;
  CEntry *lpEntry;
  LONG nPlatform;
  HANDLE h;

  if (dwPid == 0)
    return NULL;
  for (lpEntry=it.Begin(cEntries); lpEntry!=NULL; lpEntry=it.Next())
  {
    if (lpEntry->dwPid == dwPid)
      break;
  }
  if (lpEntry == NULL)
  {
    if (dwPid == NktHookLibHelpers::GetCurrentProcessId())
    {
      h = NKTHOOKLIB_CurrentProcess;
    }
    else
    {
      h = CreateHandle(dwPid, PROCESS_SUSPEND_RESUME|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|
                              PROCESS_VM_WRITE);
      if (h == NULL)
        return NULL;
    }
    nPlatform = NktHookLibHelpers::GetProcessPlatform(h);
    if (!NT_SUCCESS(nPlatform))
    {
      if (h != NKTHOOKLIB_CurrentProcess)
        NktNtClose(h);
      return NULL;
    }
    lpEntry = new CEntry(dwPid, h, nPlatform);
    if (lpEntry == NULL)
    {
      if (h != NKTHOOKLIB_CurrentProcess)
        NktNtClose(h);
      return NULL;
    }
    cEntries.PushHead(lpEntry);
  }
  lpEntry->AddRef();
  return lpEntry;
}

HANDLE CProcessesHandles::CreateHandle(__in DWORD dwPid, __in DWORD dwDesiredAccess)
{
  HANDLE hToken, hProc;
  TOKEN_PRIVILEGES sTokPriv;
  BOOL bRevertToSelf;
  NTSTATUS nNtStatus;

  if (dwPid == 0)
    return NULL;
  //try to enable SeDebugPrivilege
  bRevertToSelf = FALSE;
  nNtStatus = NktNtOpenThreadToken(NKTHOOKLIB_CurrentThread, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, FALSE, &hToken);
  if (!NT_SUCCESS(nNtStatus))
  {
    hToken = NULL;
    nNtStatus = NktRtlImpersonateSelf(SecurityImpersonation);
    if (NT_SUCCESS(nNtStatus))
    {
      bRevertToSelf = TRUE;
      nNtStatus = NktNtOpenThreadToken(NKTHOOKLIB_CurrentThread, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, FALSE, &hToken);
      if (!NT_SUCCESS(nNtStatus))
        hToken = NULL;
    }
  }
  NktHookLibHelpers::MemSet(&sTokPriv, 0, sizeof(sTokPriv));
  if (hToken != NULL)
  {
    sTokPriv.PrivilegeCount = 1;
    sTokPriv.Privileges[0].Luid.LowPart = MY_SE_DEBUG_PRIVILEGE;
    sTokPriv.Privileges[0].Luid.HighPart = 0;
    sTokPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    NktNtAdjustPrivilegesToken(hToken, 0, &sTokPriv, sizeof(sTokPriv), NULL, NULL);
  }
  //open process
  hProc = NktHookLibHelpers::OpenProcess(dwDesiredAccess, FALSE, dwPid);
  if (hProc == NULL)
  {
    if ((dwDesiredAccess & (PROCESS_QUERY_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION)) == PROCESS_QUERY_INFORMATION)
    {
      dwDesiredAccess &= (~PROCESS_QUERY_INFORMATION);
      dwDesiredAccess |= PROCESS_QUERY_LIMITED_INFORMATION;
      hProc = NktHookLibHelpers::OpenProcess(dwDesiredAccess, FALSE, dwPid);
    }
  }
  //restore privileges
  if (sTokPriv.PrivilegeCount > 0)
  {
    sTokPriv.Privileges[0].Attributes = 0;
    NktNtAdjustPrivilegesToken(hToken, 0, &sTokPriv, sizeof(sTokPriv), NULL, NULL);
  }
  if (bRevertToSelf != FALSE)
  {
    HANDLE hDummyToken = NULL;
    NktNtSetInformationThread(NKTHOOKLIB_CurrentThread, (THREADINFOCLASS)ThreadImpersonationToken, &hDummyToken,
                              sizeof(hDummyToken));
  }
  if (hToken != NULL)
    NktNtClose(hToken);
  //done
  return hProc;
}

//-----------------------------------------------------------

CProcessesHandles::CEntry::CEntry(__in DWORD _dwPid, __in HANDLE _h, __in LONG _nPlatform) : TNktLnkLstNode<CEntry>(),
                                                                                             CNktNtHeapBaseObj()
{
  dwPid = _dwPid;
  h = _h;
  nPlatform = _nPlatform;
  _InterlockedExchange(&nRefCount, 1);
  return;
}

CProcessesHandles::CEntry::~CEntry()
{
  NKT_ASSERT(GetLinkedList() == NULL);
  if (h != NULL && h != INVALID_HANDLE_VALUE && h != NKTHOOKLIB_CurrentProcess)
    NktNtClose(h);
  return;
}

VOID CProcessesHandles::CEntry::AddRef()
{
  _InterlockedIncrement(&nRefCount);
  return;
}

VOID CProcessesHandles::CEntry::Release()
{
  if (_InterlockedDecrement(&nRefCount) == 0)
    delete this;
  return;
}

LONG CProcessesHandles::CEntry::GetCurrPlatform()
{
  LONG volatile nPlatform = (LONG)-1;

  if (nPlatform == (LONG)-1)
  {
    LONG _plat = NktHookLibHelpers::GetProcessPlatform(NKTHOOKLIB_CurrentProcess);
    if (NT_SUCCESS(_plat))
      _InterlockedExchange(&nPlatform, _plat);
  }
  return nPlatform;
}

LPBYTE CProcessesHandles::CEntry::AllocateStub(__in LPVOID lpRefAddr, __in SIZE_T nSlotSize)
{
  TNktLnkLst<CMemBlock>::Iterator it;
  CMemBlock *lpBlock;
  LPBYTE lpPtr;
#if defined(_M_X64)
  ULONGLONG nMin, nMax;
#endif //_M_X64

#if defined(_M_X64)
  //calculate min/max address
  nMin = nMax = ((ULONGLONG)(SIZE_T)lpRefAddr) & (~65535ui64);
  if (nMin > 0x40000000ui64)
    nMin -= 0x40000000ui64;
  else
    nMin = 0ui64;
  if (nMax < 0xFFFFFFFFFFFFFFFFui64-0x40000000ui64)
    nMax += 0x40000000ui64;
  else
    nMax = 0xFFFFFFFFFFFFFFFFui64;
#endif //_M_X64
  //find a previously allocated block
  for (lpBlock=it.Begin(cMemBlocksList); lpBlock!=NULL; lpBlock=it.Next())
  {
#if defined(_M_X64)
    if ((ULONGLONG)(SIZE_T)(lpBlock->GetBaseAddress()) >= nMin &&
        (ULONGLONG)(SIZE_T)(lpBlock->GetBaseAddress()) < nMax &&
        lpBlock->GetSlotSize() == nSlotSize)
    {
#endif //_M_X64
      lpPtr = lpBlock->GetFreeSlot();
      if (lpPtr != NULL)
        return lpPtr;
#if defined(_M_X64)
    }
#endif //_M_X64
  }
  lpBlock = new CMemBlock(GetHandle(), nSlotSize);
  if (lpBlock == NULL)
    return NULL;
  if (lpBlock->Initialize(
#if defined(_M_X64)
    nMin, nMax
#endif //_M_X64
    ) == FALSE)
  {
    delete lpBlock;
    return NULL;
  }
  cMemBlocksList.PushHead(lpBlock);
  return lpBlock->GetFreeSlot();
};

VOID CProcessesHandles::CEntry::FreeStub(__in LPVOID lpAddr)
{
  TNktLnkLst<CMemBlock>::Iterator it;
  CMemBlock *lpBlock;

  for (lpBlock=it.Begin(cMemBlocksList); lpBlock!=NULL; lpBlock=it.Next())
  {
    if (lpBlock->IsAddressInBlock(lpAddr) != FALSE)
    {
      lpBlock->ReleaseSlot(lpAddr);
      return;
    }
  }
  NKT_ASSERT(FALSE);
  return;
};

//-----------------------------------------------------------

CProcessesHandles::CEntry::CMemBlock::CMemBlock(__in HANDLE _hProc,
                                                __in SIZE_T _nSlotSize) : TNktLnkLstNode<CMemBlock>(),
                                                                          CNktNtHeapBaseObj()
{
  SIZE_T nFreeEntriesSize;

  NKT_ASSERT(_nSlotSize > 0 && _nSlotSize <= 65536);
  NKT_ASSERT((_nSlotSize && !(_nSlotSize & (_nSlotSize - 1))) != false); //_nSlotSize must be a power of 2
  hProc = _hProc;
  nSlotSize = _nSlotSize;
  nFreeEntriesSize = ((65536 / nSlotSize) + 7) >> 3;
  lpFreeEntries = (LPBYTE)NktHookLibHelpers::MemAlloc(nFreeEntriesSize);
  if (lpFreeEntries != NULL)
    NktHookLibHelpers::MemSet(lpFreeEntries, 0xFF, nFreeEntriesSize);
  nFreeCount = 65536 / nSlotSize;
  lpBaseAddress = NULL;
  return;
}

CProcessesHandles::CEntry::CMemBlock::~CMemBlock()
{
  SIZE_T nSize;

  if (lpBaseAddress != NULL && nFreeCount >= (65536 / nSlotSize))
  {
    nSize = 0;
    NktNtFreeVirtualMemory(hProc, (PVOID*)&lpBaseAddress, &nSize, MEM_RELEASE);
  }
  if (lpFreeEntries != NULL)
    NktHookLibHelpers::MemFree(lpFreeEntries);
  return;
}

#if defined(_M_IX86)
BOOL CProcessesHandles::CEntry::CMemBlock::Initialize()
{
  SIZE_T nSize;
  NTSTATUS nNtStatus;

  if (lpFreeEntries == NULL)
    return FALSE;
  lpBaseAddress = NULL;
  nSize = 65536;
  nNtStatus = NktNtAllocateVirtualMemory(hProc, (PVOID*)&lpBaseAddress, 0, &nSize, MEM_RESERVE|MEM_COMMIT,
                                         PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(nNtStatus))
    lpBaseAddress = NULL;
  return (lpBaseAddress != NULL) ? TRUE : FALSE;
}

#elif defined(_M_X64)
BOOL CProcessesHandles::CEntry::CMemBlock::Initialize(__in ULONGLONG nMin, __in ULONGLONG nMax)
{
  MEMORY_BASIC_INFORMATION sMbi;
  SIZE_T nSize, nResultLength;
  NTSTATUS nNtStatus;

  if (lpFreeEntries == NULL)
    return FALSE;
  if (nMin < 65536)
    nMin = 65536;
  while (nMin < nMax)
  {
    NktHookLibHelpers::MemSet(&sMbi, 0, sizeof(sMbi));
    nNtStatus = NktNtQueryVirtualMemory(hProc, (PVOID)nMin, MyMemoryBasicInformation, &sMbi, sizeof(sMbi),
                                        &nResultLength);
    if (NT_SUCCESS(nNtStatus) && sMbi.State == MEM_FREE)
    {
      lpBaseAddress = (LPBYTE)nMin;
      nSize = 65536;
      nNtStatus = NktNtAllocateVirtualMemory(hProc, (PVOID*)&lpBaseAddress, 0, &nSize, MEM_RESERVE|MEM_COMMIT,
                                             PAGE_EXECUTE_READWRITE);

      if (NT_SUCCESS(nNtStatus))
        return TRUE;
    }
    nMin += 65536;
  }
  lpBaseAddress = NULL;
  return FALSE;
}
#endif

LPBYTE CProcessesHandles::CEntry::CMemBlock::GetFreeSlot()
{
  SIZE_T i, nIdx, nFreeEntriesSize;

  if (nFreeCount == 0)
    return NULL;
  nFreeEntriesSize = ((65536 / nSlotSize) + 7) >> 3;
  for (nIdx=0; nIdx<nFreeEntriesSize; nIdx++)
  {
    if (lpFreeEntries[nIdx] != 0)
      break;
  }
  NKT_ASSERT(nIdx < nFreeEntriesSize);
  for (i=0; i<8; i++)
  {
    if ((lpFreeEntries[nIdx] & (1<<i)) != 0)
      break;
  }
  NKT_ASSERT(i < 8);
  lpFreeEntries[nIdx] &= ~(1<<i);
  nFreeCount--;
  return lpBaseAddress + ((nIdx<<3) + i) * nSlotSize;
}

VOID CProcessesHandles::CEntry::CMemBlock::ReleaseSlot(__in LPVOID lpAddr)
{
  SIZE_T nOfs;
  BYTE nMask;

  NKT_ASSERT((SIZE_T)(LPBYTE)lpAddr >= (SIZE_T)lpBaseAddress);
  nOfs = (SIZE_T)(LPBYTE)lpAddr - (SIZE_T)lpBaseAddress;
  NKT_ASSERT((nOfs % nSlotSize) == 0);
  nOfs /= nSlotSize;
  NKT_ASSERT((nOfs>>3) < ((65536 / nSlotSize) + 7) >> 3);
  nMask = 1 << (nOfs & 7);
  nOfs >>= 3;
  NKT_ASSERT((lpFreeEntries[nOfs] & nMask) == 0);
  lpFreeEntries[nOfs] |= nMask;
  nFreeCount++;
  return;
}

BOOL CProcessesHandles::CEntry::CMemBlock::IsAddressInBlock(__in LPVOID lpAddr)
{
  return ((SIZE_T)lpAddr >= (SIZE_T)lpBaseAddress &&
          (SIZE_T)lpAddr < (SIZE_T)lpBaseAddress + 65536) ? TRUE : FALSE;
}

//-----------------------------------------------------------

} //Internals
} //NktHookLib
