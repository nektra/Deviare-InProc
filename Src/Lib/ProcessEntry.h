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

#ifndef _NKT_HOOKLIB_PROCESSENTRY_H
#define _NKT_HOOKLIB_PROCESSENTRY_H

#include "..\..\Include\NktHookLib.h"
#include "LinkedList.h"
#include "WaitableObjects.h"
#include "NtHeapBaseObj.h"

namespace NktHookLib {

//-----------------------------------------------------------

class CProcessesHandles
{
public:
  class CEntry : public TNktLnkLstNode<CEntry>, public CNktNtHeapBaseObj
  {
  protected:
    CEntry(__in DWORD dwPid, __in HANDLE h, __in LONG nPlatform);
  public:
    ~CEntry();

  public:
    VOID AddRef();
    VOID Release();

    DWORD GetPid()
      {
      return dwPid;
      };

    HANDLE GetHandle()
      {
      return h;
      };

    LONG GetPlatform()
      {
      return nPlatform;
      };

    LPBYTE AllocateStub(__in LPVOID lpRefAddr, __in SIZE_T nSlotSize);
    VOID FreeStub(__in LPVOID lpAddr);

  private:
    friend class CProcessesHandles;

    class CMemBlock : public TNktLnkLstNode<CMemBlock>, public CNktNtHeapBaseObj
    {
    public:
      CMemBlock(__in HANDLE hProc, __in SIZE_T nSlotSize);
      ~CMemBlock();

#if defined(_M_IX86)
      BOOL Initialize();
#elif defined(_M_X64)
      BOOL Initialize(__in ULONGLONG nMin, __in ULONGLONG nMax);
#else
  #error Platform not supported
#endif

      LPBYTE GetBaseAddress()
        {
        return lpBaseAddress;
        };

      SIZE_T GetSlotSize() const
        {
        return nSlotSize;
        };

      LPBYTE GetFreeSlot();
      VOID ReleaseSlot(__in LPVOID lpAddr);

      BOOL IsAddressInBlock(__in LPVOID lpAddr);

    private:
      HANDLE hProc;
      SIZE_T nSlotSize;
      LPBYTE lpBaseAddress;
      LPBYTE lpFreeEntries;
      SIZE_T nFreeCount;
    };

    static LONG GetCurrPlatform();

    DWORD dwPid;
    HANDLE h;
    LONG nPlatform;
    LONG volatile nRefCount;
    TNktLnkLst<CMemBlock> cMemBlocksList;
  };

public:
  class CEntryPtr
  {
  public:
    CEntryPtr()
      {
      lpEntry = NULL;
      return;
      };

    ~CEntryPtr()
      {
      if (lpEntry != NULL)
        lpEntry->Release();
      return;
      };

    VOID operator=(__in CEntry *_lpEntry)
      {
      if (lpEntry != NULL)
        lpEntry->Release();
      lpEntry = _lpEntry;
      if (lpEntry != NULL)
        lpEntry->AddRef();
      return;
      };

    VOID Attach(__in CEntry *_lpEntry)
      {
      if (lpEntry != NULL)
        lpEntry->Release();
      lpEntry = _lpEntry;
      return;
      };

    CEntry* Detach()
      {
      CEntry *_lpEntry = lpEntry;
      lpEntry = NULL;
      return _lpEntry;
      };

    CEntry* operator->() const
      {
      return lpEntry;
      };

    BOOL operator!() const
      {
      return (lpEntry == NULL) ? TRUE : FALSE;
      };

    BOOL operator==(CEntry* _lpEntry) const
      {
      return (lpEntry == _lpEntry) ? TRUE : FALSE;
      };

    operator CEntry*() const
      {
      return lpEntry;
      };

  private:
    CEntry *lpEntry;
  };

public:
  CProcessesHandles();
  ~CProcessesHandles();

  CEntry* Get(__in DWORD dwPid);

  static HANDLE CreateHandle(__in DWORD dwPid, __in DWORD dwDesiredAccess);

private:
  CNktFastMutex cMtx;
  TNktLnkLst<CEntry> cEntries;
};

//-----------------------------------------------------------

} //NktHookLib

#endif //_NKT_HOOKLIB_PROCESSENTRY_H
