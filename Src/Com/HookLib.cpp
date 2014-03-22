/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "StdAfx.h"
#include "HookLib.h"
#include "HookInfo.h"

//-----------------------------------------------------------

__inline HRESULT NKT_HRESULT_FROM_WIN32(DWORD dwOsErr)
{
  if (dwOsErr == ERROR_NOT_ENOUGH_MEMORY)
    dwOsErr = ERROR_OUTOFMEMORY;
  return HRESULT_FROM_WIN32(dwOsErr);
}

//-----------------------------------------------------------

STDMETHODIMP CNktHookLibImpl::InterfaceSupportsErrorInfo(REFIID riid)
{
  static const IID* arr[] = { &IID_INktHookLib, NULL };
  SIZE_T i;

  for (i=0; arr[i]!=NULL; i++)
  {
    if (InlineIsEqualGUID(*arr[i], riid))
      return S_OK;
  }
  return S_FALSE;
}

STDMETHODIMP CNktHookLibImpl::Hook(__in VARIANT itemsToHook, __in LONG flags)
{
  return RemoteHook(itemsToHook, ::GetCurrentProcessId(), flags);
}

STDMETHODIMP CNktHookLibImpl::RemoteHook(__in VARIANT itemsToHook, __in LONG pid, __in LONG flags)
{
  CHookInfo cHkInfo;
  HRESULT hRes;

  hRes = cHkInfo.Init(itemsToHook);
  if (SUCCEEDED(hRes))
    hRes = NKT_HRESULT_FROM_WIN32(cHookLib.RemoteHook(cHkInfo.lpInfo, cHkInfo.nCount, (DWORD)pid, (DWORD)flags));
  if (SUCCEEDED(hRes))
    cHkInfo.StoreInfo();
  return hRes;
}

STDMETHODIMP CNktHookLibImpl::Unhook(__in VARIANT itemsToUnhook)
{
  CHookInfo cHkInfo;
  HRESULT hRes;

  hRes = cHkInfo.Init(itemsToUnhook);
  if (SUCCEEDED(hRes))
    hRes = NKT_HRESULT_FROM_WIN32(cHookLib.Unhook(cHkInfo.lpInfo, cHkInfo.nCount));
  return hRes;
}

STDMETHODIMP CNktHookLibImpl::UnhookProcess(__in LONG pid)
{
  cHookLib.UnhookProcess((DWORD)pid);
  return S_OK;
}

STDMETHODIMP CNktHookLibImpl::UnhookAll()
{
  cHookLib.UnhookAll();
  return S_OK;
}

STDMETHODIMP CNktHookLibImpl::EnableHook(__in VARIANT items, __in VARIANT_BOOL enable)
{
  CHookInfo cHkInfo;
  HRESULT hRes;

  hRes = cHkInfo.Init(items);
  if (SUCCEEDED(hRes))
  {
    hRes = NKT_HRESULT_FROM_WIN32(cHookLib.EnableHook(cHkInfo.lpInfo, cHkInfo.nCount,
                                                      (enable != VARIANT_FALSE) ? TRUE : FALSE));
  }
  return hRes;
}

STDMETHODIMP CNktHookLibImpl::put_SuspendThreadsWhileHooking(__in VARIANT_BOOL enable)
{
  cHookLib.SetSuspendThreadsWhileHooking((enable != VARIANT_FALSE) ? TRUE : FALSE);
  return S_OK;
}

STDMETHODIMP CNktHookLibImpl::get_SuspendThreadsWhileHooking(__out VARIANT_BOOL *enable)
{
  if (enable == NULL)
    return E_POINTER;
  *enable = (cHookLib.GetSuspendThreadsWhileHooking() != FALSE) ? VARIANT_TRUE : VARIANT_FALSE;
  return S_OK;
}

STDMETHODIMP CNktHookLibImpl::put_ShowDebugOutput(__in VARIANT_BOOL enable)
{
  cHookLib.SetEnableDebugOutput((enable != VARIANT_FALSE) ? TRUE : FALSE);
  return S_OK;
}

STDMETHODIMP CNktHookLibImpl::get_ShowDebugOutput(__out VARIANT_BOOL *enable)
{
  if (enable == NULL)
    return E_POINTER;
  *enable = (cHookLib.GetEnableDebugOutput() != FALSE) ? VARIANT_TRUE : VARIANT_FALSE;
  return S_OK;
}

//-----------------------------------------------------------

CNktHookLibImpl::CHookInfo::CHookInfo()
{
  lpInfo = NULL;
  lplpHookInfoPtr = NULL;
  nCount = 0;
  return;
}

CNktHookLibImpl::CHookInfo::~CHookInfo()
{
  SIZE_T i;

  if (lplpHookInfoPtr != NULL)
  {
    for (i=0; i<nCount; i++)
    {
      if (lplpHookInfoPtr[i] != NULL)
        lplpHookInfoPtr[i]->Release();
    }
    free(lplpHookInfoPtr);
  }
  if (lpInfo != NULL)
    free(lpInfo);
  return;
}

HRESULT CNktHookLibImpl::CHookInfo::Init(__in VARIANT items)
{
  VARTYPE nVarType;
  union {
    LPVOID pv;
    IUnknown **lpUnk;
    IDispatch **lpDisp;
  };
  CNktHookInfoImpl *lpHookInfoImpl;
  SIZE_T i;
  HRESULT hRes;

  switch (V_VT(&items))
  {
    case VT_DISPATCH:
      if (items.pdispVal == NULL)
        return E_POINTER;
      lpDisp = &(items.pdispVal);
      nCount = 1;
      break;

    case VT_BYREF|VT_DISPATCH:
      if (items.ppdispVal == NULL)
        return E_POINTER;
      lpDisp = items.ppdispVal;
      nCount = 1;
      break;

    case VT_UNKNOWN:
      if (items.punkVal == NULL)
        return E_POINTER;
      lpUnk = &(items.punkVal);
      nCount = 1;
      break;

    case VT_BYREF|VT_UNKNOWN:
      if (items.ppunkVal == NULL)
        return E_POINTER;
      lpUnk = items.ppunkVal;
      nCount = 1;
      break;

    case VT_ARRAY|VT_DISPATCH:
    case VT_ARRAY|VT_UNKNOWN:
      if (items.parray == NULL)
        return E_POINTER;
      //check for vector
      if (::SafeArrayGetDim(items.parray) != 1)
        return E_INVALIDARG;
      //check count
      nCount = (SIZE_T)(items.parray->rgsabound[0].cElements);
      if (nCount < 1)
        return E_INVALIDARG;
      //check type
      hRes = ::SafeArrayGetVartype(items.parray, &nVarType);
      if (FAILED(hRes))
        return hRes;
      if (nVarType != VT_UNKNOWN && nVarType != VT_DISPATCH)
        return E_INVALIDARG;
      break;

    default:
      return E_INVALIDARG;
  }
  //allocate memory
  lpInfo = (CNktHookLib::HOOK_INFO*)malloc(nCount * sizeof(CNktHookLib::HOOK_INFO));
  if (lpInfo == NULL)
    return E_POINTER;
  memset(lpInfo, 0, nCount * sizeof(CNktHookLib::HOOK_INFO));
  lplpHookInfoPtr = (INktHookInfo**)malloc(nCount * sizeof(INktHookInfo*));
  if (lplpHookInfoPtr == NULL)
    return E_POINTER;
  memset(lplpHookInfoPtr, 0, nCount * sizeof(INktHookInfo*));
  //get items
  switch (V_VT(&items))
  {
    case VT_DISPATCH:
    case VT_BYREF|VT_DISPATCH:
      if (lpDisp == NULL)
        return E_POINTER;
      hRes = (*lpDisp)->QueryInterface(IID_INktHookInfo, (LPVOID*)&lplpHookInfoPtr[0]);
      if (FAILED(hRes))
        return hRes;
      lpHookInfoImpl = static_cast<CNktHookInfoImpl*>(lplpHookInfoPtr[0]);
      lpInfo[0] = lpHookInfoImpl->sInfo;
      break;

    case VT_UNKNOWN:
    case VT_BYREF|VT_UNKNOWN:
      if (lpUnk == NULL)
        return E_POINTER;
      hRes = (*lpUnk)->QueryInterface(IID_INktHookInfo, (LPVOID*)&lplpHookInfoPtr[0]);
      if (FAILED(hRes))
        return hRes;
      lpHookInfoImpl = static_cast<CNktHookInfoImpl*>(lplpHookInfoPtr[0]);
      lpInfo[0] = lpHookInfoImpl->sInfo;
      break;

    case VT_ARRAY|VT_DISPATCH:
    case VT_ARRAY|VT_UNKNOWN:
      hRes = ::SafeArrayAccessData(items.parray, &pv);
      if (SUCCEEDED(hRes))
      {
        for (i=0; i<nCount && SUCCEEDED(hRes); i++)
        {
          switch (nVarType)
          {
            case VT_UNKNOWN:
              if (lpUnk[i] != NULL)
                hRes = lpUnk[i]->QueryInterface(IID_INktHookInfo, (LPVOID*)&lplpHookInfoPtr[i]);
              else
                hRes = E_POINTER;
              break;
            case VT_DISPATCH:
              if (lpDisp[i] != NULL)
                hRes = lpDisp[i]->QueryInterface(IID_INktHookInfo, (LPVOID*)&lplpHookInfoPtr[i]);
              else
                hRes = E_POINTER;
              break;
          }
          if (SUCCEEDED(hRes))
          {
            lpHookInfoImpl = static_cast<CNktHookInfoImpl*>(lplpHookInfoPtr[i]);
            lpInfo[i] = lpHookInfoImpl->sInfo;
          }
        }
        ::SafeArrayUnaccessData(items.parray);
      }
      if (FAILED(hRes))
        return hRes;
      break;
  }
  return S_OK;
}

VOID CNktHookLibImpl::CHookInfo::StoreInfo()
{
  CNktHookInfoImpl *lpHookInfoImpl;
  SIZE_T i;

  for (i=0; i<nCount; i++)
  {
    lpHookInfoImpl = static_cast<CNktHookInfoImpl*>(lplpHookInfoPtr[i]);
    lpHookInfoImpl->sInfo = lpInfo[i];
  }
  return;
}
