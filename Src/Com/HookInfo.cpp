/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "StdAfx.h"
#include "HookLib.h"
#include "HookInfo.h"

//-----------------------------------------------------------

STDMETHODIMP CNktHookInfoImpl::InterfaceSupportsErrorInfo(REFIID riid)
{
  static const IID* arr[] = { &IID_INktHookInfo, NULL };
  SIZE_T i;

  for (i=0; arr[i]!=NULL; i++)
  {
    if (InlineIsEqualGUID(*arr[i], riid))
      return S_OK;
  }
  return S_FALSE;
}

STDMETHODIMP CNktHookInfoImpl::get_Id(__out LONG *hookId)
{
  if (hookId == NULL)
    return E_POINTER;
  *hookId = (LONG)(ULONG)(sInfo.nHookId);
  return S_OK;
}

STDMETHODIMP CNktHookInfoImpl::get_OrigProcAddr(__out my_ssize_t *procAddr)
{
  if (procAddr == NULL)
    return E_POINTER;
  *procAddr = (my_ssize_t)(sInfo.lpProcToHook);
  return S_OK;
}

STDMETHODIMP CNktHookInfoImpl::put_OrigProcAddr(__in my_ssize_t procAddr)
{
  sInfo.lpProcToHook = (LPVOID)(SIZE_T)procAddr;
  return S_OK;
}

STDMETHODIMP CNktHookInfoImpl::get_NewProcAddr(__out my_ssize_t *procAddr)
{
  if (procAddr == NULL)
    return E_POINTER;
  *procAddr = (my_ssize_t)(sInfo.lpNewProcAddr);
  return S_OK;
}

STDMETHODIMP CNktHookInfoImpl::put_NewProcAddr(__in my_ssize_t procAddr)
{
  sInfo.lpNewProcAddr = (LPVOID)(SIZE_T)procAddr;
  return S_OK;
}

STDMETHODIMP CNktHookInfoImpl::get_CallOriginalAddr(__out my_ssize_t *procAddr)
{
  if (procAddr == NULL)
    return E_POINTER;
  *procAddr = (my_ssize_t)(sInfo.lpCallOriginal);
  return S_OK;
}
