/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "StdAfx.h"
#include "HookLib.h"
#include "HookProcessInfo.h"

//-----------------------------------------------------------

STDMETHODIMP CNktHookProcessInfoImpl::InterfaceSupportsErrorInfo(REFIID riid)
{
  static const IID* arr[] = { &IID_INktHookProcessInfo, NULL };
  SIZE_T i;

  for (i=0; arr[i]!=NULL; i++)
  {
    if (InlineIsEqualGUID(*arr[i], riid))
      return S_OK;
  }
  return S_FALSE;
}

STDMETHODIMP CNktHookProcessInfoImpl::get_ProcessHandle(__out my_ssize_t *procHandle)
{
  if (procHandle == NULL)
    return E_POINTER;
  *procHandle = (my_ssize_t)(sProcInfo.hProcess);
  return S_OK;
}

STDMETHODIMP CNktHookProcessInfoImpl::get_ThreadHandle(__out my_ssize_t *threadHandle)
{
  if (threadHandle == NULL)
    return E_POINTER;
  *threadHandle = (my_ssize_t)(sProcInfo.hThread);
  return S_OK;
}

STDMETHODIMP CNktHookProcessInfoImpl::get_ProcessId(__out LONG *pid)
{
  if (pid == NULL)
    return E_POINTER;
  *pid = (LONG)(sProcInfo.dwProcessId);
  return S_OK;
}

STDMETHODIMP CNktHookProcessInfoImpl::get_ThreadId(__out LONG *tid)
{
  if (tid == NULL)
    return E_POINTER;
  *tid = (LONG)(sProcInfo.dwThreadId);
  return S_OK;
}
