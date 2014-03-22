/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "StdAfx.h"
#include "resource.h"
#include "dllmain.h"
#include "dlldatax.h"

//-----------------------------------------------------------

// Used to determine whether the DLL can be unloaded by OLE
STDAPI DllCanUnloadNow(void)
{
#ifdef _MERGE_PROXYSTUB
  HRESULT hRes = PrxDllCanUnloadNow();
  if (hRes != S_OK)
    return hRes;
#endif //_MERGE_PROXYSTUB
  return _AtlModule.DllCanUnloadNow();
}

// Returns a class factory to create an object of the requested type
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
#ifdef _MERGE_PROXYSTUB
  if (PrxDllGetClassObject(rclsid, riid, ppv) == S_OK)
    return S_OK;
#endif //_MERGE_PROXYSTUB
  return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}

// DllRegisterServer - Adds entries to the system registry
STDAPI DllRegisterServer(void)
{
  // registers object, typelib and all interfaces in typelib
  HRESULT hRes = _AtlModule.DllRegisterServer();
#ifdef _MERGE_PROXYSTUB
  if (FAILED(hRes))
    return hRes;
  hRes = PrxDllRegisterServer();
  if (hRes == E_NOINTERFACE) //patch because all interfaces are local
    hRes = S_OK;
#endif //_MERGE_PROXYSTUB
  return hRes;
}

// DllUnregisterServer - Removes entries from the system registry
STDAPI DllUnregisterServer(void)
{
  HRESULT hRes = _AtlModule.DllUnregisterServer();
#ifdef _MERGE_PROXYSTUB
  if (FAILED(hRes))
    return hRes;
  hRes = PrxDllRegisterServer();
  if (SUCCEEDED(hRes))
    hRes = PrxDllUnregisterServer();
  else if (hRes == E_NOINTERFACE) //patch because all interfaces are local
    hRes = S_OK;
#endif //_MERGE_PROXYSTUB
  return hRes;
}

// DllInstall - Adds/Removes entries to the system registry per user per machine.
STDAPI DllInstall(BOOL bInstall, LPCWSTR pszCmdLine)
{
  HRESULT hRes = E_FAIL;
  static const wchar_t szUserSwitch[] = L"user";

  if (pszCmdLine != NULL)
  {
    if (_wcsnicmp(pszCmdLine, szUserSwitch, _countof(szUserSwitch)) == 0)
    {
      AtlSetPerUserRegistration(true);
    }
  }
  if (bInstall)
  {
    hRes = DllRegisterServer();
    if (FAILED(hRes))
    {
       DllUnregisterServer();
    }
  }
  else
  {
    hRes = DllUnregisterServer();
  }
  return hRes;
}
