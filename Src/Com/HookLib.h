/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#pragma once

#include "resource.h"       // main symbols
#if _MSC_VER >= 1700
  #ifdef _WIN64
    #include "DeviareLiteCOM_i64_vs2012.h"
  #else //_WIN64
    #include "DeviareLiteCOM_i_vs2012.h"
  #endif //_WIN64
#elif  _MSC_VER >= 1600
  #ifdef _WIN64
    #include "DeviareLiteCOM_i64_vs2010.h"
  #else //_WIN64
    #include "DeviareLiteCOM_i_vs2010.h"
  #endif //_WIN64
#else
  #ifdef _WIN64
    #include "DeviareLiteCOM_i64_vs2008.h"
  #else //_WIN64
    #include "DeviareLiteCOM_i_vs2008.h"
  #endif //_WIN64
#endif
#include "DllMain.h"
#include "CustomRegistryMap.h"
class CNktHookLibImpl;
class CNktHookInfoImpl;
class CNktHookProcessInfoImpl;
#include "..\..\Include\NktHookLib.h"

//-----------------------------------------------------------

extern HINSTANCE hDllInst;

//-----------------------------------------------------------

// CNktHookLibImpl
class ATL_NO_VTABLE CNktHookLibImpl : public CComObjectRootEx<CComMultiThreadModel>,
                                      public CComCoClass<CNktHookLibImpl, &CLSID_NktHookLib>,
                                      public IObjectSafetyImpl<CNktHookLibImpl, INTERFACESAFE_FOR_UNTRUSTED_CALLER>,
                                      public IDispatchImpl<INktHookLib, &IID_INktHookLib, &LIBID_DeviareLite, 1, 0>
{
public:
  CNktHookLibImpl() : CComObjectRootEx<CComMultiThreadModel>(),
                      CComCoClass<CNktHookLibImpl, &CLSID_NktHookLib>(),
                      IObjectSafetyImpl<CNktHookLibImpl, INTERFACESAFE_FOR_UNTRUSTED_CALLER>(),
                      IDispatchImpl<INktHookLib, &IID_INktHookLib, &LIBID_DeviareLite, 1, 0>()
    {
    return;
    };

  ~CNktHookLibImpl()
    {
    cHookLib.UnhookAll();
    return;
    };

  DECLARE_REGISTRY_RESOURCEID_EX(IDR_INTERFACEREGISTRAR, L"DeviareLite.NktHookLib", L"1", L"NktHookLib Class",
                                 CLSID_NktHookLib, LIBID_DeviareLite, L"Neutral")

  BEGIN_COM_MAP(CNktHookLibImpl)
    COM_INTERFACE_ENTRY(INktHookLib)
    COM_INTERFACE_ENTRY(IDispatch)
    COM_INTERFACE_ENTRY(IObjectSafety)
    COM_INTERFACE_ENTRY_AGGREGATE(IID_IMarshal, cUnkMarshaler.p)
  END_COM_MAP()

  // ISupportsErrorInfo
  STDMETHOD(InterfaceSupportsErrorInfo)(REFIID riid);

  DECLARE_PROTECT_FINAL_CONSTRUCT()

  DECLARE_GET_CONTROLLING_UNKNOWN()

  HRESULT FinalConstruct()
    {
    return ::CoCreateFreeThreadedMarshaler(GetControllingUnknown(), &(cUnkMarshaler.p));
    };

  void FinalRelease()
    {
    cUnkMarshaler.Release();
    return;
    };

public:
  STDMETHOD(Hook)(__in VARIANT itemsToHook, __in LONG flags);
  STDMETHOD(RemoteHook)(__in VARIANT itemsToHook, __in LONG pid, __in LONG flags);

  STDMETHOD(Unhook)(__in VARIANT itemsToUnhook);
  STDMETHOD(UnhookProcess)(__in LONG pid);
  STDMETHOD(UnhookAll)();

  STDMETHOD(EnableHook)(__in VARIANT items, __in VARIANT_BOOL enable);

  STDMETHOD(RemoveHook)(__in VARIANT items, __in VARIANT_BOOL disable);

  STDMETHOD(put_SuspendThreadsWhileHooking)(__in VARIANT_BOOL enable);
  STDMETHOD(get_SuspendThreadsWhileHooking)(__out VARIANT_BOOL *enable);

  STDMETHOD(put_ShowDebugOutput)(__in VARIANT_BOOL enable);
  STDMETHOD(get_ShowDebugOutput)(__out VARIANT_BOOL *enable);

  STDMETHOD(GetModuleBaseAddress)(__in BSTR moduleName, __out my_ssize_t *baseAddress);
  STDMETHOD(GetRemoteModuleBaseAddress)(__in LONG pid, __in BSTR moduleName, __in VARIANT_BOOL scanMappedImages,
                                        __out my_ssize_t *baseAddress);

  STDMETHOD(GetProcedureAddress)(__in my_ssize_t moduleBaseAddress, __in BSTR procName, __out my_ssize_t *funcAddress);
  STDMETHOD(GetRemoteProcedureAddress)(__in LONG pid, __in my_ssize_t moduleBaseAddress, __in BSTR procName,
                                       __out my_ssize_t *funcAddress);

  STDMETHOD(CreateProcessWithDll)(__in BSTR applicationName, __in BSTR commandLine, __in my_ssize_t processAttributes,
                                  __in my_ssize_t threadAttributes, __in VARIANT_BOOL inheritHandles,
                                  __in LONG creationFlags, __in BSTR environment, __in BSTR currentDirectory,
                                  __in my_ssize_t startupInfo, __in BSTR dllName,
                                  __deref_out INktHookProcessInfo **ppProcInfo);

  STDMETHOD(CreateProcessWithLogonAndDll)(__in BSTR userName, __in BSTR domain, __in BSTR password,
                                          __in LONG logonFlags, __in BSTR applicationName, __in BSTR commandLine,
                                          __in LONG creationFlags, __in BSTR environment, __in BSTR currentDirectory,
                                          __in my_ssize_t startupInfo, __in BSTR dllName,
                                          __deref_out INktHookProcessInfo **ppProcInfo);

  STDMETHOD(CreateProcessWithTokenAndDll)(__in my_ssize_t token, __in LONG logonFlags, __in BSTR applicationName,
                                          __in BSTR commandLine, __in LONG creationFlags, __in BSTR environment,
                                          __in BSTR currentDirectory, __in my_ssize_t startupInfo, __in BSTR dllName,
                                          __deref_out INktHookProcessInfo **ppProcInfo);

private:
  friend class CNktHookInfoImpl;

  class CHookInfo
  {
  public:
    CHookInfo();
    ~CHookInfo();

    HRESULT Init(__in VARIANT items);
    VOID StoreInfo();

  public:
    CNktHookLib::HOOK_INFO *lpInfo;
    INktHookInfo **lplpHookInfoPtr;
    SIZE_T nCount;
  };

private:
  CNktHookLib cHookLib;
  //----
  CComPtr<IUnknown> cUnkMarshaler;
};

//-----------------------------------------------------------

OBJECT_ENTRY_AUTO(__uuidof(NktHookLib), CNktHookLibImpl)
