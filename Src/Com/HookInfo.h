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
#include "CustomRegistryMap.h"
#include "DllMain.h"
class CNktHookLibImpl;
class CNktHookInfoImpl;
#include "..\..\Include\NktHookLib.h"

//-----------------------------------------------------------

extern HINSTANCE hDllInst;

//-----------------------------------------------------------

// CNktHookInfoImpl
class ATL_NO_VTABLE CNktHookInfoImpl : public CComObjectRootEx<CComMultiThreadModel>,
                                       public CComCoClass<CNktHookInfoImpl, &CLSID_NktHookInfo>,
                                       public IObjectSafetyImpl<CNktHookInfoImpl, INTERFACESAFE_FOR_UNTRUSTED_CALLER>,
                                       public IDispatchImpl<INktHookInfo, &IID_INktHookInfo, &LIBID_DeviareLite, 1, 0>
{
public:
  CNktHookInfoImpl() : CComObjectRootEx<CComMultiThreadModel>(),
                       CComCoClass<CNktHookInfoImpl, &CLSID_NktHookInfo>(),
                       IObjectSafetyImpl<CNktHookInfoImpl, INTERFACESAFE_FOR_UNTRUSTED_CALLER>(),
                       IDispatchImpl<INktHookInfo, &IID_INktHookInfo, &LIBID_DeviareLite, 1, 0>()
    {
    memset(&sInfo, 0, sizeof(sInfo));
    return;
    };

  ~CNktHookInfoImpl()
    {
    return;
    };

  DECLARE_REGISTRY_RESOURCEID_EX(IDR_INTERFACEREGISTRAR, L"DeviareLite.NktHookInfo", L"1", L"NktHookInfo Class",
                                 CLSID_NktHookInfo, LIBID_DeviareLite, L"Neutral")

  BEGIN_COM_MAP(CNktHookInfoImpl)
    COM_INTERFACE_ENTRY(INktHookInfo)
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
  STDMETHOD(get_Id)(__out LONG *hookId);

  STDMETHOD(get_OrigProcAddr)(__out my_ssize_t *procAddr);
  STDMETHOD(put_OrigProcAddr)(__in my_ssize_t procAddr);

  STDMETHOD(get_NewProcAddr)(__out my_ssize_t *procAddr);
  STDMETHOD(put_NewProcAddr)(__in my_ssize_t procAddr);

  STDMETHOD(get_CallOriginalAddr)(__out my_ssize_t *procAddr);

private:
  friend class CNktHookLibImpl::CHookInfo;

  CNktHookLib::HOOK_INFO sInfo;
  //----
  CComPtr<IUnknown> cUnkMarshaler;
};

//-----------------------------------------------------------

OBJECT_ENTRY_AUTO(__uuidof(NktHookInfo), CNktHookInfoImpl)
