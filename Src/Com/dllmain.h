/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#pragma once

#include "resource.h"       // main symbols
#include "CustomRegistryMap.h"
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
#include "DotNetCoreHooks.h"
#include "..\..\Include\NktHookLib.h"

//-----------------------------------------------------------

class CDeviareLiteCOMModule : public CAtlDllModuleT<CDeviareLiteCOMModule>
{
public:
  CDeviareLiteCOMModule();
  ~CDeviareLiteCOMModule();

  DECLARE_LIBID(LIBID_DeviareLite)
#ifdef _WIN64
  DECLARE_REGISTRY_APPID_RESOURCEID(IDR_DEVIARELITECOM64, "{7F65AF61-32C2-4f4e-9B91-7C32910503FD}")
#else //_WIN64
  DECLARE_REGISTRY_APPID_RESOURCEID(IDR_DEVIARELITECOM, "{7F65AF62-32C2-4f4e-9B91-7C32910503FD}")
#endif //_WIN64
};

//-----------------------------------------------------------

extern class CDeviareLiteCOMModule _AtlModule;
extern HINSTANCE hDllInst;
