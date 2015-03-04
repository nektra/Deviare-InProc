/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "StdAfx.h"
#include "resource.h"
#include "dllmain.h"
#include "dlldatax.h"
#if _MSC_VER >= 1700
  #ifdef _WIN64
    #include "DeviareLiteCOM_i64_vs2012.c"
  #else //_WIN64
    #include "DeviareLiteCOM_i_vs2012.c"
  #endif //_WIN64
#elif  _MSC_VER >= 1600
  #ifdef _WIN64
    #include "DeviareLiteCOM_i64_vs2010.c"
  #else //_WIN64
    #include "DeviareLiteCOM_i_vs2010.c"
  #endif //_WIN64
#else
  #ifdef _WIN64
    #include "DeviareLiteCOM_i64_vs2008.c"
  #else //_WIN64
    #include "DeviareLiteCOM_i_vs2008.c"
  #endif //_WIN64
#endif

//-----------------------------------------------------------

CDeviareLiteCOMModule _AtlModule;
HINSTANCE hDllInst;

//-----------------------------------------------------------

static LONG __stdcall ICorJitCompiler_compileMethod(__in LPVOID lpThis, __in LPVOID comp, __in LPVOID info,
                                                    __in unsigned flags, __out BYTE **nativeEntry,
                                                    __out ULONG *nativeSizeOfCode);

//-----------------------------------------------------------

// DLL Entry Point
extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
  if (dwReason == DLL_PROCESS_ATTACH)
    hDllInst = hInstance;
#ifdef _MERGE_PROXYSTUB
  if (!PrxDllMain(hInstance, dwReason, lpReserved))
    return FALSE;
#endif
  return _AtlModule.DllMain(dwReason, lpReserved);
}

//-----------------------------------------------------------

CDeviareLiteCOMModule::CDeviareLiteCOMModule() : CAtlDllModuleT<CDeviareLiteCOMModule>()
{
  return;
}

CDeviareLiteCOMModule::~CDeviareLiteCOMModule()
{
  DotNetCoreHooks::Finalize();
  return;
}
