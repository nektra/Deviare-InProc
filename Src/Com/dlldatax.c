// wrapper for dlldata.c

#ifdef _MERGE_PROXYSTUB // merge proxy stub DLL

#define REGISTER_PROXY_DLL //DllRegisterServer, etc.

#define _WIN32_WINNT 0x0500	//for WinNT 4.0 or Win95 with DCOM
//#define USE_STUBLESS_PROXY	//defined only with MIDL switch /Oicf

#pragma comment(lib, "rpcns4.lib")
#pragma comment(lib, "rpcrt4.lib")

#define ENTRY_PREFIX	Prx

#if _MSC_VER >= 1700
  #ifdef _WIN64
    #include "dlldata64_vs2012.c"
    #include "DeviareLiteCOM_p64_vs2012.c"
  #else //_WIN64
    #include "dlldata_vs2012.c"
    #include "DeviareLiteCOM_p_vs2012.c"
  #endif //_WIN64
#elif  _MSC_VER >= 1600
  #ifdef _WIN64
    #include "dlldata64_vs2010.c"
    #include "DeviareLiteCOM_p64_vs2010.c"
  #else //_WIN64
    #include "dlldata_vs2010.c"
    #include "DeviareLiteCOM_p_vs2010.c"
  #endif //_WIN64
#else
  #ifdef _WIN64
    #include "dlldata64_vs2008.c"
    #include "DeviareLiteCOM_p64_vs2008.c"
  #else //_WIN64
    #include "dlldata_vs2008.c"
    #include "DeviareLiteCOM_p_vs2008.c"
  #endif //_WIN64
#endif

#endif //_MERGE_PROXYSTUB
