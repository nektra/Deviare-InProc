/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "StdAfx.h"

//-----------------------------------------------------------

#if _MSC_VER >= 1700
  #define X_LIBPATH "2012"
#elif  _MSC_VER >= 1600
  #define X_LIBPATH "2010"
#else
  #define X_LIBPATH "2008"
#endif

#if defined _M_IX86
  #ifdef _DEBUG
    #pragma comment (lib, "..\\..\\Libs\\" X_LIBPATH "\\NktHookLib_Debug.lib")
  #else //_DEBUG
    #pragma comment (lib, "..\\..\\Libs\\" X_LIBPATH "\\NktHookLib.lib")
  #endif //_DEBUG
#elif defined _M_X64
  #ifdef _DEBUG
    #pragma comment (lib, "..\\..\\Libs\\" X_LIBPATH "\\NktHookLib64_Debug.lib")
  #else //_DEBUG
    #pragma comment (lib, "..\\..\\Libs\\" X_LIBPATH "\\NktHookLib64.lib")
  #endif //_DEBUG
#else
  #error Unsupported platform
#endif
