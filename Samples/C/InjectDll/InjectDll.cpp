/*
 * Copyright (C) 2010-2015 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved. Contact: http://www.nektra.com
 *
 *
 * This file is part of Deviare In-Proc
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial Deviare In-Proc licenses may use this
 * file in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and Nektra.  For licensing terms and
 * conditions see http://www.nektra.com/licensing/.  For further information
 * use the contact form at http://www.nektra.com/contact/.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl.html.
 *
 **/

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "..\..\..\Include\NktHookLib.h"

#define DISALLOW_REENTRANCY

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
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib_Debug.lib")
  #else //_DEBUG
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib.lib")
  #endif //_DEBUG
#elif defined _M_X64
  #ifdef _DEBUG
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib64_Debug.lib")
  #else //_DEBUG
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib64.lib")
  #endif //_DEBUG
#else
  #error Unsupported platform
#endif

//-----------------------------------------------------------

int __CRTDECL wmain(__in int argc, __in wchar_t *argv[], __in wchar_t *envp[])
{
  DWORD dwOsErr, dwPid;
  LPWSTR szStopW;

  if (argc != 3)
  {
    wprintf_s(L"Use: InjectDLL pid path-to-dll\n");
    return 1;
  }
  dwPid = (DWORD)wcstoul(argv[1], &szStopW, 10);
  if (dwPid == 0 || *szStopW != 0)
  {
    wprintf_s(L"Error: Invalid process ID specified.\n");
    return 1;
  }
  if (dwPid == ::GetCurrentProcessId())
  {
    wprintf_s(L"Error: Cannot inject a dll into myself.\n");
    return 1;
  }
  if (argv[2][0] == 0)
  {
    wprintf_s(L"Error: Invalid dll name specified.\n");
    return 1;
  }
  dwOsErr = NktHookLibHelpers::InjectDllByPidW(dwPid, argv[1]);
  if (dwOsErr != ERROR_SUCCESS)
  {
    wprintf_s(L"Error: Cannot inject Dll in target process [0x%08X]\n", dwOsErr);
    return 2;
  }
  wprintf_s(L"Dll successfully injected!\n");
  return 0;
}
