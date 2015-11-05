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

#if _MSC_VER >= 1900
  #define X_LIBPATH "2015"
#elif _MSC_VER >= 1800
  #define X_LIBPATH "2013"
#elif _MSC_VER >= 1700
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

  //check arguments
  if (argc != 3)
  {
    wprintf_s(L"Use: InjectDLL path-to-exe|process-id path-to-dll\n");
    return 1;
  }
  //if first argument is numeric, assume a process ID
  if (argv[1][0] >= L'0' && argv[1][0] <= L'9')
  {
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
  }
  else
  {
    //assume a process path to execute
    dwPid = 0;
  }
  //take dll name
  if (argv[2][0] == 0)
  {
    wprintf_s(L"Error: Invalid dll name specified.\n");
    return 1;
  }
  //execute action
  if (dwPid != 0)
  {

    //if a process ID was specified, inject dll into that process
    dwOsErr = NktHookLibHelpers::InjectDllByPidW(dwPid, argv[2]);
    if (dwOsErr != ERROR_SUCCESS)
    {
      wprintf_s(L"Error: Cannot inject Dll in target process [0x%08X]\n", dwOsErr);
      return 2;
    }
  }
  else
  {
    STARTUPINFOW sSiW;
    PROCESS_INFORMATION sPi;

    memset(&sSiW, 0, sizeof(sSiW));
    sSiW.cb = (DWORD)sizeof(sSiW);
    memset(&sPi, 0, sizeof(sPi));
    dwOsErr = NktHookLibHelpers::CreateProcessWithDllW(argv[1], NULL, NULL, NULL, FALSE, 0, NULL, NULL, &sSiW, &sPi, argv[2]);
    if (dwOsErr != ERROR_SUCCESS)
    {
      wprintf_s(L"Error: Cannot launch process and inject dll [0x%08X]\n", dwOsErr);
      return 2;
    }
    ::CloseHandle(sPi.hThread);
    ::CloseHandle(sPi.hProcess);
  }
  wprintf_s(L"Dll successfully injected!\n");
  return 0;
}
