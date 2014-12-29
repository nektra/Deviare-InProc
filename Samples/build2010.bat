@ECHO OFF
SETLOCAL
IF NOT "%VCINSTALLDIR%" == "" GOTO do_process
IF "%VS100COMNTOOLS%" == "" (
  ECHO Please ensure Visual Studio 2010 is installed
  PAUSE
  GOTO end
)

SETLOCAL
CALL "%VS100COMNTOOLS%\vsvars32.bat" >NUL 2>NUL
ENDLOCAL & SET __VCINSTALLDIR=%VCINSTALLDIR%

:do_process
SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x86
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x86
DEVENV C\ApiHook\vs2010\HookTest.sln /rebuild "Release|Win32"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x64
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x64
DEVENV C\ApiHook\vs2010\HookTest.sln /rebuild "Release|x64"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x86
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x86
DEVENV C\TestDll\vs2010\TestDll.sln /rebuild "Release|Win32"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x64
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x64
DEVENV C\TestDll\vs2010\TestDll.sln /rebuild "Release|x64"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x86
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x86
DEVENV CSharp\ApiHook\vs2010\Test.sln /rebuild "Debug|x86"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x64
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x64
DEVENV CSharp\ApiHook\vs2010\Test.sln /rebuild "Debug|x64"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x86
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x86
DEVENV CSharp\CreateProcessWithDllTest\vs2010\CreateProcessWithDllTest.sln /rebuild "Debug|x86"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x64
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x64
DEVENV CSharp\CreateProcessWithDllTest\vs2010\CreateProcessWithDllTest.sln /rebuild "Debug|x64"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL
GOTO end

:err_cantsetupvs_x86
ENDLOCAL
ECHO Cannot initialize Visual Studio x86 Command Prompt environment
PAUSE
GOTO end

:err_cantsetupvs_x64
ENDLOCAL
ECHO Cannot initialize Visual Studio x64 Command Prompt environment
PAUSE
GOTO end

:bad_compile
ENDLOCAL
ECHO Errors detected while compiling project
PAUSE
GOTO end

:end
ENDLOCAL
