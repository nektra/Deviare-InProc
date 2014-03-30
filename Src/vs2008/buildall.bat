@ECHO OFF
SETLOCAL
IF NOT "%VCINSTALLDIR%" == "" GOTO do_process
IF "%VS90COMNTOOLS%" == "" GOTO show_err

:do_process
CALL "%VS90COMNTOOLS%\..\..\VC\vcvarsall.bat" x86
IF "%VS90COMNTOOLS%" == "" GOTO err_cantsetupvs_x86
DEVENV NktHookLib.sln /rebuild "Debug|Win32" /project "NktHookLib"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteCOM depends on NktHookLib
DEVENV NktHookLib.sln /rebuild "Release|Win32" /project "DeviareLiteCOM"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%VS90COMNTOOLS%\..\..\VC\vcvarsall.bat" x64
IF "%VS90COMNTOOLS%" == "" GOTO err_cantsetupvs_x64
DEVENV NktHookLib.sln /rebuild "Debug|x64" /project "NktHookLib"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteCOM depends on NktHookLib
DEVENV NktHookLib.sln /rebuild "Release|x64" /project "DeviareLiteCOM"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
GOTO end

:show_err
ECHO Please ensure Visual Studio 2008 is installed
PAUSE
GOTO end

:err_cantsetupvs_x86
ECHO Cannot initialize Visual Studio x86 Command Prompt environment
PAUSE
GOTO end

:err_cantsetupvs_x64
ECHO Cannot initialize Visual Studio x64 Command Prompt environment
PAUSE
GOTO end

:bad_compile
ECHO Errors detected while compiling project
PAUSE
GOTO end

:end
ENDLOCAL
