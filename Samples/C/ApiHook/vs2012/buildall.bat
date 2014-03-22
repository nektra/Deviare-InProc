@ECHO OFF
SETLOCAL
IF NOT "%VCINSTALLDIR%" == "" GOTO do_process
IF "%VS110COMNTOOLS%" == "" GOTO show_err

:do_process
CALL "%VS110COMNTOOLS%\..\..\VC\vcvarsall.bat" x86
IF "%VS110COMNTOOLS%" == "" GOTO err_cantsetupvs_x86
DEVENV HookTest.sln /rebuild "Release|Win32"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%VS110COMNTOOLS%\..\..\VC\vcvarsall.bat" x64
IF "%VS110COMNTOOLS%" == "" GOTO err_cantsetupvs_x64
DEVENV HookTest.sln /rebuild "Release|x64"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
GOTO end

:show_err
ECHO Please ensure Visual Studio 2012 is installed
GOTO end

:err_cantsetupvs_x86
ECHO Cannot initialize Visual Studio x86 Command Prompt environment
GOTO end

:err_cantsetupvs_x64
ECHO Cannot initialize Visual Studio x64 Command Prompt environment
GOTO end

:bad_compile
ECHO Errors detected while compiling project
GOTO end

:end
ENDLOCAL
