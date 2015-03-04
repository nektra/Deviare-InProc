@ECHO OFF
SETLOCAL
IF NOT "%VCINSTALLDIR%" == "" GOTO do_process
IF "%VS110COMNTOOLS%" == "" (
  ECHO Please ensure Visual Studio 2012 is installed
  PAUSE
  GOTO end
)

SETLOCAL
CALL "%VS110COMNTOOLS%\vsvars32.bat" >NUL 2>NUL
ENDLOCAL & SET __VCINSTALLDIR=%VCINSTALLDIR%

:do_process
SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x86
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x86
DEVENV vs2012\NktHookLib.sln /rebuild "Debug|Win32" /project "NktHookLib"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteInterop depends on DeviareLiteCOM
REM DeviareLiteCOM depends on NktHookLib
DEVENV vs2012\NktHookLib.sln /rebuild "Release|Win32" /project "DeviareLiteInterop" 
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x64
IF "%VCINSTALLDIR%" == "" GOTO err_cantsetupvs_x64
DEVENV vs2012\NktHookLib.sln /rebuild "Debug|x64" /project "NktHookLib"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteInterop depends on DeviareLiteCOM
REM DeviareLiteCOM depends on NktHookLib
DEVENV vs2012\NktHookLib.sln /rebuild "Release|x64" /project "DeviareLiteInterop"
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
