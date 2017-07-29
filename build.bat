@ECHO OFF
SETLOCAL

SET __ComnTools=-
SET __Version=0
IF [%~1] == [] (
    ECHO Use: BUILD.BAT ^(2013^|2015^)
    ENDLOCAL
    PAUSE
    EXIT /B 1
)

IF [%~1%] == [] (
	ECHO Error: Missing argument for /MSVCVERSION parameter
	ENDLOCAL
	PAUSE
	EXIT /B 1
)
IF /I [%~1] == [2013] (
	SET "__ComnTools=%VS120COMNTOOLS%"
	SET __Version=2013
) ELSE IF /I [%~1] == [2015] (
	SET "__ComnTools=%VS140COMNTOOLS%"
	SET __Version=2015
) ELSE (
	ECHO Error: Unsupported Visual Studio version
	ENDLOCAL
	PAUSE
	EXIT /B 1
)

IF [__ComnTools] == [-] (
    ECHO Error: /MSVCVERSION parameter not specified
    ENDLOCAL
    PAUSE
    EXIT /B 1
)

IF "%__ComnTools%" == "" (
    ECHO Error: Ensure Visual Studio is installed
    ENDLOCAL
    PAUSE
    EXIT /B 1
)

SETLOCAL
CALL "%__ComnTools%\vsvars32.bat" >NUL 2>NUL
ENDLOCAL & SET "__VCINSTALLDIR=%VCINSTALLDIR%"

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x86
IF "%VCINSTALLDIR%" == "" (
    ECHO Error: Cannot initialize Visual Studio x86 Command Prompt environment
    ENDLOCAL
    PAUSE
    EXIT /B 1
)
DEVENV "NktHookLib_%__Version%.sln" /rebuild "Debug|Win32"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteInterop depends on DeviareLiteCOM
REM DeviareLiteCOM depends on NktHookLib
DEVENV "NktHookLib_%__Version%.sln" /rebuild "Release|Win32"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

SETLOCAL
CALL "%__VCINSTALLDIR%\vcvarsall.bat" x64
IF "%VCINSTALLDIR%" == "" (
    ECHO Error: Cannot initialize Visual Studio x64 Command Prompt environment
    ENDLOCAL
    PAUSE
    EXIT /B 1
)
DEVENV "NktHookLib_%__Version%.sln" /rebuild "Debug|x64"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteInterop depends on DeviareLiteCOM
REM DeviareLiteCOM depends on NktHookLib
DEVENV "NktHookLib_%__Version%.sln" /rebuild "Release|x64"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

ENDLOCAL
EXIT /B 0

:bad_compile
ECHO Errors detected while compiling project
ENDLOCAL
PAUSE
EXIT /B 1
