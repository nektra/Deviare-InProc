@ECHO OFF
SETLOCAL

SET __ComnTools=-
SET __SolutionDir=
IF [%~1] == [] (
    ECHO Use: BUILD.BAT [options]
    ECHO Where 'options' can be
    ECHO    /MSVCVERSION ^(2010^|2012^|2013^|2015^)
    ENDLOCAL
    PAUSE
    EXIT /B 1
)

:paramsLoop
IF [%~1] == [] GOTO paramsEnd

IF /I [%~1] == [/MSVCVERSION] (
    IF [%__ComnTools%] NEQ [-] (
        ECHO Error: Visual Studio version already specified
        ENDLOCAL
        PAUSE
        EXIT /B 1
    )
    IF [%~2%] == [] (
        ECHO Error: Missing argument for /MSVCVERSION parameter
        ENDLOCAL
        PAUSE
        EXIT /B 1
    )
    IF /I [%~2] == [2010] (
        SET "__ComnTools=%VS100COMNTOOLS%"
        SET __SolutionDir=vs2010
    ) ELSE IF /I [%~2] == [2012] (
        SET "__ComnTools=%VS110COMNTOOLS%"
        SET __SolutionDir=vs2012
    ) ELSE IF /I [%~2] == [2013] (
        SET "__ComnTools=%VS120COMNTOOLS%"
        SET __SolutionDir=vs2013
    ) ELSE IF /I [%~2] == [2015] (
        SET "__ComnTools=%VS140COMNTOOLS%"
        SET __SolutionDir=vs2015
    ) ELSE (
        ECHO Error: Unsupported Visual Studio version
        ENDLOCAL
        PAUSE
        EXIT /B 1
    )
    SHIFT
) ELSE (
    ECHO Error: Invalid parameter
    ENDLOCAL
    PAUSE
    EXIT /B 1
)
SHIFT & GOTO paramsLoop
:paramsEnd
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
DEVENV "%__SolutionDir%\NktHookLib.sln" /rebuild "Debug|Win32" /project "NktHookLib"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteInterop depends on DeviareLiteCOM
REM DeviareLiteCOM depends on NktHookLib
DEVENV "%__SolutionDir%\NktHookLib.sln" /rebuild "Release|Win32" /project "DeviareLiteInterop" 
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
DEVENV "%__SolutionDir%\NktHookLib.sln" /rebuild "Debug|x64" /project "NktHookLib"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
REM DeviareLiteInterop depends on DeviareLiteCOM
REM DeviareLiteCOM depends on NktHookLib
DEVENV "%__SolutionDir%\NktHookLib.sln" /rebuild "Release|x64" /project "DeviareLiteInterop"
IF NOT %ERRORLEVEL% == 0 goto bad_compile
ENDLOCAL

ENDLOCAL
EXIT /B 0

:bad_compile
ECHO Errors detected while compiling project
ENDLOCAL
PAUSE
EXIT /B 1
