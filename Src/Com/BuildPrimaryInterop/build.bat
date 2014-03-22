@ECHO OFF
ECHO Creating TLB...
COPY /Y "%~dp0\..\DeviareLiteCOM.idl" "%~dp0\DeviareLiteCOM.idl" >NUL
COPY /Y "%~dp0\..\disp_ids.h" "%~dp0\disp_ids.h" >NUL
MIDL "%~dp0\DeviareLiteCOM.idl" /D "NDEBUG" /nologo /char signed /env win32 /tlb "%~dp0\DeviareLiteCOM.tlb" /h "%~dp0\DeviareLiteCOM_i.h" /dlldata "%~dp0\dlldata.c" /iid "%~dp0\DeviareLiteCOM_i.c" /proxy "%~dp0\DeviareLiteCOM_p.c" /error all /error stub_data /Os
IF NOT %ERRORLEVEL% == 0 goto bad_compile

TLBIMP "%~dp0\DeviareLiteCOM.tlb" /primary "/keyfile:%~dp0\keypair.snk" /transform:dispret "/out:%~1\Nektra.DeviareLite.dll"
IF NOT %ERRORLEVEL% == 0 goto bad_interopbuild

GOTO end

:bad_compile
ECHO Errors detected while compiling IDL file
GOTO end

:bad_interopbuild
ECHO Errors detected while building Primary Interop Assembly
GOTO end

:end
DEL /Q "%~dp0\DeviareLiteCOM*.c" >NUL 2>NUL
DEL /Q "%~dp0\DeviareLiteCOM*.h" >NUL 2>NUL
DEL /Q "%~dp0\dlldata*.c" >NUL 2>NUL
