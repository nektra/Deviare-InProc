@ECHO OFF
ECHO Building package...
DEL /Q /F "%~dp0\DeviareInProcWithSources.zip" >NUL 2>NUL
CD ..
"%~dp0\7Z.EXE" a "%~dp0\DeviareInProcWithSources.zip" "-i@%~dp0\files_with_sources.txt"
CD Installer
