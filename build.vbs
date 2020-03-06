Option Explicit
Const DontShowWindow = 0
Const DoShowWindow = 1
Const WaitUntilFinished = True
Const ForReading = 1
Const TristateFalse = 0
Const WshRunning = 0
Dim szBaseFolder, szMsBuildExe
Dim nErr, nVsVersion

If WScript.Arguments.Count < 1 Then
	WScript.Echo "Use: CSCRIPT build.vbs VS-Version"
	WScript.Echo ""
	WScript.Echo "Where 'VS-Version' can be 2010, 20112, 2013, 2015, 2017 or 2019"
	WScript.Quit 1
End If
nVsVersion = CInt(WScript.Arguments.Item(0))
If nVsVersion <> 2010 And nVsVersion <> 2012 And nVsVersion <> 2013 And nVsVersion <> 2015 And nVsVersion <> 2017 And nVsVersion <> 2019 Then
	WScript.Echo "Error: Unsupported Visual Studio version"
	WScript.Quit 1
End If

szBaseFolder = Left(WScript.ScriptFullName, Len(WScript.ScriptFullName) - Len(WScript.ScriptName))

'-------------------------------------------------------------------------------
'Locate MSBUILD

szMsBuildExe = FindMsBuild()
If Len(szMsBuildExe) = 0 Then
	WScript.Echo "Error: Unable to locate Microsoft Visual Studio " & CStr(nVsVersion)
	WScript.Quit 1
End If

'-------------------------------------------------------------------------------
'Compile projects

'NktHookLib_2013
'DeviareLiteCOM_2013
'DeviareLiteInterop_2013
'Obj2Inc
'HookTest_2013
'InjectDll_2013
'TestDll_2013
'Test_2013
'CreateProcessWithDllTest_2013

nErr = CompileSolution("NktHookLib_" & CStr(nVsVersion) & ".sln", "Debug;Release", "Win32", "/t:rebuild")
If nErr = 0 Then
	nErr = CompileSolution("NktHookLib_" & CStr(nVsVersion) & ".sln", "Debug;Release", "x64", "/t:rebuild")
End If

'-------------------------------------------------------------------------------
'Done

If nErr <> 0 Then
	WScript.Echo "Error: Unable to complete code compilation"
	WScript.Quit 1
End If

WScript.Echo "Compilation succeeded!"
WScript.Quit 0

'-------------------------------------------------------------------------------


Function FindMsBuild()
Dim oFso, oShell, oApp
Dim S, szApp, szVersion
Dim I

	szApp = ""
	Set oFso = CreateObject("Scripting.FileSystemObject")
	Set oShell = CreateObject("WScript.Shell")

	If nVsVersion >= 2017 Then

		If nVsVersion = 2017 Then
			szVersion = "[15.0,16.0)"
		Else
			szVersion = "[16.0,17.0)"
		End If
		S = szBaseFolder & "vswhere.exe -version " & szVersion & " -property installationPath -requires Microsoft.Component.MSBuild"

		Set oApp = oShell.Exec(S)
		Do While Not oApp.StdOut.AtEndOfStream
			S = oApp.StdOut.ReadLine()
			If Len(S) > 0 Then
				If Right(S, 1) <> "\" Then S = S & "\"
				If nVsVersion = 2017 Then
					S = S & "MSBuild\15.0\Bin\MsBuild.exe"
				Else
					S = S & "MSBuild\Current\Bin\MsBuild.exe"
				End If
				If oFso.FileExists(S) Then
					szApp = S
					Exit Do
				End If
			End If
		Loop
		Set oApp = Nothing

	Else

		For I = 1 To 2
			S = "HKEY_LOCAL_MACHINE\SOFTWARE\"
			If I = 2 Then S = S & "WOW6432Node\"
			S = S & "Microsoft\VisualStudio\SxS\VS7\"

			If nVsVersion = 2010 Then
				szVersion = "10.0"
			ElseIf nVsVersion = 2012 Then
				szVersion = "11.0"
			ElseIf nVsVersion = 2013 Then
				szVersion = "12.0"
			ElseIf nVsVersion = 2015 Then
				szVersion = "14.0"
			End If

			On Error Resume Next
			S = oShell.RegRead(S & szVersion)
			On Error Goto 0
			If Len(S) > 0 Then
				S = S & "\MSBuild\" & szVersion & "\Bin\MSBuild.exe"
				S = Replace(S, "/", "\", 1, -1, 1)
				S = Replace(S, "\\", "\", 1, -1, 1)
				If oFso.FileExists(S) Then
					szApp = S
					Exit For
				End If
			End If
		Next

	End If

	Set oShell = Nothing
	Set oFso = Nothing

	FindMsBuild = szApp
End Function

'-------------------------------------------------------------------------------

Function RunDosCommand(szCommand, szCurrFolder)
	RunDosCommand = RunApp("CMD.EXE /C " & szCommand, szCurrFolder, False)
End Function

Function RunApp(szCommand, szCurrFolder, bHide)
Dim oShell
Dim S

	Set oShell = CreateObject("WScript.Shell")
	If Len(szCurrFolder) > 0 Then
		oShell.CurrentDirectory = szCurrFolder
	Else
		oShell.CurrentDirectory = szBaseFolder
	End If
	If bHide = False Then
		WScript.Echo "Executing: " & szCommand
	End If
	RunApp = oShell.Run(szCommand, DontShowWindow, WaitUntilFinished)
End Function

'-------------------------------------------------------------------------------

Function CompileSolution(szSolution, szConfigurations, szPlatforms, szExtraParams)
Dim nErr, aConfigurations, aPlatforms, szConfig, szPlatform

	aConfigurations = Split(szConfigurations, ";")
	aPlatforms = Split(szPlatforms, ";")
	For Each szPlatform In aPlatforms
		For Each szConfig In aConfigurations
			nErr = CompileProject(szSolution, szConfig, szPlatform, szExtraParams)
			If nErr <> 0 Then
				CompileSolution = nErr
				Exit Function
			End If
		Next
	Next
	CompileSolution = 0
End Function

Function CompileProject(szSolution, szConfiguration, szPlatform, szExtraParams)
Dim S

	S = Chr(34) & szMsBuildExe & Chr(34)
	S = S & " " & Chr(34) & szBaseFolder & szSolution & Chr(34)
	S = S & " /p:Configuration=" & Chr(34) & szConfiguration & Chr(34)
	S = S & " /p:Platform=" & Chr(34) & szPlatform & Chr(34)
	S = S & " /p:BuildProjectReferences=false /m"
	If szExtraParams <> "" Then
		S = S & " " & szExtraParams
	End If

	CompileProject = RunApp(S, "", False)
End Function
