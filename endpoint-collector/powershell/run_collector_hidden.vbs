Option Explicit

Dim shell
Dim collectorScriptPath
Dim configPath
Dim command

If WScript.Arguments.Count < 2 Then
    WScript.Quit 1
End If

collectorScriptPath = WScript.Arguments(0)
configPath = WScript.Arguments(1)

command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & collectorScriptPath & """ -Mode Run -ConfigPath """ & configPath & """ -Quiet"

Set shell = CreateObject("WScript.Shell")
shell.Run command, 0, False
