param(
    [string]$LauncherName = "DevicePostureCollector.vbs",
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot "collector.config.json"
}

$startupFolder = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
$launcherPath = Join-Path $startupFolder $LauncherName
$legacyCmdPath = Join-Path $startupFolder "DevicePostureCollector.cmd"
$collectorPath = Join-Path $PSScriptRoot "device_posture_collector.ps1"

$launcherContent = @"
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$collectorPath"" -Mode Run -ConfigPath ""$ConfigPath"" -Quiet", 0, False
"@

if (Test-Path $legacyCmdPath) {
    Remove-Item -Path $legacyCmdPath -Force
}

Set-Content -Path $launcherPath -Value $launcherContent -Encoding ASCII
Write-Host "Installed startup launcher: $launcherPath"
Write-Host "Collector log: $([Environment]::ExpandEnvironmentVariables('%ProgramData%\\DevicePosture\\collector.log'))"
