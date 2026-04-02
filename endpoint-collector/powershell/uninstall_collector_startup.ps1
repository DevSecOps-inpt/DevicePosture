param(
    [string]$LauncherName = "DevicePostureCollector.vbs",
    [switch]$KeepRuntime
)

$ErrorActionPreference = "Stop"

$startupFolder = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
$launcherPath = Join-Path $startupFolder $LauncherName
$legacyCmdPath = Join-Path $startupFolder "DevicePostureCollector.cmd"

if (Test-Path $launcherPath) {
    Remove-Item -Path $launcherPath -Force
    Write-Host "Removed startup launcher: $launcherPath"
}
else {
    Write-Host "Startup launcher not found: $launcherPath"
}

if (Test-Path $legacyCmdPath) {
    Remove-Item -Path $legacyCmdPath -Force
    Write-Host "Removed legacy startup launcher: $legacyCmdPath"
}

if (-not $KeepRuntime) {
    $stopScript = Join-Path $PSScriptRoot "stop_collector_runtime.ps1"
    & $stopScript
}
