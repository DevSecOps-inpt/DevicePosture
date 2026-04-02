param(
    [string]$TaskName = "DevicePostureCollector",
    [switch]$KeepRuntime
)

$ErrorActionPreference = "Stop"

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    try {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
    }

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "Removed scheduled task '$TaskName'."
}
else {
    Write-Host "Scheduled task '$TaskName' was not found."
}

if (-not $KeepRuntime) {
    $stopScript = Join-Path $PSScriptRoot "stop_collector_runtime.ps1"
    & $stopScript
}
