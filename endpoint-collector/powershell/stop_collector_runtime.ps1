param()

$ErrorActionPreference = "Stop"

$selfId = $PID
$targets = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq "powershell.exe" -and
    $_.ProcessId -ne $selfId -and
    $_.CommandLine -like "*device_posture_collector.ps1*" -and
    $_.CommandLine -like "*-Mode*" -and
    $_.CommandLine -like "*Run*"
}

if (-not $targets) {
    Write-Host "No running collector runtime process found."
    exit 0
}

foreach ($target in $targets) {
    try {
        Stop-Process -Id $target.ProcessId -Force -ErrorAction Stop
        Write-Host "Stopped collector runtime process PID $($target.ProcessId)."
    }
    catch {
        Write-Warning "Failed to stop collector runtime process PID $($target.ProcessId): $($_.Exception.Message)"
    }
}
