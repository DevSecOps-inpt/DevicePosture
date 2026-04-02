param(
    [string]$TaskName = "DevicePostureCollector"
)

$ErrorActionPreference = "Stop"

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$processes = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq "powershell.exe" -and $_.CommandLine -like "*device_posture_collector.ps1*"
} | Select-Object ProcessId, Name, CommandLine

if ($null -eq $task) {
    Write-Host "Scheduled task '$TaskName' is not installed."
}
else {
    $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Host "Task name: $($task.TaskName)"
    Write-Host "Task state: $($task.State)"
    Write-Host "Last run time: $($taskInfo.LastRunTime)"
    Write-Host "Last task result: $($taskInfo.LastTaskResult)"
    Write-Host "Next run time: $($taskInfo.NextRunTime)"
}
Write-Host ""
Write-Host "Collector processes:"
if ($processes) {
    $processes | Format-Table -AutoSize
}
else {
    Write-Host "No matching collector PowerShell process found."
}

$logPath = [Environment]::ExpandEnvironmentVariables("%ProgramData%\\DevicePosture\\collector.log")
Write-Host ""
Write-Host "Collector log: $logPath"
if (Test-Path $logPath) {
    Get-Content -Path $logPath | Select-Object -Last 20
}
else {
    Write-Host "Collector log file does not exist yet."
}
