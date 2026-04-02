param(
    [string]$TaskName = "DevicePostureCollector",
    [string]$ConfigPath = "",
    [ValidateSet("Startup", "Logon")]
    [string]$TriggerType = "Logon",
    [ValidateSet("CurrentUser", "System")]
    [string]$RunAs = "CurrentUser",
    [switch]$StartNow
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot "collector.config.json"
}

$collectorPath = Join-Path $PSScriptRoot "device_posture_collector.ps1"
$hiddenLauncherPath = Join-Path $PSScriptRoot "run_collector_hidden.vbs"
if (-not (Test-Path $hiddenLauncherPath)) {
    throw "Hidden launcher not found: $hiddenLauncherPath"
}

$arguments = @(
    "//B",
    "//Nologo",
    ('"{0}"' -f $hiddenLauncherPath),
    ('"{0}"' -f $collectorPath),
    ('"{0}"' -f $ConfigPath)
) -join " "

$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument $arguments

if ($TriggerType -eq "Logon") {
    $trigger = New-ScheduledTaskTrigger -AtLogOn
}
else {
    $trigger = New-ScheduledTaskTrigger -AtStartup
}

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($RunAs -eq "System") {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
}
else {
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
}

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
if ($StartNow -or $TriggerType -eq "Logon") {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
}

$taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
$logPath = [Environment]::ExpandEnvironmentVariables("%ProgramData%\\DevicePosture\\collector.log")
Write-Host "Installed scheduled task '$TaskName' for the PowerShell endpoint agent."
Write-Host "Trigger: $TriggerType"
Write-Host "Principal: $RunAs"
Write-Host "Last task result: $($taskInfo.LastTaskResult)"
Write-Host "Collector log: $logPath"
