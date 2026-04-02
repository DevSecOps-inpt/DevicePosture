param(
    [ValidateSet("setup", "run", "start-all", "stop", "status")]
    [string]$Action = "status",

    [ValidateSet("telemetry-api", "policy-service", "evaluation-engine", "enforcement-service", "python-collector", "python-collector-service", "powershell-collector", "powershell-collector-service", "frontend")]
    [string]$Component = "telemetry-api",

    [string]$RootPath = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$HostAddress = "127.0.0.1",
    [string]$CollectorUrl = "http://127.0.0.1:8011/telemetry",
    [switch]$Insecure
)

$ErrorActionPreference = "Stop"

$VenvPath = Join-Path $RootPath ".venv"
$PythonPath = Join-Path $VenvPath "Scripts\\python.exe"
$RunPath = Join-Path $RootPath ".run"
$LogPath = Join-Path $RootPath ".logs"

$ServiceDefinitions = @{
    "telemetry-api" = @{
        WorkDir = Join-Path $RootPath "services\\telemetry-api"
        Port = 8011
        App = "app.main:app"
        Env = @{}
    }
    "policy-service" = @{
        WorkDir = Join-Path $RootPath "services\\policy-service"
        Port = 8002
        App = "app.main:app"
        Env = @{}
    }
    "evaluation-engine" = @{
        WorkDir = Join-Path $RootPath "services\\evaluation-engine"
        Port = 8003
        App = "app.main:app"
        Env = @{
            TELEMETRY_API_URL = "http://127.0.0.1:8011"
            POLICY_SERVICE_URL = "http://127.0.0.1:8002"
            ENFORCEMENT_SERVICE_URL = "http://127.0.0.1:8004"
        }
    }
    "enforcement-service" = @{
        WorkDir = Join-Path $RootPath "services\\enforcement-service"
        Port = 8004
        App = "app.main:app"
        Env = @{
            FORTIGATE_BASE_URL = "http://127.0.0.1:65535"
            FORTIGATE_TOKEN = "dev-token"
            HTTP_TIMEOUT_SECONDS = "2"
            HTTP_RETRIES = "1"
        }
    }
}

$CollectorDefinitions = @{
    "powershell-collector-service" = @{
        ScriptPath = Join-Path $RootPath "endpoint-collector\\powershell\\device_posture_collector.ps1"
        ConfigPath = Join-Path $RootPath "endpoint-collector\\powershell\\collector.config.json"
        Match = "*device_posture_collector.ps1*"
    }
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Ensure-Venv {
    if (-not (Test-Path $PythonPath)) {
        Write-Host "Creating virtual environment at $VenvPath"
        python -m venv $VenvPath
    }
}

function Install-Repo {
    Ensure-Venv
    Write-Host "Installing shared package and service dependencies..."
    & $PythonPath -m pip install --upgrade pip
    & $PythonPath -m pip install -e (Join-Path $RootPath "shared")

    foreach ($serviceName in @("telemetry-api", "policy-service", "evaluation-engine", "enforcement-service")) {
        $serviceDir = $ServiceDefinitions[$serviceName].WorkDir
        Push-Location $serviceDir
        try {
            & $PythonPath -m pip install -r "requirements.txt"
        }
        finally {
            Pop-Location
        }
    }
}

function Get-EnvPrefix {
    param([hashtable]$EnvMap)
    $pairs = @()
    foreach ($entry in $EnvMap.GetEnumerator()) {
        $currentValue = [Environment]::GetEnvironmentVariable($entry.Key)
        $value = if ([string]::IsNullOrWhiteSpace($currentValue)) { $entry.Value } else { $currentValue }
        $pairs += ('$env:{0}=''{1}''' -f $entry.Key, $value.Replace("'", "''"))
    }
    return ($pairs -join "; ")
}

function Get-ServiceCommand {
    param([string]$Name)
    $service = $ServiceDefinitions[$Name]
    $envPrefix = Get-EnvPrefix -EnvMap $service.Env
    $uvicorn = ('& ''{0}'' -m uvicorn {1} --host {2} --port {3}' -f $PythonPath, $service.App, $HostAddress, $service.Port)
    if ($envPrefix) {
        return "$envPrefix; $uvicorn"
    }
    return $uvicorn
}

function Get-ServiceRunningProcessId {
    param([string]$Name)
    $port = $ServiceDefinitions[$Name].Port
    $match = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -like "python*" -and
        $_.CommandLine -like "*-m uvicorn*" -and
        $_.CommandLine -like "*--port $port*"
    } | Select-Object -First 1

    if ($match) {
        return $match.ProcessId
    }

    return $null
}

function Get-CollectorRunningProcessId {
    param([string]$Name)
    $definition = $CollectorDefinitions[$Name]
    $match = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq "powershell.exe" -and
        $_.CommandLine -like $definition.Match -and
        $_.CommandLine -like "*-Mode*Run*"
    } | Select-Object -First 1

    if ($match) {
        return $match.ProcessId
    }

    return $null
}

function Start-ServiceBackground {
    param([string]$Name)
    Ensure-Directory $RunPath
    Ensure-Directory $LogPath

    $stdout = Join-Path $LogPath "$Name.out.log"
    $stderr = Join-Path $LogPath "$Name.err.log"
    $pidFile = Join-Path $RunPath "$Name.pid"
    $command = Get-ServiceCommand -Name $Name
    $workDir = $ServiceDefinitions[$Name].WorkDir

    $runningProcessId = Get-ServiceRunningProcessId -Name $Name
    if ($runningProcessId) {
        Set-Content -Path $pidFile -Value $runningProcessId
        Write-Host "$Name is already running with PID $runningProcessId"
        return
    }

    $process = Start-Process -FilePath "powershell" `
        -ArgumentList "-NoProfile", "-Command", $command `
        -WorkingDirectory $workDir `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru

    Start-Sleep -Seconds 1
    $serviceProcessId = Get-ServiceRunningProcessId -Name $Name
    if ($serviceProcessId) {
        Set-Content -Path $pidFile -Value $serviceProcessId
        Write-Host ("Started {0} on port {1} with PID {2}" -f $Name, $ServiceDefinitions[$Name].Port, $serviceProcessId)
    }
    else {
        Set-Content -Path $pidFile -Value $process.Id
        Write-Host ("Started {0}, but the service PID could not be resolved. Wrapper PID: {1}" -f $Name, $process.Id)
    }
}

function Start-CollectorBackground {
    param([string]$Name)
    Ensure-Directory $RunPath
    Ensure-Directory $LogPath

    $stdout = Join-Path $LogPath "$Name.out.log"
    $stderr = Join-Path $LogPath "$Name.err.log"
    $pidFile = Join-Path $RunPath "$Name.pid"
    $definition = $CollectorDefinitions[$Name]

    $runningProcessId = Get-CollectorRunningProcessId -Name $Name
    if ($runningProcessId) {
        Set-Content -Path $pidFile -Value $runningProcessId
        Write-Host "$Name is already running with PID $runningProcessId"
        return
    }

    $process = Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $definition.ScriptPath, "-Mode", "Run", "-ConfigPath", $definition.ConfigPath, "-Quiet" `
        -WorkingDirectory $RootPath `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru

    Start-Sleep -Seconds 1
    $collectorProcessId = Get-CollectorRunningProcessId -Name $Name
    if ($collectorProcessId) {
        Set-Content -Path $pidFile -Value $collectorProcessId
        Write-Host ("Started {0} with PID {1}" -f $Name, $collectorProcessId)
    }
    else {
        Set-Content -Path $pidFile -Value $process.Id
        Write-Host ("Started {0}, but the collector PID could not be resolved. Wrapper PID: {1}" -f $Name, $process.Id)
    }
}

function Stop-ServiceBackground {
    param([string]$Name)
    $pidFile = Join-Path $RunPath "$Name.pid"

    $processId = $null
    if (Test-Path $pidFile) {
        $processId = Get-Content $pidFile -ErrorAction SilentlyContinue
    }

    if (-not $processId) {
        $processId = Get-ServiceRunningProcessId -Name $Name
    }

    if ($processId) {
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
            Stop-Process -Id $processId -Force
            Write-Host "Stopped $Name (PID $processId)"
        }
    }
    else {
        Write-Host "$Name is not running"
    }

    if (Test-Path $pidFile) {
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
}

function Stop-CollectorBackground {
    param([string]$Name)
    $pidFile = Join-Path $RunPath "$Name.pid"

    $processId = $null
    if (Test-Path $pidFile) {
        $processId = Get-Content $pidFile -ErrorAction SilentlyContinue
    }

    if (-not $processId) {
        $processId = Get-CollectorRunningProcessId -Name $Name
    }

    if ($processId) {
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
            Stop-Process -Id $processId -Force
            Write-Host "Stopped $Name (PID $processId)"
        }
    }
    else {
        Write-Host "$Name is not running"
    }

    if (Test-Path $pidFile) {
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
}

function Stop-OrphanRepoProcesses {
    foreach ($name in $ServiceDefinitions.Keys) {
        $processId = Get-ServiceRunningProcessId -Name $name
        if ($processId) {
            try {
                Stop-Process -Id $processId -Force -ErrorAction Stop
                Write-Host ("Stopped orphan repo service process for {0} (PID {1})" -f $name, $processId)
            }
            catch {
            }
        }
    }
    foreach ($name in $CollectorDefinitions.Keys) {
        $processId = Get-CollectorRunningProcessId -Name $name
        if ($processId) {
            try {
                Stop-Process -Id $processId -Force -ErrorAction Stop
                Write-Host ("Stopped orphan collector process for {0} (PID {1})" -f $name, $processId)
            }
            catch {
            }
        }
    }
}

function Show-Status {
    Ensure-Directory $RunPath
    foreach ($name in $ServiceDefinitions.Keys) {
        $processId = Get-ServiceRunningProcessId -Name $name
        if ($processId) {
            Write-Host ("{0,-20} running (PID {1})" -f $name, $processId)
        }
        else {
            Write-Host ("{0,-20} stopped" -f $name)
        }
    }
    foreach ($name in $CollectorDefinitions.Keys) {
        $processId = Get-CollectorRunningProcessId -Name $name
        if ($processId) {
            Write-Host ("{0,-20} running (PID {1})" -f $name, $processId)
        }
        else {
            Write-Host ("{0,-20} stopped" -f $name)
        }
    }
}

function Run-ServiceForeground {
    param([string]$Name)
    $service = $ServiceDefinitions[$Name]
    Push-Location $service.WorkDir
    try {
        foreach ($entry in $service.Env.GetEnumerator()) {
            $currentValue = [Environment]::GetEnvironmentVariable($entry.Key)
            if ([string]::IsNullOrWhiteSpace($currentValue)) {
                Set-Item -Path ("Env:{0}" -f $entry.Key) -Value $entry.Value
            }
        }
        & $PythonPath -m uvicorn $service.App --host $HostAddress --port $service.Port
    }
    finally {
        Pop-Location
    }
}

function Run-PythonCollector {
    $collectorPath = Join-Path $RootPath "endpoint-collector\\python_collector\\collector.py"
    $arguments = @($collectorPath, "--url", $CollectorUrl)
    if ($Insecure) {
        $arguments += "--insecure"
    }
    & $PythonPath @arguments
}

function Run-PythonCollectorService {
    $collectorPath = Join-Path $RootPath "endpoint-collector\\python_collector\\collector.py"
    $configPath = Join-Path $RootPath "endpoint-collector\\python_collector\\example-config.toml"
    & $PythonPath $collectorPath run --config $configPath
}

function Run-PowerShellCollector {
    $collectorPath = Join-Path $RootPath "endpoint-collector\\powershell\\device_posture_collector.ps1"
    $arguments = @(
        "-ExecutionPolicy", "Bypass",
        "-File", $collectorPath,
        "-Mode", "Once",
        "-ApiUrl", $CollectorUrl
    )
    & powershell @arguments
}

function Run-PowerShellCollectorService {
    $collectorPath = Join-Path $RootPath "endpoint-collector\\powershell\\device_posture_collector.ps1"
    $configPath = Join-Path $RootPath "endpoint-collector\\powershell\\collector.config.json"
    $arguments = @(
        "-ExecutionPolicy", "Bypass",
        "-File", $collectorPath,
        "-Mode", "Run",
        "-ConfigPath", $configPath,
        "-Quiet"
    )
    & powershell @arguments
}

function Run-Frontend {
    $frontendPath = Join-Path $RootPath "frontend"
    Push-Location $frontendPath
    try {
        & npm.cmd run dev
    }
    finally {
        Pop-Location
    }
}

switch ($Action) {
    "setup" {
        Install-Repo
        Write-Host "Setup complete."
    }
    "run" {
        if ($Component -in $ServiceDefinitions.Keys -or $Component -in @("python-collector", "python-collector-service")) {
            Ensure-Venv
        }

        if ($Component -in $ServiceDefinitions.Keys) {
            Run-ServiceForeground -Name $Component
        }
        elseif ($Component -eq "python-collector") {
            Run-PythonCollector
        }
        elseif ($Component -eq "powershell-collector") {
            Run-PowerShellCollector
        }
        elseif ($Component -eq "powershell-collector-service") {
            Run-PowerShellCollectorService
        }
        elseif ($Component -eq "python-collector-service") {
            Run-PythonCollectorService
        }
        elseif ($Component -eq "frontend") {
            Run-Frontend
        }
    }
    "start-all" {
        Ensure-Venv
        foreach ($name in @("telemetry-api", "policy-service", "enforcement-service", "evaluation-engine")) {
            Start-ServiceBackground -Name $name
        }
        
    }
    "stop" {
        foreach ($name in @("telemetry-api", "policy-service", "evaluation-engine", "enforcement-service")) {
            Stop-ServiceBackground -Name $name
        }
        Stop-CollectorBackground -Name "powershell-collector-service"
        Stop-OrphanRepoProcesses
    }
    "status" {
        Show-Status
    }
}
