param(
    [ValidateSet("Once", "Run")]
    [string]$Mode = "Once",
    [string]$ConfigPath = "",
    [string]$ApiUrl,
    [int]$TimeoutSeconds = 0,
    [int]$RetryCount = 0,
    [string]$OutputPath,
    [switch]$NoSend,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$script:CollectorRegistry = [ordered]@{}

function Get-DefaultConfigPath {
    return Join-Path $PSScriptRoot "collector.config.json"
}

function Get-CollectorsPath {
    return Join-Path $PSScriptRoot "collectors"
}

function Resolve-AgentPath {
    param([string]$PathValue)

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $PathValue
    }

    $expandedPath = [Environment]::ExpandEnvironmentVariables($PathValue)

    if ([System.IO.Path]::IsPathRooted($expandedPath)) {
        return $expandedPath
    }

    return Join-Path $PSScriptRoot $expandedPath
}

function Get-DefaultConfig {
    return @{
        agent = @{
            name = "windows-powershell-agent"
            interval_seconds = 2
            active_grace_multiplier = 3
            log_path = "%ProgramData%\\DevicePosture\\collector.log"
            write_payload_file = ""
        }
        transport = @{
            enabled = $true
            url = "http://127.0.0.1:8011/telemetry"
            timeout_seconds = 10
            retry_count = 3
            bearer_token = ""
            headers = @{}
        }
        collectors = @{
            enabled = @("system_info", "hotfixes", "services", "processes", "antivirus")
            settings = @{}
        }
    }
}

function ConvertTo-NativeObject {
    param([object]$InputObject)

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $table = @{}
        foreach ($key in $InputObject.Keys) {
            $table[$key] = ConvertTo-NativeObject -InputObject $InputObject[$key]
        }
        return $table
    }

    if ($InputObject -is [pscustomobject]) {
        $table = @{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $table[$property.Name] = ConvertTo-NativeObject -InputObject $property.Value
        }
        return $table
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(ConvertTo-NativeObject -InputObject $item)
        }
        return $items
    }

    return $InputObject
}

function Merge-Hashtable {
    param(
        [System.Collections.IDictionary]$Base,
        [System.Collections.IDictionary]$Override
    )

    foreach ($key in $Override.Keys) {
        if ($Base[$key] -is [System.Collections.IDictionary] -and $Override[$key] -is [System.Collections.IDictionary]) {
            Merge-Hashtable -Base $Base[$key] -Override $Override[$key] | Out-Null
        }
        else {
            $Base[$key] = $Override[$key]
        }
    }
    return $Base
}

function Test-DictionaryKey {
    param(
        [System.Collections.IDictionary]$Dictionary,
        [string]$Key
    )

    if ($null -eq $Dictionary) {
        return $false
    }

    if ($Dictionary -is [hashtable]) {
        return $Dictionary.ContainsKey($Key)
    }

    return $Dictionary.Contains($Key)
}

function Read-CollectorConfig {
    param([string]$Path)

    $config = Get-DefaultConfig
    if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path $Path)) {
        $raw = ConvertTo-NativeObject -InputObject (Get-Content -Raw -Path $Path | ConvertFrom-Json)
        $config = Merge-Hashtable -Base $config -Override $raw
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Path) -and $Path -ne (Get-DefaultConfigPath)) {
        throw "Config file not found: $Path"
    }

    if ($ApiUrl) {
        $config.transport.url = $ApiUrl
    }
    if ($TimeoutSeconds -gt 0) {
        $config.transport.timeout_seconds = $TimeoutSeconds
    }
    if ($RetryCount -gt 0) {
        $config.transport.retry_count = $RetryCount
    }
    if ($OutputPath) {
        $config.agent.write_payload_file = $OutputPath
    }
    if ($NoSend) {
        $config.transport.enabled = $false
    }

    return $config
}

function Ensure-ParentDirectory {
    param([string]$FilePath)

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return
    }

    $parent = Split-Path -Parent $FilePath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
}

function Write-AgentLog {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$Level,
        [string]$Message
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString("o")
    $line = "$timestamp [$Level] $Message"
    if (-not $Quiet -or $Level -in @("WARN", "ERROR")) {
        Write-Host $line
    }

    $logPath = Resolve-AgentPath -PathValue $Config.agent.log_path
    if (-not [string]::IsNullOrWhiteSpace($logPath)) {
        try {
            Ensure-ParentDirectory -FilePath $logPath
            $line | Out-File -FilePath $logPath -Append -Encoding utf8
        }
        catch {
            $fallback = Resolve-AgentPath -PathValue "%ProgramData%\\DevicePosture\\collector-fallback.log"
            Ensure-ParentDirectory -FilePath $fallback
            $line | Out-File -FilePath $fallback -Append -Encoding utf8
        }
    }
}

function Register-Collector {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw "Collector name is required."
    }
    if ($null -eq $ScriptBlock) {
        throw "Collector script block is required for '$Name'."
    }

    $script:CollectorRegistry[$Name] = $ScriptBlock
}

function Import-CollectorPlugins {
    $collectorsPath = Get-CollectorsPath
    if (-not (Test-Path $collectorsPath)) {
        throw "Collectors path not found: $collectorsPath"
    }

    foreach ($collectorFile in (Get-ChildItem -Path $collectorsPath -Filter "*.ps1" | Sort-Object Name)) {
        . $collectorFile.FullName
    }
}

function Get-EndpointId {
    try {
        return Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid"
    }
    catch {
        return $env:COMPUTERNAME
    }
}

function Get-ActiveIPv4 {
    try {
        return Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike "169.254*" -and $_.IPAddress -ne "127.0.0.1" } |
            Select-Object -First 1 -ExpandProperty IPAddress
    }
    catch {
        return $null
    }
}

function Get-CollectorRegistry {
    return $script:CollectorRegistry
}

function Merge-Payload {
    param([object[]]$Parts)

    $merged = @{
        schema_version = "1.0"
        collector_type = "powershell-windows-agent"
        endpoint_id = "unknown-endpoint"
        hostname = $env:COMPUTERNAME
        collected_at = (Get-Date).ToUniversalTime().ToString("o")
        agent = @{
            name = $null
            interval_seconds = $null
            active_grace_multiplier = 3
            enabled_collectors = @()
            transport_enabled = $true
        }
        network = @{
            ipv4 = $null
        }
        os = @{
            name = $null
            version = $null
            build = $null
        }
        hotfixes = @()
        services = @()
        processes = @()
        antivirus_products = @()
        extras = @{}
    }

    foreach ($part in $Parts) {
        if ($part -is [System.Collections.IDictionary]) {
            Merge-Hashtable -Base $merged -Override $part | Out-Null
        }
    }

    $merged.agent = @{
        name = [string]$Config.agent.name
        interval_seconds = [int]$Config.agent.interval_seconds
        active_grace_multiplier = [Math]::Max(1, [int]$Config.agent.active_grace_multiplier)
        enabled_collectors = @($Config.collectors.enabled)
        transport_enabled = [bool]$Config.transport.enabled
    }

    return $merged
}

function Invoke-CollectionCycle {
    param([System.Collections.IDictionary]$Config)

    $registry = Get-CollectorRegistry
    $parts = @()
    foreach ($name in @($Config.collectors.enabled)) {
        if (-not (Test-DictionaryKey -Dictionary $registry -Key $name)) {
            $parts += @{ extras = @{ "$($name)_error" = "Collector not registered" } }
            continue
        }

        try {
            $settings = @{}
            if ($Config.collectors.settings -is [System.Collections.IDictionary] -and (Test-DictionaryKey -Dictionary $Config.collectors.settings -Key $name)) {
                $settings = ConvertTo-NativeObject -InputObject $Config.collectors.settings[$name]
            }

            $context = @{
                config = $Config
                collector_name = $name
                settings = $settings
                collected_at = (Get-Date).ToUniversalTime().ToString("o")
            }

            $parts += & $registry[$name] $context
        }
        catch {
            $parts += @{ extras = @{ "$($name)_error" = $_.Exception.Message } }
        }
    }
    return Merge-Payload -Parts $parts
}

function Write-PayloadToDisk {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadJson
    )

    $outputFile = Resolve-AgentPath -PathValue $Config.agent.write_payload_file
    if (-not [string]::IsNullOrWhiteSpace($outputFile)) {
        Ensure-ParentDirectory -FilePath $outputFile
        $PayloadJson | Out-File -FilePath $outputFile -Encoding utf8
    }
}

function Send-TelemetryPayload {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadJson
    )

    if (-not $Config.transport.enabled) {
        return $null
    }

    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($PayloadJson)
    $timeout = [int]$Config.transport.timeout_seconds
    $retries = [int]$Config.transport.retry_count
    $url = [string]$Config.transport.url
    $headers = @{}
    if ($Config.transport.headers -is [System.Collections.IDictionary]) {
        foreach ($headerKey in $Config.transport.headers.Keys) {
            $headers[$headerKey] = [string]$Config.transport.headers[$headerKey]
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Config.transport.bearer_token)) {
        $headers["Authorization"] = "Bearer $($Config.transport.bearer_token)"
    }

    for ($attempt = 1; $attempt -le $retries; $attempt++) {
        try {
            Write-AgentLog -Config $Config -Level "INFO" -Message "Sending telemetry attempt $attempt to $url"
            $invokeParams = @{
                Uri = $url
                Method = "Post"
                Body = $jsonBytes
                ContentType = "application/json; charset=utf-8"
                TimeoutSec = $timeout
            }
            if ($headers.Count -gt 0) {
                $invokeParams.Headers = $headers
            }
            $response = Invoke-RestMethod @invokeParams
            Write-AgentLog -Config $Config -Level "INFO" -Message "Telemetry POST succeeded for endpoint payload"
            return $response
        }
        catch {
            Write-AgentLog -Config $Config -Level "WARN" -Message "Telemetry POST attempt $attempt failed: $($_.Exception.Message)"
            if ($attempt -eq $retries) {
                throw
            }
            Start-Sleep -Seconds $attempt
        }
    }
}

function Invoke-AgentOnce {
    param([System.Collections.IDictionary]$Config)

    Write-AgentLog -Config $Config -Level "INFO" -Message "Running one collector cycle with interval=$($Config.agent.interval_seconds)s grace_multiplier=$($Config.agent.active_grace_multiplier) transport_enabled=$($Config.transport.enabled)"
    $payload = Invoke-CollectionCycle -Config $Config
    $payload.collector_type = [string]$Config.agent.name
    $payloadJson = $payload | ConvertTo-Json -Depth 8
    Write-PayloadToDisk -Config $Config -PayloadJson $payloadJson
    if (-not $Quiet) {
        Write-Output $payloadJson
    }

    if ($Config.transport.enabled) {
        $response = Send-TelemetryPayload -Config $Config -PayloadJson $payloadJson
        if ($null -ne $response -and -not $Quiet) {
            Write-Output ($response | ConvertTo-Json -Depth 6)
        }
        Write-AgentLog -Config $Config -Level "INFO" -Message "One-shot collector cycle completed successfully for $($payload.endpoint_id)"
    }
    else {
        Write-AgentLog -Config $Config -Level "INFO" -Message "One-shot collector cycle completed without transport for $($payload.endpoint_id)"
    }
}

function Start-AgentLoop {
    param([System.Collections.IDictionary]$Config)

    $interval = [Math]::Max(1, [int]$Config.agent.interval_seconds)
    $heartbeatTimeout = $interval * [Math]::Max(1, [int]$Config.agent.active_grace_multiplier)
    Write-AgentLog -Config $Config -Level "INFO" -Message "Starting PowerShell endpoint agent with interval=${interval}s heartbeat_timeout=${heartbeatTimeout}s url=$($Config.transport.url)"
    Write-AgentLog -Config $Config -Level "INFO" -Message ("Enabled collectors: " + (($Config.collectors.enabled) -join ", "))

    while ($true) {
        try {
            Write-AgentLog -Config $Config -Level "INFO" -Message "Starting collector cycle"
            $payload = Invoke-CollectionCycle -Config $Config
            $payload.collector_type = [string]$Config.agent.name
            $payloadJson = $payload | ConvertTo-Json -Depth 8
            Write-PayloadToDisk -Config $Config -PayloadJson $payloadJson

            if ($Config.transport.enabled) {
                $response = Send-TelemetryPayload -Config $Config -PayloadJson $payloadJson
                $recordId = $null
                if ($null -ne $response -and $response.PSObject.Properties.Name -contains "record_id") {
                    $recordId = $response.record_id
                }
                Write-AgentLog -Config $Config -Level "INFO" -Message "Sent telemetry for $($payload.endpoint_id) successfully. Record: $recordId"
            }
            else {
                Write-AgentLog -Config $Config -Level "INFO" -Message "Collected telemetry for $($payload.endpoint_id) without sending"
            }
        }
        catch {
            Write-AgentLog -Config $Config -Level "ERROR" -Message "Collector cycle failed: $($_.Exception.Message)"
        }

        Write-AgentLog -Config $Config -Level "INFO" -Message "Sleeping for ${interval}s before the next cycle"
        Start-Sleep -Seconds $interval
    }
}

Import-CollectorPlugins
$resolvedConfigPath = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { Get-DefaultConfigPath } else { $ConfigPath }
$config = Read-CollectorConfig -Path $resolvedConfigPath
Write-AgentLog -Config $config -Level "INFO" -Message "Loaded collector config from $resolvedConfigPath"

if ($Mode -eq "Run") {
    Start-AgentLoop -Config $config
}
else {
    try {
        Invoke-AgentOnce -Config $config
    }
    catch {
        Write-Error "Failed to send telemetry to $($config.transport.url). $($_.Exception.Message)"
        exit 1
    }
}
