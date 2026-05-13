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
            agent_name = "windows-powershell-agent"
            agent_version = "1.1.0-mvp-typed-telemetry"
            hostname_source = "computername"
            ip_detection = "first_active_ipv4"
            log_path = "%ProgramData%\\DevicePosture\\collector.log"
            write_payload_file = ""
        }
        server = @{
            base_url = "http://127.0.0.1:8011"
            endpoints = @{
                legacy_telemetry = "/telemetry"
                heartbeat = "/telemetry/heartbeat"
                posture_snapshot = "/telemetry/posture"
                inventory_full = "/telemetry/inventory/full"
                inventory_delta = "/telemetry/inventory/delta"
            }
            timeout_seconds = 10
            retry = @{
                retry_count = 3
                backoff_seconds = 1
            }
            bearer_token = ""
            headers = @{}
        }
        dry_run = $false
        scheduling = @{
            heartbeat_interval_seconds = 3
            posture_interval_seconds = 3
            inventory_delta_interval_seconds = 10
            inventory_full_interval_seconds = 900
            send_full_inventory_on_startup = $true
            send_full_inventory_on_resync_required = $true
        }
        payload = @{
            gzip_enabled = $false
            max_payload_bytes = 10485760
            include_sequence_numbers = $true
            include_hashes = $true
            debug_payload_dump_enabled = $false
            debug_payload_dump_dir = ".\\logs\\payload-dumps"
        }
        heartbeat = @{
            enabled = $true
            include = @("hostname", "ip_address", "agent_version", "uptime")
        }
        posture_snapshot = @{
            enabled = $true
            trigger_policy_evaluation = $true
            collectors = @(
                "system_info",
                "antivirus",
                "domain_membership",
                "critical_patches_summary",
                "required_services",
                "forbidden_processes",
                "security_processes"
            )
            required_services = @("WinDefend", "SecurityHealthService")
            security_processes = @("MsMpEng", "SecurityHealthSystray")
            forbidden_processes = @()
            critical_patches = @()
        }
        inventory = @{
            enabled = $true
            full_snapshot_categories = @("system_info", "hotfixes", "services", "processes", "antivirus")
            delta_categories = @("hotfixes", "services", "processes")
            services = @{ enabled = $true }
            processes = @{ enabled = $true }
            hotfixes = @{ enabled = $true }
            software = @{ enabled = $false }
        }
        local_state = @{
            enabled = $true
            state_file = "%ProgramData%\\DevicePosture\\collector-state.json"
            store_last_inventory_hash = $true
            store_last_sequence_numbers = $true
            store_last_baselines = $true
        }
        logging = @{
            level = "INFO"
            log_file = "%ProgramData%\\DevicePosture\\collector.log"
            log_payload_size = $true
            log_collection_duration = $true
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

function Normalize-CollectorConfig {
    param([System.Collections.IDictionary]$Config)

    if ((Test-DictionaryKey -Dictionary $Config -Key "transport") -and $Config.transport -is [System.Collections.IDictionary]) {
        $legacyUrl = [string]$Config.transport.url
        if (-not [string]::IsNullOrWhiteSpace($legacyUrl)) {
            $uri = [System.Uri]$legacyUrl
            $Config.server.base_url = "$($uri.Scheme)://$($uri.Authority)"
            $Config.server.endpoints.legacy_telemetry = $uri.AbsolutePath
        }
        if (Test-DictionaryKey -Dictionary $Config.transport -Key "timeout_seconds") {
            $Config.server.timeout_seconds = $Config.transport.timeout_seconds
        }
        if (Test-DictionaryKey -Dictionary $Config.transport -Key "retry_count") {
            $Config.server.retry.retry_count = $Config.transport.retry_count
        }
        if (Test-DictionaryKey -Dictionary $Config.transport -Key "bearer_token") {
            $Config.server.bearer_token = $Config.transport.bearer_token
        }
        if (Test-DictionaryKey -Dictionary $Config.transport -Key "headers") {
            $Config.server.headers = $Config.transport.headers
        }
    }

    if ((Test-DictionaryKey -Dictionary $Config.agent -Key "name") -and -not (Test-DictionaryKey -Dictionary $Config.agent -Key "agent_name")) {
        $Config.agent.agent_name = $Config.agent.name
    }
    if ((Test-DictionaryKey -Dictionary $Config.agent -Key "interval_seconds") -and -not (Test-DictionaryKey -Dictionary $Config.scheduling -Key "posture_interval_seconds")) {
        $Config.scheduling.posture_interval_seconds = $Config.agent.interval_seconds
        $Config.scheduling.heartbeat_interval_seconds = $Config.agent.interval_seconds
    }
    if (-not (Test-DictionaryKey -Dictionary $Config -Key "collectors")) {
        $Config.collectors = @{ settings = @{} }
    }
    if (-not (Test-DictionaryKey -Dictionary $Config.collectors -Key "settings")) {
        $Config.collectors.settings = @{}
    }
    return $Config
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
        $uri = [System.Uri]$ApiUrl
        $config.server.base_url = "$($uri.Scheme)://$($uri.Authority)"
        $config.server.endpoints.legacy_telemetry = $uri.AbsolutePath
    }
    if ($TimeoutSeconds -gt 0) {
        $config.server.timeout_seconds = $TimeoutSeconds
    }
    if ($RetryCount -gt 0) {
        $config.server.retry.retry_count = $RetryCount
    }
    if ($OutputPath) {
        $config.agent.write_payload_file = $OutputPath
    }
    if ($NoSend) {
        $config.server.enabled = $false
        $config.dry_run = $true
    }

    return Normalize-CollectorConfig -Config $config
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
        try {
            Write-Host $line
        }
        catch {
            # Keep collection alive even if the host console is unavailable.
        }
    }

    $logPath = Resolve-AgentPath -PathValue $Config.agent.log_path
    if (-not [string]::IsNullOrWhiteSpace($logPath)) {
        try {
            Ensure-ParentDirectory -FilePath $logPath
            $line | Out-File -FilePath $logPath -Append -Encoding utf8
        }
        catch {
            try {
                $fallback = Resolve-AgentPath -PathValue "%ProgramData%\\DevicePosture\\collector-fallback.log"
                Ensure-ParentDirectory -FilePath $fallback
                $line | Out-File -FilePath $fallback -Append -Encoding utf8
            }
            catch {
                try {
                    Write-Host $line
                }
                catch {
                    # Last-resort logging failed; never stop the collector because of logging.
                }
            }
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
        name = [string]$Config.agent.agent_name
        version = [string]$Config.agent.agent_version
        interval_seconds = [int]$Config.scheduling.posture_interval_seconds
        active_grace_multiplier = 3
        enabled_collectors = @()
        transport_enabled = -not [bool]$NoSend
    }

    return $merged
}

function Invoke-CollectionCycle {
    param(
        [System.Collections.IDictionary]$Config,
        [string[]]$CollectorNames
    )

    $registry = Get-CollectorRegistry
    if ($null -eq $CollectorNames -or $CollectorNames.Count -eq 0) {
        $CollectorNames = @($Config.inventory.full_snapshot_categories)
    }
    $parts = @()
    foreach ($name in @($CollectorNames)) {
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
    $payload = Merge-Payload -Parts $parts
    $payload.agent.enabled_collectors = @($CollectorNames)
    return $payload
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

function Get-EndpointUrl {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadType
    )

    $baseUrl = ([string]$Config.server.base_url).TrimEnd("/")
    $path = [string]$Config.server.endpoints[$PayloadType]
    if ([string]::IsNullOrWhiteSpace($path)) {
        $path = [string]$Config.server.endpoints.legacy_telemetry
    }
    return "$baseUrl/$($path.TrimStart('/'))"
}

function ConvertTo-JsonBytes {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadJson
    )

    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($PayloadJson)
    if ([bool]$Config.payload.gzip_enabled) {
        $output = New-Object System.IO.MemoryStream
        $gzip = New-Object System.IO.Compression.GzipStream($output, [System.IO.Compression.CompressionMode]::Compress)
        $gzip.Write($jsonBytes, 0, $jsonBytes.Length)
        $gzip.Close()
        return $output.ToArray()
    }
    return $jsonBytes
}

function Write-DebugPayloadDump {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadType,
        [string]$PayloadJson
    )

    if (-not [bool]$Config.payload.debug_payload_dump_enabled) {
        return
    }

    try {
        $dumpDir = Resolve-AgentPath -PathValue $Config.payload.debug_payload_dump_dir
        if ([string]::IsNullOrWhiteSpace($dumpDir)) {
            return
        }
        if (-not (Test-Path $dumpDir)) {
            New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
        }
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
        $fileName = "$timestamp-$PayloadType.json"
        $PayloadJson | Out-File -FilePath (Join-Path $dumpDir $fileName) -Encoding utf8
    }
    catch {
        Write-AgentLog -Config $Config -Level "WARN" -Message "Failed to write debug payload dump for $PayloadType`: $($_.Exception.Message)"
    }
}

function Send-TelemetryPayload {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadType,
        [string]$PayloadJson
    )

    if ([bool]$Config.dry_run -or ((Test-DictionaryKey -Dictionary $Config.server -Key "enabled") -and -not [bool]$Config.server.enabled)) {
        Write-AgentLog -Config $Config -Level "INFO" -Message "Dry-run enabled; not sending $PayloadType"
        return $null
    }

    $jsonBytes = ConvertTo-JsonBytes -Config $Config -PayloadJson $PayloadJson
    if ($Config.payload.max_payload_bytes -and $jsonBytes.Length -gt [int]$Config.payload.max_payload_bytes) {
        throw "Payload '$PayloadType' is $($jsonBytes.Length) bytes, above max_payload_bytes=$($Config.payload.max_payload_bytes)"
    }
    $timeout = [int]$Config.server.timeout_seconds
    $retries = [int]$Config.server.retry.retry_count
    $backoffSeconds = [int]$Config.server.retry.backoff_seconds
    $url = Get-EndpointUrl -Config $Config -PayloadType $PayloadType
    $headers = @{}
    if ($Config.server.headers -is [System.Collections.IDictionary]) {
        foreach ($headerKey in $Config.server.headers.Keys) {
            $headers[$headerKey] = [string]$Config.server.headers[$headerKey]
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Config.server.bearer_token)) {
        $headers["Authorization"] = "Bearer $($Config.server.bearer_token)"
    }
    if ([bool]$Config.payload.gzip_enabled) {
        $headers["Content-Encoding"] = "gzip"
    }

    for ($attempt = 1; $attempt -le $retries; $attempt++) {
        try {
            Write-AgentLog -Config $Config -Level "INFO" -Message "Sending $PayloadType attempt $attempt to $url bytes=$($jsonBytes.Length)"
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
            Write-AgentLog -Config $Config -Level "INFO" -Message "$PayloadType POST succeeded"
            return $response
        }
        catch {
            $statusCode = $null
            $errorDetail = $_.Exception.Message
            if ($_.Exception.Response) {
                try {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                catch {
                    $statusCode = $null
                }
            }
            if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
                try {
                    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $responseBody = $reader.ReadToEnd()
                    if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                        $errorDetail = "$errorDetail response=$responseBody"
                    }
                }
                catch {
                    $errorDetail = "$errorDetail response=<failed to read error body: $($_.Exception.Message)>"
                }
            }
            Write-AgentLog -Config $Config -Level "WARN" -Message "$PayloadType POST attempt $attempt failed url=$url status=$statusCode bytes=$($jsonBytes.Length): $errorDetail"
            if ($attempt -eq $retries) {
                throw
            }
            Start-Sleep -Seconds ([Math]::Max(1, $backoffSeconds) * $attempt)
        }
    }
}

function Get-AgentUptimeSeconds {
    try {
        return [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds
    }
    catch {
        return $null
    }
}

function Get-BaseEndpointPayload {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadType
    )

    return @{
        schema_version = "1.1"
        payload_type = $PayloadType
        endpoint_ref = Get-EndpointId
        endpoint_id = Get-EndpointId
        hostname = $env:COMPUTERNAME
        sent_at = (Get-Date).ToUniversalTime().ToString("o")
        collected_at = (Get-Date).ToUniversalTime().ToString("o")
        ip_address = Get-ActiveIPv4
        network = @{ ipv4 = Get-ActiveIPv4 }
        agent = @{
            name = [string]$Config.agent.agent_name
            version = [string]$Config.agent.agent_version
            interval_seconds = [int]$Config.scheduling.posture_interval_seconds
            active_grace_multiplier = 3
        }
    }
}

function New-HeartbeatPayload {
    param([System.Collections.IDictionary]$Config)

    $payload = Get-BaseEndpointPayload -Config $Config -PayloadType "heartbeat"
    $payload.agent.interval_seconds = [int]$Config.scheduling.heartbeat_interval_seconds
    $payload.heartbeat_interval_seconds = [int]$Config.scheduling.heartbeat_interval_seconds
    $payload.uptime_seconds = Get-AgentUptimeSeconds
    return $payload
}

function Get-NamedServiceStatus {
    param([string[]]$Names)

    $results = @()
    foreach ($serviceName in @($Names)) {
        try {
            $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            $results += @{
                name = $serviceName
                display_name = if ($null -ne $service) { [string]$service.DisplayName } else { $null }
                status = if ($null -ne $service) { [string]$service.State } else { "Missing" }
                start_type = if ($null -ne $service) { [string]$service.StartMode } else { $null }
                running = ($null -ne $service -and [string]$service.State -eq "Running")
            }
        }
        catch {
            $results += @{ name = $serviceName; status = "Error"; running = $false; error = $_.Exception.Message }
        }
    }
    return @($results)
}

function Get-ProcessFindings {
    param(
        [string[]]$Names,
        [bool]$ExpectedPresent
    )

    $allProcesses = @(Get-Process -ErrorAction SilentlyContinue)
    $results = @()
    foreach ($processName in @($Names)) {
        $matches = @($allProcesses | Where-Object { $_.ProcessName -ieq $processName })
        $results += @{
            name = $processName
            present = ($matches.Count -gt 0)
            expected_present = $ExpectedPresent
            count = $matches.Count
            pids = @($matches | Select-Object -ExpandProperty Id)
        }
    }
    return @($results)
}

function Get-CriticalPatchSummary {
    param([string[]]$PatchIds)

    if ($null -eq $PatchIds -or $PatchIds.Count -eq 0) {
        return @{ required = @(); installed = @(); missing = @() }
    }
    $installed = @(Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID)
    $missing = @($PatchIds | Where-Object { $installed -notcontains $_ })
    return @{
        required = @($PatchIds)
        installed = @($PatchIds | Where-Object { $installed -contains $_ })
        missing = $missing
    }
}

function New-PostureSnapshotPayload {
    param([System.Collections.IDictionary]$Config)

    $payload = Invoke-CollectionCycle -Config $Config -CollectorNames @("system_info", "antivirus")
    $payload.payload_type = "posture_snapshot"
    $payload.schema_version = "1.1"
    $payload.collector_type = [string]$Config.agent.agent_name
    $payload.agent.interval_seconds = [int]$Config.scheduling.posture_interval_seconds
    $payload.posture_interval_seconds = [int]$Config.scheduling.posture_interval_seconds

    $requiredServices = Get-NamedServiceStatus -Names @($Config.posture_snapshot.required_services)
    $forbiddenProcesses = Get-ProcessFindings -Names @($Config.posture_snapshot.forbidden_processes) -ExpectedPresent $false
    $securityProcesses = Get-ProcessFindings -Names @($Config.posture_snapshot.security_processes) -ExpectedPresent $true
    $criticalPatches = Get-CriticalPatchSummary -PatchIds @($Config.posture_snapshot.critical_patches)
    $payload.services = @($requiredServices | ForEach-Object {
        @{ name = $_.name; display_name = $_.display_name; status = $_.status; start_type = $_.start_type }
    })
    $payload.processes = @(
        @($forbiddenProcesses | Where-Object { $_.present } | ForEach-Object { @{ name = $_.name; pid = $null } }) +
        @($securityProcesses | Where-Object { $_.present } | ForEach-Object { @{ name = $_.name; pid = $null } })
    )
    $payload.hotfixes = @($criticalPatches.installed | ForEach-Object { @{ id = $_; description = "configured critical patch"; installed_on = $null } })
    $payload.extras.posture_snapshot = @{
        domain_membership = $payload.extras.domain_membership
        critical_patch_summary = $criticalPatches
        required_services = $requiredServices
        forbidden_process_findings = $forbiddenProcesses
        security_process_findings = $securityProcesses
    }
    $payload.posture = @{
        system_info = $payload.os
        antivirus = $payload.antivirus_products
        required_services = $requiredServices
        forbidden_processes_found = @($forbiddenProcesses | Where-Object { $_.present })
        security_processes_found = @($securityProcesses | Where-Object { $_.present })
    }
    return $payload
}

function Get-StatePath {
    param([System.Collections.IDictionary]$Config)
    return Resolve-AgentPath -PathValue $Config.local_state.state_file
}

function Read-CollectorState {
    param([System.Collections.IDictionary]$Config)

    $statePath = Get-StatePath -Config $Config
    if (-not [bool]$Config.local_state.enabled -or [string]::IsNullOrWhiteSpace($statePath) -or -not (Test-Path $statePath)) {
        return @{ baseline_id = [guid]::NewGuid().ToString(); sequence_number = 0; current_hash = ""; inventory = @{} }
    }
    try {
        return ConvertTo-NativeObject -InputObject (Get-Content -Raw -Path $statePath | ConvertFrom-Json)
    }
    catch {
        return @{ baseline_id = [guid]::NewGuid().ToString(); sequence_number = 0; current_hash = ""; inventory = @{} }
    }
}

function Write-CollectorState {
    param(
        [System.Collections.IDictionary]$Config,
        [System.Collections.IDictionary]$State
    )

    if (-not [bool]$Config.local_state.enabled) {
        return
    }
    $statePath = Get-StatePath -Config $Config
    Ensure-ParentDirectory -FilePath $statePath
    ($State | ConvertTo-Json -Depth 12) | Out-File -FilePath $statePath -Encoding utf8
}

function Get-JsonHash {
    param([object]$Value)

    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
}

function Get-InventoryItemKey {
    param(
        [string]$Category,
        [System.Collections.IDictionary]$Item
    )

    if ($Category -eq "hotfixes") { return [string]$Item.id }
    if ($Category -eq "services") { return [string]$Item.name }
    if ($Category -eq "processes") { return [string]$Item.name }
    if ($Category -eq "software") { return "$($Item.name)|$($Item.version)" }
    return Get-JsonHash -Value $Item
}

function Convert-InventoryToMap {
    param(
        [System.Collections.IDictionary]$Inventory,
        [string[]]$Categories
    )

    $map = @{}
    foreach ($category in @($Categories)) {
        $categoryMap = @{}
        foreach ($item in @($Inventory[$category])) {
            if ($item -is [System.Collections.IDictionary]) {
                $key = Get-InventoryItemKey -Category $category -Item $item
                if (-not [string]::IsNullOrWhiteSpace($key)) {
                    $categoryMap[$key] = $item
                }
            }
        }
        $map[$category] = $categoryMap
    }
    return $map
}

function New-FullInventoryPayload {
    param(
        [System.Collections.IDictionary]$Config,
        [System.Collections.IDictionary]$State
    )

    $payload = Invoke-CollectionCycle -Config $Config -CollectorNames @($Config.inventory.full_snapshot_categories)
    $payload.payload_type = "inventory_full"
    $payload.schema_version = "1.1"
    $payload.collector_type = [string]$Config.agent.agent_name
    $payload.agent.interval_seconds = [int]$Config.scheduling.inventory_full_interval_seconds
    if (-not $State.baseline_id) {
        $State.baseline_id = [guid]::NewGuid().ToString()
    }
    $State.sequence_number = 0
    $State.inventory = Convert-InventoryToMap -Inventory $payload -Categories @($Config.inventory.delta_categories)
    $State.current_hash = Get-JsonHash -Value $State.inventory
    $payload.baseline_id = [string]$State.baseline_id
    $payload.sequence_number = [int]$State.sequence_number
    $payload.current_hash = [string]$State.current_hash
    $payload.category = "all"
    $payload.inventory = @{
        services = @($payload.services)
        processes = @($payload.processes)
        hotfixes = @($payload.hotfixes)
        software = @($payload.software)
    }
    Write-CollectorState -Config $Config -State $State
    return $payload
}

function New-InventoryDeltaPayload {
    param(
        [System.Collections.IDictionary]$Config,
        [System.Collections.IDictionary]$State
    )

    $inventory = Invoke-CollectionCycle -Config $Config -CollectorNames @($Config.inventory.delta_categories)
    $currentMap = Convert-InventoryToMap -Inventory $inventory -Categories @($Config.inventory.delta_categories)
    $previousMap = if ($State.inventory -is [System.Collections.IDictionary]) { $State.inventory } else { @{} }
    $changes = @{}
    foreach ($category in @($Config.inventory.delta_categories)) {
        $previousCategory = if ($previousMap[$category] -is [System.Collections.IDictionary]) { $previousMap[$category] } else { @{} }
        $currentCategory = if ($currentMap[$category] -is [System.Collections.IDictionary]) { $currentMap[$category] } else { @{} }
        $addedUpdated = @()
        $removed = @()
        foreach ($key in $currentCategory.Keys) {
            if (-not $previousCategory.ContainsKey($key) -or (Get-JsonHash -Value $previousCategory[$key]) -ne (Get-JsonHash -Value $currentCategory[$key])) {
                $addedUpdated += $currentCategory[$key]
            }
        }
        foreach ($key in $previousCategory.Keys) {
            if (-not $currentCategory.ContainsKey($key)) {
                $removed += $key
            }
        }
        $changes[$category] = @{ added_updated = $addedUpdated; removed = $removed }
    }

    $previousHash = [string]$State.current_hash
    $State.sequence_number = [int]$State.sequence_number + 1
    $State.inventory = $currentMap
    $State.current_hash = Get-JsonHash -Value $currentMap
    $payload = Get-BaseEndpointPayload -Config $Config -PayloadType "inventory_delta"
    $payload.agent.interval_seconds = [int]$Config.scheduling.inventory_delta_interval_seconds
    $payload.baseline_id = [string]$State.baseline_id
    $payload.sequence_number = [int]$State.sequence_number
    $payload.previous_hash = $previousHash
    $payload.current_hash = [string]$State.current_hash
    $payload.changes = $changes
    $payload.category = "all"
    Write-CollectorState -Config $Config -State $State
    return $payload
}

function Send-PayloadObject {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadType,
        [System.Collections.IDictionary]$Payload
    )

    $payloadJson = $Payload | ConvertTo-Json -Depth 50 -Compress
    Write-PayloadToDisk -Config $Config -PayloadJson $payloadJson
    Write-DebugPayloadDump -Config $Config -PayloadType $PayloadType -PayloadJson $payloadJson
    if (-not $Quiet) {
        Write-Output $payloadJson
    }
    if (-not $NoSend) {
        return Send-TelemetryPayload -Config $Config -PayloadType $PayloadType -PayloadJson $payloadJson
    }
    return $null
}

function Invoke-PayloadSafely {
    param(
        [System.Collections.IDictionary]$Config,
        [string]$PayloadType,
        [scriptblock]$BuildPayload
    )

    try {
        $payload = & $BuildPayload
        $response = Send-PayloadObject -Config $Config -PayloadType $PayloadType -Payload $payload
        return @{ success = $true; response = $response }
    }
    catch {
        Write-AgentLog -Config $Config -Level "WARN" -Message "$PayloadType loop failed but collector will continue: $($_.Exception.Message)"
        return @{ success = $false; response = $null }
    }
}

function Invoke-AgentOnce {
    param([System.Collections.IDictionary]$Config)

    Write-AgentLog -Config $Config -Level "INFO" -Message "Running one collector posture_snapshot cycle"
    $payload = New-PostureSnapshotPayload -Config $Config
    $response = Send-PayloadObject -Config $Config -PayloadType "posture_snapshot" -Payload $payload
    if ($null -ne $response -and -not $Quiet) {
        Write-Output ($response | ConvertTo-Json -Depth 6)
    }
    Write-AgentLog -Config $Config -Level "INFO" -Message "One-shot collector cycle completed for $($payload.endpoint_id)"
}

function Start-AgentLoop {
    param([System.Collections.IDictionary]$Config)

    $heartbeatInterval = [Math]::Max(1, [int]$Config.scheduling.heartbeat_interval_seconds)
    $postureInterval = [Math]::Max(1, [int]$Config.scheduling.posture_interval_seconds)
    $deltaInterval = [Math]::Max(1, [int]$Config.scheduling.inventory_delta_interval_seconds)
    $fullInterval = [Math]::Max(1, [int]$Config.scheduling.inventory_full_interval_seconds)
    $state = Read-CollectorState -Config $Config
    $lastHeartbeat = [DateTime]::MinValue
    $lastPosture = [DateTime]::MinValue
    $lastDelta = [DateTime]::MinValue
    $lastFull = [DateTime]::MinValue
    Write-AgentLog -Config $Config -Level "INFO" -Message "Starting PowerShell endpoint agent heartbeat=${heartbeatInterval}s posture=${postureInterval}s inventory_delta=${deltaInterval}s inventory_full=${fullInterval}s"

    if ([bool]$Config.scheduling.send_full_inventory_on_startup -and [bool]$Config.inventory.enabled) {
        try {
            $fullPayload = New-FullInventoryPayload -Config $Config -State $state
            Send-PayloadObject -Config $Config -PayloadType "inventory_full" -Payload $fullPayload | Out-Null
            $lastFull = Get-Date
        }
        catch {
            Write-AgentLog -Config $Config -Level "WARN" -Message "Startup inventory_full failed: $($_.Exception.Message)"
        }
    }

    while ($true) {
        $now = Get-Date
        if ([bool]$Config.heartbeat.enabled -and (($now - $lastHeartbeat).TotalSeconds -ge $heartbeatInterval)) {
            $heartbeatResult = Invoke-PayloadSafely -Config $Config -PayloadType "heartbeat" -BuildPayload {
                New-HeartbeatPayload -Config $Config
            }
            if ([bool]$heartbeatResult.success) {
                $lastHeartbeat = $now
            }
        }
        if ([bool]$Config.posture_snapshot.enabled -and (($now - $lastPosture).TotalSeconds -ge $postureInterval)) {
            $postureResult = Invoke-PayloadSafely -Config $Config -PayloadType "posture_snapshot" -BuildPayload {
                New-PostureSnapshotPayload -Config $Config
            }
            if ([bool]$postureResult.success) {
                $lastPosture = $now
            }
        }
        if ([bool]$Config.inventory.enabled -and (($now - $lastDelta).TotalSeconds -ge $deltaInterval)) {
            $deltaResult = Invoke-PayloadSafely -Config $Config -PayloadType "inventory_delta" -BuildPayload {
                New-InventoryDeltaPayload -Config $Config -State $state
            }
            if ([bool]$deltaResult.success) {
                $response = $deltaResult.response
                if ($null -ne $response -and $response.PSObject.Properties.Name -contains "resync_required" -and [bool]$response.resync_required -and [bool]$Config.scheduling.send_full_inventory_on_resync_required) {
                    Write-AgentLog -Config $Config -Level "WARN" -Message "Server requested inventory resync: $($response.reason)"
                    $resyncResult = Invoke-PayloadSafely -Config $Config -PayloadType "inventory_full" -BuildPayload {
                        New-FullInventoryPayload -Config $Config -State $state
                    }
                    if ([bool]$resyncResult.success) {
                        $lastFull = Get-Date
                    }
                }
                $lastDelta = $now
            }
        }
        if ([bool]$Config.inventory.enabled -and (($now - $lastFull).TotalSeconds -ge $fullInterval)) {
            $fullResult = Invoke-PayloadSafely -Config $Config -PayloadType "inventory_full" -BuildPayload {
                New-FullInventoryPayload -Config $Config -State $state
            }
            if ([bool]$fullResult.success) {
                $lastFull = $now
            }
        }

        Start-Sleep -Seconds 1
    }
}

try {
    Import-CollectorPlugins
    $resolvedConfigPath = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { Get-DefaultConfigPath } else { $ConfigPath }
    $config = Read-CollectorConfig -Path $resolvedConfigPath
    Write-AgentLog -Config $config -Level "INFO" -Message "Loaded collector config from $resolvedConfigPath"

    if ($Mode -eq "Run") {
        Start-AgentLoop -Config $config
    }
    else {
        Invoke-AgentOnce -Config $config
    }
}
catch {
    if ($null -ne $config) {
        Write-AgentLog -Config $config -Level "ERROR" -Message "Collector fatal error: $($_.Exception.Message)"
    }
    Write-Error "Collector fatal error. $($_.Exception.Message)"
    exit 1
}
