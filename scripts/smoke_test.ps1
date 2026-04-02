param(
    [string]$PythonPath = "C:\Users\essag\Documents\Playground\.venv\Scripts\python.exe",
    [string]$RootPath = "C:\Users\essag\Documents\Playground"
)

$ErrorActionPreference = "Stop"
$logs = Join-Path $RootPath ".logs"
$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$procs = @()

function Start-ServiceProcess {
    param(
        [string]$Name,
        [string]$WorkDir,
        [string]$Command
    )

    New-Item -ItemType Directory -Force -Path $logs | Out-Null
    $stdout = Join-Path $logs ("{0}-{1}.out.log" -f $Name, $runId)
    $stderr = Join-Path $logs ("{0}-{1}.err.log" -f $Name, $runId)
    Start-Process -FilePath "powershell" `
        -ArgumentList "-NoProfile", "-Command", $Command `
        -WorkingDirectory $WorkDir `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru
}

function Wait-ForHealth {
    param([string]$Url)

    for ($i = 0; $i -lt 30; $i++) {
        try {
            $response = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 2
            if ($response.status -eq "ok") {
                return
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }

    throw "Healthcheck failed for $Url"
}

try {
    $telemetryCmd = ('& ''{0}'' -m uvicorn app.main:app --host 127.0.0.1 --port 8001' -f $PythonPath)
    $policyCmd = ('& ''{0}'' -m uvicorn app.main:app --host 127.0.0.1 --port 8002' -f $PythonPath)
    $enforcementCmd = ('$env:FORTIGATE_BASE_URL=''http://127.0.0.1:65535''; $env:FORTIGATE_TOKEN=''test-token''; $env:HTTP_TIMEOUT_SECONDS=''2''; $env:HTTP_RETRIES=''1''; & ''{0}'' -m uvicorn app.main:app --host 127.0.0.1 --port 8004' -f $PythonPath)
    $evaluationCmd = ('$env:TELEMETRY_API_URL=''http://127.0.0.1:8001''; $env:POLICY_SERVICE_URL=''http://127.0.0.1:8002''; $env:ENFORCEMENT_SERVICE_URL=''http://127.0.0.1:8004''; & ''{0}'' -m uvicorn app.main:app --host 127.0.0.1 --port 8003' -f $PythonPath)

    $procs += Start-ServiceProcess -Name "telemetry" -WorkDir (Join-Path $RootPath "services\\telemetry-api") -Command $telemetryCmd
    $procs += Start-ServiceProcess -Name "policy" -WorkDir (Join-Path $RootPath "services\\policy-service") -Command $policyCmd
    $procs += Start-ServiceProcess -Name "enforcement" -WorkDir (Join-Path $RootPath "services\\enforcement-service") -Command $enforcementCmd
    $procs += Start-ServiceProcess -Name "evaluation" -WorkDir (Join-Path $RootPath "services\\evaluation-engine") -Command $evaluationCmd

    Wait-ForHealth "http://127.0.0.1:8001/healthz"
    Wait-ForHealth "http://127.0.0.1:8002/healthz"
    Wait-ForHealth "http://127.0.0.1:8003/healthz"
    Wait-ForHealth "http://127.0.0.1:8004/healthz"

    $policyPayload = @{
        name = "Windows 11 baseline smoke $runId"
        description = "Smoke test policy"
        target_action = "quarantine"
        is_active = $true
        conditions = @(
            @{ type = "os_version"; field = "os"; operator = "windows_build_gte"; value = @{ name = "Microsoft Windows 11 Pro"; min_build = 22631 } },
            @{ type = "required_kbs"; field = "hotfixes"; operator = "contains_all"; value = @("KB5039212", "KB5039302") },
            @{ type = "allowed_antivirus"; field = "antivirus_products"; operator = "contains_any"; value = @("microsoft defender antivirus", "crowdstrike falcon") }
        )
    } | ConvertTo-Json -Depth 8
    $policy = Invoke-RestMethod -Uri "http://127.0.0.1:8002/policies" -Method Post -ContentType "application/json" -Body $policyPayload

    $assignmentPayload = @{ assignment_type = "default"; assignment_value = "default" } | ConvertTo-Json
    $assignment = Invoke-RestMethod -Uri ("http://127.0.0.1:8002/policies/{0}/assignments" -f $policy.id) -Method Post -ContentType "application/json" -Body $assignmentPayload

    $telemetryPayload = @{
        schema_version = "1.0"
        collector_type = "smoke-test"
        endpoint_id = "ws-smoke-$runId"
        hostname = "WS-SMOKE-$runId"
        collected_at = (Get-Date).ToUniversalTime().ToString("o")
        network = @{ ipv4 = "192.168.1.26" }
        os = @{ name = "Microsoft Windows 11 Pro"; version = "10.0.22631"; build = "22631" }
        hotfixes = @(@{ id = "KB5039212"; description = "Security Update"; installed_on = "2026-03-20" })
        services = @(@{ name = "WinDefend"; display_name = "Microsoft Defender Antivirus Service"; status = "Running"; start_type = "Automatic" })
        processes = @(@{ pid = 1234; name = "MsMpEng" })
        antivirus_products = @(@{ name = "Unknown AV"; identifier = "unknown av"; state = "enabled" })
        extras = @{}
    } | ConvertTo-Json -Depth 8
    $ingest = Invoke-RestMethod -Uri "http://127.0.0.1:8001/telemetry" -Method Post -ContentType "application/json" -Body $telemetryPayload
    $endpointId = ($telemetryPayload | ConvertFrom-Json).endpoint_id

    $decision = Invoke-RestMethod -Uri ("http://127.0.0.1:8003/evaluate/{0}" -f $endpointId) -Method Post
    $latestEnforcement = Invoke-RestMethod -Uri ("http://127.0.0.1:8004/enforcement/{0}/latest" -f $endpointId) -Method Get
    $auditEvents = Invoke-RestMethod -Uri "http://127.0.0.1:8004/audit-events" -Method Get

    [pscustomobject]@{
        run_id = $runId
        policy_id = $policy.id
        assignment_id = $assignment.id
        endpoint_id = $endpointId
        ingest = $ingest
        decision = $decision
        latest_enforcement = $latestEnforcement
        latest_audit_events = @($auditEvents | Select-Object -First 4)
    } | ConvertTo-Json -Depth 10 | Write-Output
}
finally {
    foreach ($proc in $procs) {
        if ($null -ne $proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force
        }
    }
}
