param(
    [string]$BaseUrl = "http://127.0.0.1:8011",
    [string]$EndpointRef = $env:COMPUTERNAME,
    [string]$Hostname = $env:COMPUTERNAME,
    [string]$IpAddress = "127.0.0.1",
    [string]$ApiKey = ""
)

$ErrorActionPreference = "Stop"

$payload = @{
    payload_type = "posture_snapshot"
    endpoint_ref = $EndpointRef
    hostname = $Hostname
    ip_address = $IpAddress
    posture_interval_seconds = 3
    sequence_number = 1
    sent_at = (Get-Date).ToUniversalTime().ToString("o")
    posture = @{
        system_info = @{ name = "Windows"; version = "unknown"; build = "unknown" }
        antivirus = @()
        required_services = @()
        forbidden_processes_found = @()
        security_processes_found = @()
    }
}

$headers = @{}
if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $headers["X-API-Key"] = $ApiKey
}

$url = "$($BaseUrl.TrimEnd('/'))/telemetry/posture"
$json = $payload | ConvertTo-Json -Depth 50 -Compress
$utf8 = [System.Text.UTF8Encoding]::new($false)
$bodyBytes = $utf8.GetBytes($json)

try {
    $response = Invoke-WebRequest -Uri $url -Method Post -Body $bodyBytes -ContentType "application/json; charset=utf-8" -Headers $headers
    Write-Host "HTTP $([int]$response.StatusCode)"
    Write-Host $response.Content
}
catch {
    $statusCode = $null
    $responseBody = ""
    if ($_.Exception.Response) {
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
        } catch {}
    }
    Write-Host "HTTP $statusCode"
    Write-Host $responseBody
    throw
}
