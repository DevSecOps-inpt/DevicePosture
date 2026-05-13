param(
    [string]$BaseUrl = "http://127.0.0.1:8011",
    [string]$EndpointRef = $env:COMPUTERNAME,
    [string]$Hostname = $env:COMPUTERNAME,
    [string]$IpAddress = "127.0.0.1",
    [string]$ApiKey = ""
)

$ErrorActionPreference = "Stop"

$payload = @{
    payload_type = "inventory_full"
    endpoint_ref = $EndpointRef
    hostname = $Hostname
    ip_address = $IpAddress
    category = "all"
    baseline_id = [guid]::NewGuid().ToString()
    sequence_number = 1
    sent_at = (Get-Date).ToUniversalTime().ToString("o")
    inventory = @{
        services = @()
        processes = @()
        hotfixes = @()
        software = @()
    }
}

$headers = @{}
if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $headers["X-API-Key"] = $ApiKey
}

$url = "$($BaseUrl.TrimEnd('/'))/telemetry/inventory/full"
$body = $payload | ConvertTo-Json -Depth 50 -Compress

try {
    $response = Invoke-WebRequest -Uri $url -Method Post -Body $body -ContentType "application/json" -Headers $headers
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
