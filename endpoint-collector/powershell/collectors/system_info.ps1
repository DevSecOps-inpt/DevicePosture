Register-Collector -Name "system_info" -ScriptBlock {
    param($Context)

    $os = Get-CimInstance Win32_OperatingSystem
    return @{
        endpoint_id = Get-EndpointId
        hostname = $env:COMPUTERNAME
        network = @{
            ipv4 = Get-ActiveIPv4
        }
        os = @{
            name = $os.Caption
            version = $os.Version
            build = [string]$os.BuildNumber
        }
    }
}
