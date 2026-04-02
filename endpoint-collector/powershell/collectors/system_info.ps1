Register-Collector -Name "system_info" -ScriptBlock {
    param($Context)

    $os = Get-CimInstance Win32_OperatingSystem
    $computerSystem = Get-CimInstance Win32_ComputerSystem
    $domainName = $null
    $isDomainJoined = $false
    if ($null -ne $computerSystem) {
        $domainName = [string]$computerSystem.Domain
        $isDomainJoined = [bool]$computerSystem.PartOfDomain
    }
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
        extras = @{
            domain_membership = @{
                joined = $isDomainJoined
                domain_name = if ([string]::IsNullOrWhiteSpace($domainName)) { $null } else { $domainName }
            }
        }
    }
}
