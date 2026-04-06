Register-Collector -Name "antivirus" -ScriptBlock {
    param($Context)

    try {
        $mpStatus = $null
        try {
            $mpStatus = Get-MpComputerStatus
        }
        catch {
            $mpStatus = $null
        }

        return @{
            antivirus_products = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntivirusProduct" | ForEach-Object {
                $displayName = $_.displayName
                $identifier = $displayName.ToLower()
                $isDefender = $identifier -like "*defender*"
                @{
                    name = $displayName
                    identifier = $identifier
                    state = [string]$_.productState
                    real_time_protection_enabled = if ($isDefender -and $null -ne $mpStatus) { [bool]$mpStatus.RealTimeProtectionEnabled } else { $null }
                    antivirus_enabled = if ($isDefender -and $null -ne $mpStatus) { [bool]$mpStatus.AntivirusEnabled } else { $null }
                    am_service_enabled = if ($isDefender -and $null -ne $mpStatus) { [bool]$mpStatus.AMServiceEnabled } else { $null }
                    tamper_protection_source = if ($isDefender -and $null -ne $mpStatus) { [string]$mpStatus.TamperProtectionSource } else { $null }
                }
            })
        }
    }
    catch {
        return @{ antivirus_products = @() }
    }
}
