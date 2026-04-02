Register-Collector -Name "antivirus" -ScriptBlock {
    param($Context)

    try {
        return @{
            antivirus_products = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntivirusProduct" | ForEach-Object {
                @{
                    name = $_.displayName
                    identifier = $_.displayName.ToLower()
                    state = [string]$_.productState
                }
            })
        }
    }
    catch {
        return @{ antivirus_products = @() }
    }
}
