Register-Collector -Name "services" -ScriptBlock {
    param($Context)

    try {
        return @{
            services = @(Get-CimInstance Win32_Service | ForEach-Object {
                @{
                    name = $_.Name
                    display_name = $_.DisplayName
                    status = [string]$_.State
                    start_type = [string]$_.StartMode
                }
            })
        }
    }
    catch {
        return @{ services = @() }
    }
}
