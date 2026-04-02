Register-Collector -Name "processes" -ScriptBlock {
    param($Context)

    try {
        return @{
            processes = @(Get-Process | ForEach-Object {
                @{
                    pid = $_.Id
                    name = $_.ProcessName
                }
            })
        }
    }
    catch {
        return @{ processes = @() }
    }
}
