Register-Collector -Name "hotfixes" -ScriptBlock {
    param($Context)

    try {
        return @{
            hotfixes = @(Get-HotFix | ForEach-Object {
                @{
                    id = $_.HotFixID
                    description = $_.Description
                    installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString("yyyy-MM-dd") } else { $null }
                }
            })
        }
    }
    catch {
        return @{ hotfixes = @() }
    }
}
