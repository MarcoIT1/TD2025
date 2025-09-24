param(
    [string]$proxyAddress = "10.0.0.4:3128"
)

Write-Output "Starting proxy configuration..."

try {
    # --- 1. Configure system proxy (WinHTTP) ---
    netsh winhttp set proxy $proxyAddress | Out-Null
    Write-Output "System (WinHTTP) proxy set to $proxyAddress"

    # --- 2. Configure machine-wide proxy (HKLM, default for all users) ---
    $regPathMachine = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    New-ItemProperty -Path $regPathMachine -Name ProxyEnable -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $regPathMachine -Name ProxyServer -Value $proxyAddress -PropertyType String -Force | Out-Null
    Write-Output "Machine-wide (HKLM) proxy set to $proxyAddress"

    # --- 3. Configure proxy for all loaded user hives (HKU) ---
    Get-ChildItem Registry::HKEY_USERS | ForEach-Object {
        $sid = $_.PSChildName
        if ($sid -match "S-\d-\d+-(\d+-){1,14}\d+$") {   # only real user SIDs
            $regPathUser = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            if (Test-Path $regPathUser) {
                Set-ItemProperty -Path $regPathUser -Name ProxyEnable -Value 1 -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $regPathUser -Name ProxyServer -Value $proxyAddress -ErrorAction SilentlyContinue
                Write-Output "User proxy applied for SID $sid"
            }
        }
    }

    Write-Output "Proxy successfully configured for system and all users."
    exit 0
}
catch {
    Write-Error "Failed to configure proxy: $_"
    exit 1
}