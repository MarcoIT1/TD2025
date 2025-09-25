# set_proxy.ps1
param(
    [string]$proxyAddress = "10.0.0.4:3128"
)

Write-Output "Starting machine-wide proxy configuration..."

try {
    # --- 1. Force machine-wide proxy (disable per-user proxy) ---
    $policyPath = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (-not (Test-Path $policyPath)) {
        New-Item -Path $policyPath -Force | Out-Null
    }
    New-ItemProperty -Path $policyPath -Name ProxySettingsPerUser -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Output "Policy: ProxySettingsPerUser=0 (machine-wide proxy enforced)"

    # --- 2. Configure proxy at machine level (HKLM) ---
    $regPathMachine = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    New-ItemProperty -Path $regPathMachine -Name ProxyEnable -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $regPathMachine -Name ProxyServer -Value $proxyAddress -PropertyType String -Force | Out-Null
    Write-Output "Machine-wide (HKLM) proxy set to $proxyAddress"

    # --- 3. Configure system proxy (WinHTTP) ---
    netsh winhttp set proxy $proxyAddress | Out-Null
    Write-Output "System (WinHTTP) proxy set to $proxyAddress"

    # --- 4. Apply immediately ---
    gpupdate /target:computer /force | Out-Null

    Write-Output "Proxy successfully configured globally (all users)."
    exit 0
}
catch {
    Write-Error "Failed to configure proxy: $_"
    exit 1
}
