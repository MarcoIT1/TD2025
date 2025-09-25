# set_proxy.ps1
param(
    [string]$proxyAddress = "10.0.0.4:3128"  # default
)

Write-Output "Starting machine-wide proxy configuration..."

try {
    # --- 0. Verify if td-proxy IP changed ---
    $proxyHost = "td-proxy"
    try {
        $currentIp = (Resolve-DnsName $proxyHost -ErrorAction Stop | Where-Object { $_.AddressFamily -eq "IPv4" }).IPAddress
        if ($currentIp) {
            $proxyAddress = "$currentIp:3128"
            Write-Output "Resolved $proxyHost to $currentIp -> using $proxyAddress"
        }
    }
    catch {
        Write-Output "Warning: Could not resolve $proxyHost. Falling back to $proxyAddress"
    }

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

    # --- 4. Force refresh so changes apply immediately ---
    $signature = @"
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int SendMessageTimeout(
        IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@

    $SendMessageTimeout = Add-Type -MemberDefinition $signature -Name 'Win32SendMessageTimeout' -Namespace Win32Functions -PassThru

    $HWND_BROADCAST = [IntPtr]0xffff
    $WM_SETTINGCHANGE = 0x1A
    $result = [UIntPtr]::Zero

    $SendMessageTimeout::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Internet Settings", 2, 5000, [ref]$result) | Out-Null
    Write-Output "Broadcasted WM_SETTINGCHANGE -> Internet Settings refreshed."

    Write-Output "Proxy successfully configured globally (all users)."
    exit 0
}
catch {
    Write-Error "Failed to configure proxy: $_"
    exit 1
}
