# block_trendvision.ps1
# This script blocks only Trend Vision One communication endpoints.
# Run as Administrator.

param(
    [string[]] $BlockedFQDNs = @(
        "api.eu.xdr.trendmicro.com",
        "*.service-gateway.trendmicro.com",
        "agents.eu.xdr.trendmicro.com",
        "tm-auth.eu.trendmicro.com"
        # add the full list from Trend Vision One documentation
    ),
    [int[]] $BlockedPorts = @(80, 443),
    [string[]] $BlockedIPs = @(
        # If Trend lists raw IP addresses in their firewall exceptions doc, add them here
        # Example:
        # "52.123.45.67",
        # "18.234.56.78"
    )
)

Write-Output "Blocking Trend Vision One communication endpoints..."

# 1. Block by IPs (if provided)
foreach ($ip in $BlockedIPs) {
    foreach ($port in $BlockedPorts) {
        New-NetFirewallRule -DisplayName "Block Trend IP $ip:$port" `
            -Direction Outbound -Action Block -Protocol TCP `
            -RemoteAddress $ip -RemotePort $port -Profile Any
    }
}

# 2. Block by FQDNs (requires Windows 10 / Server 2019+ for FQDN rules)
foreach ($fqdn in $BlockedFQDNs) {
    foreach ($port in $BlockedPorts) {
        New-NetFirewallRule -DisplayName "Block Trend FQDN $fqdn:$port" `
            -Direction Outbound -Action Block -Protocol TCP `
            -RemoteAddress $fqdn -RemotePort $port -Profile Any
    }
}