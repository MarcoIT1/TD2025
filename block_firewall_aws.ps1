# --- Step 1: Remove host overrides ---
$hostsFile   = "$env:SystemRoot\System32\drivers\etc\hosts"
$backupHosts = "$hostsFile.bak.$(Get-Date -Format 'yyyyMMdd-HHmmss')"

$trendHosts = @(
    "api.eu.xdr.trendmicro.com",
    "api.xdr.trendmicro.com",
    "xpx-eu.trendmicro.com",
    "xpx.trendmicro.com",
    "visionone.trendmicro.com"
)

if (Test-Path $hostsFile) {
    Copy-Item $hostsFile $backupHosts -Force

    # Remove read-only attribute if set
    Attrib -R $hostsFile

    $lines = Get-Content $hostsFile
    $filtered = $lines | Where-Object {
        $keep = $true
        foreach ($h in $trendHosts) {
            if ($_ -match $h) { $keep = $false; break }
        }
        $keep
    }

    # Rewrite safely
    $filtered | Out-File -FilePath $hostsFile -Encoding ASCII -Force
}

# --- Step 2: Block AWS eu-central-1 ranges ---
$AwsIpRangesUrl = "https://ip-ranges.amazonaws.com/ip-ranges.json"
$Region    = "eu-central-1"
$RulePrefix = "Block AWS $Region"

try {
    $json = Invoke-RestMethod -Uri $AwsIpRangesUrl -UseBasicParsing
}
catch {
    exit 1
}

$prefixes = $json.prefixes | Where-Object {
    $_.region -eq $Region -and $_.service -eq "AMAZON"
} | Select-Object -ExpandProperty ip_prefix -Unique

foreach ($prefix in $prefixes) {
    $ruleName = "$RulePrefix $prefix"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound -Action Block -Enabled True `
            -RemoteAddress $prefix | Out-Null
    }
}
