# Load config
$Config = Get-Content ".\Api_Configuration.json" | ConvertFrom-Json

if (-not $Config.PolicyId) {
    throw "No PolicyId found. Run CreatePolicy.ps1 first."
}

$Headers = @{
    "api-secret-key" = $Config.ApiKey
    "api-version"    = "v1"
    "Content-Type"   = "application/json"
}

try {
    $Body = @{
        ID = $Config.PolicyId
        firewall = @{
            state = "on"
        }
    } | ConvertTo-Json -Depth 3

    Invoke-RestMethod -Uri "$($Config.BaseUrl)/policies/$($Config.PolicyId)" -Method Post -Headers $Headers -Body $Body | Out-Null
}
catch {
    throw
}
