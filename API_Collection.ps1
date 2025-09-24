Write-Host "=== Trend Micro Vision One - Automated Deployment ===" -ForegroundColor Cyan

# Ask user for region and API key
$Region = Read-Host "Please enter your Cloud One region (e.g. de-1, us-1, eu-1)"
$ApiKey = Read-Host "Please enter your Cloud One API Secret Key"

# Build base URL
$BaseUrl = "https://workload.$Region.cloudone.trendmicro.com/api"

# Save config to JSON
$Config = @{
    Region   = $Region
    ApiKey   = $ApiKey
    BaseUrl  = $BaseUrl
}
$Config | ConvertTo-Json | Out-File -FilePath ".\Api_Configuration.json" -Encoding utf8

try {
    # --- Run the policy creation script ---
    & ".\CreatePolicy.ps1"

    # --- Run the policy modification script ---
    & ".\ModifyPolicy.ps1"

    Write-Host "All steps completed successfully." -ForegroundColor Green
}
catch {
    Write-Host "Process failed." -ForegroundColor Red
}
