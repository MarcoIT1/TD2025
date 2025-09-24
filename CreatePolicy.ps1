# Load config
$Config = Get-Content ".\Api_Configuration.json" | ConvertFrom-Json

$Headers = @{
    "api-secret-key" = $Config.ApiKey
    "api-version"    = "v1"
    "Content-Type"   = "application/json"
}

try {
    $Body = @{
        name        = "Predefined Security Policy"
        description = "Automatically deployed configuration"
    } | ConvertTo-Json -Depth 3

    $NewPolicy = Invoke-RestMethod -Uri "$($Config.BaseUrl)/policies" -Method Post -Headers $Headers -Body $Body

    # Save Policy ID
    $Config | Add-Member -NotePropertyName "PolicyId" -NotePropertyValue $NewPolicy.ID -Force
    $Config | ConvertTo-Json | Out-File -FilePath ".\Api_Configuration.json" -Encoding utf8
}
catch {
    throw
}
