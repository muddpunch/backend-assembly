$ErrorActionPreference = 'Stop'
$base = if ($env:OGFN_TEST_BASE) { $env:OGFN_TEST_BASE } else { 'http://127.0.0.1:8080' }
$name = 'AsmPlayer_' + (Get-Random -Minimum 1000 -Maximum 9999)
$password = 'LocalPassword-' + (Get-Random -Minimum 100000 -Maximum 999999)

$form = @{
    grant_type = 'password'
    username   = $name
    password   = $password
}
$token = Invoke-RestMethod -Method Post -Uri "$base/account/api/oauth/token" -ContentType 'application/x-www-form-urlencoded' -Body $form
if ($token.token_type -ne 'bearer' -or $token.access_token.Length -ne 64 -or $token.refresh_token.Length -ne 64) {
    throw 'OAuth password response failed schema validation'
}

$headers = @{ Authorization = "Bearer $($token.access_token)" }
$verify = Invoke-RestMethod -Method Get -Uri "$base/account/api/oauth/verify" -Headers $headers
if ($verify.account_id -ne $token.account_id -or $verify.displayName -ne $name) {
    throw 'OAuth verify response mismatch'
}

$account = Invoke-RestMethod -Method Get -Uri "$base/account/api/public/account/$($token.account_id)" -Headers $headers
if ($account.id -ne $token.account_id -or $account.displayName -ne $name) {
    throw 'Account lookup response mismatch'
}

$refresh = Invoke-RestMethod -Method Post -Uri "$base/account/api/oauth/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
    grant_type    = 'refresh_token'
    refresh_token = $token.refresh_token
}
if ($refresh.access_token.Length -ne 64) {
    throw 'Refresh token response failed schema validation'
}

Write-Output "PASS account=$($token.account_id) displayName=$name"
