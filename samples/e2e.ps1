#Requires -Version 7
<#
.SYNOPSIS
    End-to-end check of the demonstration apps on Windows, with real DPAPI.

.DESCRIPTION
    Publishes both samples as self-contained win-x64 executables, starts the mock server with short-lived
    tokens and key rotation, then for each sample runs set-credentials (fake demo credentials piped to stdin),
    verify-credentials, show-credentials-info and export. Fails if any step fails, if a secret appears in the
    output or in the secrets file, or if the token renewal and 401 retry paths weren't exercised.

    Used by CI on windows-latest. Also handy for a local or server dry run.
#>
param(
    [int] $Port = 5090
)

# Two mocks, because each auth path hides the other: an early renewal hands out a fresh token just before a key
# rotation, and a 401 re-login resets the expiry clock.
#   $Port      3 s tokens, no rotation: the API export outlasts its token, so it is renewed early.
#   $Port + 1  long-lived tokens, key rotated every 4 requests: some requests get a 401 and are retried.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path ([IO.Path]::GetTempPath()) "lockbox-e2e-$([guid]::NewGuid().ToString('N'))"
$url = "http://127.0.0.1:$Port"
$rotatingUrl = "http://127.0.0.1:$($Port + 1)"
New-Item -ItemType Directory $work | Out-Null
Write-Host "Working folder: $work"

function Assert([bool] $condition, [string] $message, [string] $detail = '') {
    if (-not $condition) {
        if ($detail) { Write-Host $detail }
        throw "FAILED: $message"
    }
    Write-Host "  ok: $message"
}

# Runs a published sample, piping $Lines to its stdin. Returns its exit code and combined output.
function Invoke-Sample([string] $App, [string[]] $Arguments, [string[]] $Lines = @()) {
    $exe = Join-Path $work "$App\$App.exe"
    $ErrorActionPreference = 'Continue'
    $output = ($Lines | & $exe @Arguments 2>&1 | Out-String)
    [pscustomobject]@{ Code = $LASTEXITCODE; Output = $output }
}

# Points a published sample at a mock by rewriting its settings file.
function Set-SampleUrl([string] $App, [string] $BaseUrl) {
    @{ BaseUrl = "$BaseUrl/" } | ConvertTo-Json | Set-Content (Join-Path $work "$App\$App.settings.json")
}

function Start-Mock([string] $Name, [string] $Url, [string[]] $Options) {
    $process = Start-Process dotnet -PassThru -NoNewWindow `
        -ArgumentList (@($mockDll, '--url', $Url) + $Options) `
        -RedirectStandardOutput (Join-Path $work "$Name.log") -RedirectStandardError (Join-Path $work "$Name.err")
    $deadline = (Get-Date).AddSeconds(30)
    while ($true) {
        try { if ((Invoke-WebRequest "$Url/health" -UseBasicParsing).Content -eq 'ok') { return $process } } catch { }
        if ((Get-Date) -gt $deadline) { throw "The $Name mock server did not start." }
        Start-Sleep -Milliseconds 250
    }
}

# 1. Publish the samples self-contained.
foreach ($app in 'JiraExportSample', 'ApiExportSample') {
    dotnet publish (Join-Path $root "samples\$app") -p:PublishProfile=win-x64 -o (Join-Path $work $app) --nologo -v quiet
    if ($LASTEXITCODE) { throw "Publishing $app failed." }
    Set-SampleUrl $app $url
}

# 2. Start the mocks.
dotnet build (Join-Path $root 'samples\MockServer') -c Release --nologo -v quiet
if ($LASTEXITCODE) { throw 'Building the mock server failed.' }
$mockDll = Join-Path $root 'samples\MockServer\bin\Release\net10.0\MockServer.dll'
$mocks = @()

try {
    $mocks += Start-Mock 'mock' $url @('--token-lifetime', '3')
    $mocks += Start-Mock 'mock-rotating' $rotatingUrl @('--token-lifetime', '600', '--invalidate-every', '4')

    # ---- Jira sample: PAT ----
    Write-Host "`nJiraExportSample"
    $jiraSecrets = Join-Path $work 'jira-secrets.json'
    $opts = @('--secrets-path', $jiraSecrets)

    $r = Invoke-Sample JiraExportSample (@('set-credentials') + $opts) @('demo-pat-0000')
    Assert ($r.Code -eq 0) 'set-credentials succeeds' $r.Output
    Assert ($r.Output -match 'Signed in as Demo User') 'set-credentials verifies against the service' $r.Output

    $file = Get-Content $jiraSecrets -Raw
    Assert ($file -notmatch 'demo-pat-0000') 'the secrets file does not contain the PAT'
    Assert ($file -match '"protector": "dpapi-user"') 'the secrets file uses DPAPI'
    Assert ($file -match [regex]::Escape(($env:USERNAME))) 'encryptedBy records this account'

    $r = Invoke-Sample JiraExportSample (@('verify-credentials') + $opts)
    Assert ($r.Code -eq 0 -and $r.Output -match 'jira\.pat\s+OK') 'verify-credentials succeeds' $r.Output

    $r = Invoke-Sample JiraExportSample (@('show-credentials-info') + $opts)
    Assert ($r.Code -eq 0 -and $r.Output -match 'jira\.pat\s+set ') 'show-credentials-info lists the PAT' $r.Output

    $issues = Join-Path $work 'issues.json'
    $r = Invoke-Sample JiraExportSample (@('export', '--out', $issues, '--verbose') + $opts)
    Assert ($r.Code -eq 0) 'export succeeds' $r.Output
    Assert ((Get-Content $issues -Raw | ConvertFrom-Json).Count -eq 120) 'export wrote all 120 issues'
    Assert ($r.Output -match 'Authorization: \*') 'verbose logs show the Authorization header redacted' $r.Output
    Assert ($r.Output -notmatch 'demo-pat-0000') 'the PAT never appears in the output' $r.Output

    $r = Invoke-Sample JiraExportSample (@('set-credentials', '--secrets-path', (Join-Path $work 'wrong.json'))) @('revoked-pat')
    Assert ($r.Code -eq 1 -and $r.Output -match 'rejected the personal access token') 'a wrong PAT is reported by set-credentials' $r.Output

    # ---- API sample: username + password -> JWT ----
    Write-Host "`nApiExportSample"
    $apiSecrets = Join-Path $work 'api-secrets.json'
    $opts = @('--secrets-path', $apiSecrets)

    $r = Invoke-Sample ApiExportSample (@('set-credentials') + $opts) @('demo', 'demo-password')
    Assert ($r.Code -eq 0 -and $r.Output -match 'Signed in\.') 'set-credentials succeeds and signs in' $r.Output
    Assert ((Get-Content $apiSecrets -Raw) -notmatch 'demo-password') 'the secrets file does not contain the password'

    $r = Invoke-Sample ApiExportSample (@('verify-credentials') + $opts)
    Assert ($r.Code -eq 0) 'verify-credentials succeeds' $r.Output

    # Swapping the encrypted username and password must make both fail to decrypt.
    $swapped = Join-Path $work 'api-swapped.json'
    $json = Get-Content $apiSecrets -Raw | ConvertFrom-Json
    $u = $json.secrets.'api.username'.ciphertext
    $json.secrets.'api.username'.ciphertext = $json.secrets.'api.password'.ciphertext
    $json.secrets.'api.password'.ciphertext = $u
    $json | ConvertTo-Json -Depth 5 | Set-Content $swapped
    $r = Invoke-Sample ApiExportSample @('verify-credentials', '--secrets-path', $swapped)
    Assert ($r.Code -eq 1 -and $r.Output -match "can't be decrypted") 'swapped entries fail to decrypt' $r.Output

    $records = Join-Path $work 'records.json'
    # 1 s between 10 pages outlasts the 3 s tokens, so they're renewed before they expire.
    $r = Invoke-Sample ApiExportSample (@('export', '--out', $records, '--delay-ms', '1000', '--verbose') + $opts)
    Assert ($r.Code -eq 0) 'export succeeds' $r.Output
    Assert ((Get-Content $records -Raw | ConvertFrom-Json).Count -eq 95) 'export wrote all 95 records'
    Assert ($r.Output -match 'Signing in again\.') 'the token was renewed before it expired' $r.Output
    Assert ($r.Output -match 'Authorization: \*') 'verbose logs show the Authorization header redacted' $r.Output
    Assert ($r.Output -notmatch 'demo-password') 'the password never appears in the output' $r.Output
    Assert ($r.Output -notmatch 'eyJ') 'no JWT appears in the output' $r.Output

    # Against the rotating mock, requests 5 and 9 get a 401 and are retried after signing in again.
    Set-SampleUrl ApiExportSample $rotatingUrl
    $r = Invoke-Sample ApiExportSample (@('export', '--out', $records) + $opts)
    Assert ($r.Code -eq 0) 'export succeeds despite 401s' $r.Output
    Assert ((Get-Content $records -Raw | ConvertFrom-Json).Count -eq 95) 'export wrote all 95 records'
    Assert ((Select-String -InputObject $r.Output -Pattern 'retrying once' -AllMatches).Matches.Count -eq 2) 'both 401s were handled by signing in again and retrying' $r.Output

    Write-Host "`nAll end-to-end checks passed."
}
catch {
    foreach ($name in 'mock', 'mock-rotating') {
        Write-Host "`n--- $name log ---"
        Get-Content (Join-Path $work "$name.log"), (Join-Path $work "$name.err") -ErrorAction SilentlyContinue
    }
    throw
}
finally {
    $mocks | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
