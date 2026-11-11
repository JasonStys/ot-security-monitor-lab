# Jason Stys: require original signed Wireshark provider before hosted-only administrative extraction.
# Parameters: Package@L3. Variables: ErrorActionPreference@L4, taskSignature@L6. No functions.
param([Parameter(Mandatory = $true)][string]$Package)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'Hosted Windows only.' }
$taskSignature = Get-AuthenticodeSignature -LiteralPath $Package
if ($taskSignature.Status -ne 'Valid' -or $taskSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Wireshark Foundation(,|$)') { throw 'Official Wireshark signature required.' }
Write-Output 'Verified original valid Wireshark Foundation Authenticode signature.'
