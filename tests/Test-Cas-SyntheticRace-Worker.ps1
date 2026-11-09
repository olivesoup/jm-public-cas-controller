# Native negative tests execute the ACTUAL synthetic race writer AST, with
# a fake GitHub token and mocked HTTPS REST; ZERO network/API mutations.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$source=Join-Path $root 'scripts/Test-JM-Public-CAS-SyntheticRace.ps1'
$tokens=$null
$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw 'CAS_RACE_SOURCE_PARSE_FAILED' }
$writers=@($ast.FindAll({
  param($node)
  $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
  $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
  $node.Left.VariablePath.UserPath -ceq 'writer'
},$true))
if ($writers.Count -ne 1) { throw 'CAS_RACE_WRITER_BLOCK_NOT_UNIQUE' }
$writer= & ([ScriptBlock]::Create($writers[0].Right.Extent.Text))
$theRef='refs/tags/jm-cas/v1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$sha='b' * 40
$otherSha='c' * 40
$script:expectedTagSha=$sha
$go=Join-Path ([IO.Path]::GetTempPath()) ('cas-unit-go-'+[guid]::NewGuid().ToString('N'))
$ready=Join-Path ([IO.Path]::GetTempPath()) ('cas-unit-ready-'+[guid]::NewGuid().ToString('N'))
$script:mockMode='ok'
$script:mockStatus=0
$script:mockHttpObject=$null
$script:mockToken='FAKE_TEST_TOKEN_NEVER_USE'
$script:mockAuthFails=$false
$script:mockRestCalls=0

# The production REST client catches real HTTP exceptions whose Response has
# a provider StatusCode; this test mimics that typed object without text parsing.
Add-Type -TypeDefinition @'
using System;
public class JMTestHttpResponse {
    public int StatusCode { get; }
    public JMTestHttpResponse(int status) { StatusCode = status; }
}
public class JMTestHttpException : Exception {
    public JMTestHttpResponse Response { get; }
    public JMTestHttpException(int status) : base("untrusted diagnostic HTTP 422") {
        Response = new JMTestHttpResponse(status);
    }
}
'@

function gh {
  param([string]$auth,[string]$verb)
  if ($auth -cne 'auth' -or $verb -cne 'token') { throw 'CAS_TEST_UNEXPECTED_GH_CALL' }
  if ($script:mockAuthFails) { $global:LASTEXITCODE=1; return }
  $global:LASTEXITCODE=0
  return $script:mockToken
}
function Invoke-RestMethod {
  [CmdletBinding()]
  param(
    [string]$Uri,
    [string]$Method,
    [hashtable]$Headers,
    [string]$ContentType,
    [string]$Body
  )
  $script:mockRestCalls++
  if ($Uri -cne 'https://api.github.com/repos/olivesoup/jm-gate-witness/git/refs' -or
      $Method -cne 'Post' -or
      $ContentType -cne 'application/json' -or
      $Headers.Authorization -cne ('Bearer '+$script:mockToken) -or
      $Headers.Accept -cne 'application/vnd.github+json') {
    throw 'CAS_TEST_UNEXPECTED_REST_TARGET_OR_AUTH'
  }
  $parsedBody=$Body | ConvertFrom-Json -ErrorAction Stop
  if ($parsedBody.ref -cne $theRef -or $parsedBody.sha -cne $script:expectedTagSha) {
    throw 'CAS_TEST_WRONG_REF_REQUEST_BODY'
  }
  if ($script:mockMode -ceq 'http') {
    $response=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$script:mockStatus)
    throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Genuine typed webcmdlet HTTP test fixture', $response)
  }
  if ($script:mockMode -ceq 'forged-http-response') {
    throw [JMTestHttpException]::new($script:mockStatus)
  }
  if ($script:mockMode -ceq 'text-spoof') {
    throw [System.Exception]::new('TRANSIENT_AUTH_ERROR: fake message HTTP 422')
  }
  if ($script:mockMode -ceq 'transport') {
    throw [System.Net.WebException]::new('DNS/TLS/network: fake HTTP 422')
  }
  if ($script:mockMode -ceq 'wrong-ref') {
    return [pscustomobject]@{ref='refs/tags/jm-cas/v1/other';object=[pscustomobject]@{sha=$script:expectedTagSha;type='tag'}}
  }
  if ($script:mockMode -ceq 'wrong-type') {
    return [pscustomobject]@{ref=$theRef;object=[pscustomobject]@{sha=$script:expectedTagSha;type='commit'}}
  }
  if ($script:mockMode -ceq 'wrong-sha') {
    return [pscustomobject]@{ref=$theRef;object=[pscustomobject]@{sha=('0'*40);type='tag'}}
  }
  return [pscustomobject]@{ref=$theRef;object=[pscustomobject]@{sha=$script:expectedTagSha;type='tag'}}
}
function Test-Writer([string]$tagSha=$sha) {
  $script:expectedTagSha=$tagSha
  return (& $writer 'olivesoup/jm-gate-witness' $theRef $tagSha $go $ready)
}
function Assert-Unknown([string]$scenario) {
  $result=Test-Writer
  if ($result.ok -or $result.conflict -or $result.code -eq 0 -or
      $result.httpConflictStatus -ne 0) {
    throw ('CAS_RACE_FALSE_HTTP_RESPONSE_CLASSIFICATION_'+$scenario)
  }
}
try {
  [IO.File]::WriteAllText($go,'GO')
  $valid=Test-Writer
  if (-not $valid.ok -or $valid.conflict -or $valid.code -ne 0 -or
      $valid.httpConflictStatus -ne 0) { throw 'CAS_RACE_VALID_JSON_RESPONSE_REJECTED' }

  foreach ($scenario in @('wrong-ref','wrong-type','wrong-sha')) {
    $script:mockMode=$scenario
    Assert-Unknown $scenario
  }

  $script:mockMode='http'
  foreach ($status in @(409,422)) {
    $script:mockStatus=$status
    $loser=Test-Writer
    if ($loser.ok -or -not $loser.conflict -or $loser.code -eq 0 -or
        $loser.httpConflictStatus -ne $status) {
      throw ('CAS_RACE_REAL_STRUCTURED_HTTP_CONFLICT_NOT_CAPTURED_'+$status)
    }
  }

  foreach ($status in @(400,401,403,404,429,500,503)) {
    $script:mockStatus=$status
    Assert-Unknown ('real-http-'+$status)
  }

  $script:mockMode='forged-http-response'
  $script:mockStatus=422
  Assert-Unknown 'forged-object-with-Response-StatusCode-422'

  $script:mockMode='text-spoof'
  Assert-Unknown 'fake-error-text-containing-HTTP-422'
  $script:mockMode='transport'
  Assert-Unknown 'transport-error-containing-HTTP-422'

  $script:mockAuthFails=$true
  Assert-Unknown 'gh-token-auth-failed'
  $script:mockAuthFails=$false
  $script:mockMode='ok'

  $secondValid=Test-Writer -tagSha $otherSha
  if (-not $secondValid.ok -or $secondValid.attemptedTagSha -cne $otherSha -or
      $valid.attemptedTagSha -ceq $secondValid.attemptedTagSha) {
    throw 'CAS_RACE_DIFFERENT_CLAIMS_NOT_VERIFIED'
  }
  $results=@($valid,$secondValid)
  if (@($results | Where-Object {$_.ok -eq $true -and $_.code -eq 0}).Count -ne 2) {
    throw 'CAS_RACE_DOUBLE_SUCCESS_FIXTURE_BAD'
  }
  $sourceBytes=[IO.File]::ReadAllText($source)
  if ($sourceBytes -notmatch 'CAS_RACE_ONE_WINNER_ONE_CONFLICT_NOT_PROVEN' -or
      $sourceBytes -notmatch 'CAS_RACE_WINNER_LOSER_DIFFERENT_SUBJECTS_UNVERIFIED' -or
      $sourceBytes -notmatch 'CAS_RACE_TWO_DIFFERENT_CLAIMS_NOT_PROVEN' -or
      $sourceBytes -notmatch 'Microsoft.PowerShell.Commands.HttpResponseException' -or
      $sourceBytes -notmatch 'System.Net.HttpWebResponse' -or
      $sourceBytes -match '\[regex\]::Match\(\$msg' -or
      $sourceBytes -match 'gh api --method POST "repos/\$repository/git/refs"') {
    throw 'CAS_RACE_STATUS_SPOOF_FIX_NOT_ENFORCED'
  }
  if ($script:mockRestCalls -lt 13) { throw 'CAS_RACE_HTTP_NEGATIVE_FIXTURES_NOT_EXERCISED' }
  $global:LASTEXITCODE=0
  Write-Output 'CAS_RACE_TYPED_HTTP_AND_DIFFERENT_CLAIMS_NEGATIVE_PASS_NO_GITHUB_API'
} finally {
  Remove-Item -LiteralPath $go,$ready -Force -ErrorAction SilentlyContinue
}
