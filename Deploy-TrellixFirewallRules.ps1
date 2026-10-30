#Requires -Version 7.4
<#
.SYNOPSIS
Stages the reviewed Trellix firewall rule mappings into Microsoft Defender for Endpoint (GCC High),
as new, DISABLED, UNASSIGNED policies. Nothing is turned on and no devices are assigned.

.DESCRIPTION
Run this once per tenant. It:
  1. Checks the XML you provide is byte-for-byte the same export this mapping was built for.
  2. Signs you into your GCC High tenant (Microsoft device-code sign-in; a code + link appear on screen).
  3. Creates ONE new policy in Defender (Endpoint security > Firewall) containing every rule that could
     be mapped automatically. Every rule in it is created DISABLED. The policy has ZERO assignments.
  4. Reads the policy back from Microsoft and confirms it matches exactly what was sent, and that it is
     still unassigned, before telling you it succeeded.
  5. Prints a table: Trellix rule name -> exact Defender rule name -> policy name, plus a direct link.

Rules that could NOT be mapped automatically (unsupported Trellix conditions, application-identity
rules that need a verified install path, rule groups/ordering) are listed separately as OPEN. Nothing
is guessed or silently dropped to make the numbers look better. Re-running this script is safe — it
will not create duplicate policies; it re-verifies the same one.

.PARAMETER TenantId
Your GCC High tenant GUID (Azure AD / Entra tenant ID).

.PARAMETER XmlPath
Path to your Trellix ENS Firewall XML export. Defaults to a file named exactly like the original next
to this script. It MUST be the same file this mapping was reviewed against (checked by SHA-256).

.PARAMETER PrepareOnly
Dry run. Builds everything and shows you what WOULD happen, but does not sign in or touch Microsoft
Graph. Use this first if you want to see the rule counts before authenticating.

.EXAMPLE
pwsh -NoProfile -File .\Deploy-TrellixFirewallRules.ps1 -TenantId '11111111-2222-3333-4444-555555555555'

.EXAMPLE
pwsh -NoProfile -File .\Deploy-TrellixFirewallRules.ps1 -TenantId '11111111-2222-3333-4444-555555555555' -PrepareOnly
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [string]$XmlPath = (Join-Path $PSScriptRoot 'BWD_-_Thinned_4_Export.xml'),
    [switch]$PrepareOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($TenantId -eq [guid]::Empty) { throw 'Enter your GCC High tenant GUID with -TenantId.' }
if (-not (Test-Path -LiteralPath $XmlPath)) {
    throw "Could not find the XML file at: $XmlPath`nPass the exact path with -XmlPath 'C:\path\to\your-export.xml'"
}

$toolkit = Join-Path $PSScriptRoot 'toolkit'
Import-Module (Join-Path $toolkit 'TrellixFirewall.psm1') -Force

# This is the exact SHA-256 of the XML this mapping was built and reviewed against.
# If the customer's file does not match, we stop rather than silently mapping the wrong data.
$expectedXmlHash = 'EC2584F0E229DDD266EC3FDB82F14D99C575606F0F341271F881A4553F74BD17'
$actualXmlHash = (Get-FileHash -LiteralPath $XmlPath -Algorithm SHA256).Hash
if ($actualXmlHash -cne $expectedXmlHash) {
    throw "This XML does not match the file this mapping was reviewed against.`n" +
        "Expected SHA-256: $expectedXmlHash`nActual SHA-256:   $actualXmlHash`n" +
        'Use the original export, or have this reviewed again against the new file.'
}

$workFolder = Join-Path $PSScriptRoot "work\$TenantId"
$null = New-Item -ItemType Directory -Path $workFolder -Force
$reportPath = Join-Path $workFolder 'review.json'
$approvalPath = Join-Path $workFolder 'approval.json'
$planPath = Join-Path $workFolder 'plan.json'
$receiptPath = Join-Path $workFolder 'receipt.json'
$statePath = Join-Path $workFolder 'state.json'
$schemaPath = Join-Path $workFolder 'schema.json'

function Save-Json($Value, [string]$Path) {
    $Value | ConvertTo-Json -Depth 95 | Set-Content -LiteralPath $Path -Encoding utf8
}

Write-Host "`nReading and reviewing the Trellix export..." -ForegroundColor Cyan
if (-not (Test-Path -LiteralPath $reportPath)) {
    $null = & (Join-Path $toolkit 'Convert-TrellixFirewallReview.ps1') -XmlPath $XmlPath -OutDir $workFolder
    Move-Item -LiteralPath (Join-Path $workFolder 'trellix-firewall-review.json') -Destination $reportPath -Force
}
$review = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -AsHashtable
if ($review.SourceSha256 -cne $expectedXmlHash) { throw 'The saved review does not match this XML. Delete the work folder and rerun.' }

$candidates = @($review.Rules | Where-Object {
    $_.Kind -eq 'FirewallRule' -and
    $_.MappingClass -in @('FieldMappingDraft', 'AdditionalSemanticReviewRequired') -and
    @($_.ReviewCodes | Where-Object { $_ -ne 'PreserveDisabledState' }).Count -eq 0
})
$openRules = @($review.Rules | Where-Object { $_.Kind -eq 'FirewallRule' -and $_.SourceGuid -notin $candidates.SourceGuid })
$openGroups = @($review.Rules | Where-Object { $_.Kind -ne 'FirewallRule' })

$leafRuleCount = $review.Rules.Count - $openGroups.Count
Write-Host "Mappable automatically: $($candidates.Count) of $leafRuleCount rules. Open (not mapped): $($openRules.Count) rules, $($openGroups.Count) rule groups.`n" -ForegroundColor Cyan

if (-not $PrepareOnly) {
    Write-Host 'Signing in to GCC High. Use the code/link shown below.' -ForegroundColor Yellow
    $null = Connect-TrellixGcch -TenantId $TenantId
    $null = Get-TrellixFirewallSchema -OutPath $schemaPath
} elseif (-not (Test-Path -LiteralPath $schemaPath)) {
    Copy-Item -LiteralPath (Join-Path $toolkit 'schema\gcch-firewall-schema.json') -Destination $schemaPath
}

if (Test-Path -LiteralPath $statePath) {
    $saved = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
    foreach ($entry in @(
        @{ Path = $reportPath; Hash = $saved.ReviewSha256 },
        @{ Path = $approvalPath; Hash = $saved.ApprovalSha256 },
        @{ Path = $planPath; Hash = $saved.PlanSha256 }
    )) {
        if ((Get-FileHash -LiteralPath $entry.Path).Hash -cne $entry.Hash) {
            throw 'A previously staged file changed on disk. Delete the work folder and rerun to avoid an inconsistent deployment.'
        }
    }
} else {
    $null = New-TrellixFirewallApproval -ReportPath $reportPath -OutPath $approvalPath
    $approval = Get-Content -LiteralPath $approvalPath -Raw | ConvertFrom-Json -AsHashtable
    $approval.TargetTenantId = $TenantId.ToString()
    $approval.PolicyNamePrefix = 'Trellix Migration - Mapped Disabled'
    $approval.Profiles = @('All')
    $approval.InterfaceTypes = @('All')
    $approval.ApprovedRuleIds = @($candidates.SourceGuid)
    foreach ($key in @($approval.Acknowledgements.Keys)) { $approval.Acknowledgements[$key] = $true }
    Save-Json $approval $approvalPath
    $null = New-TrellixFirewallPlan -ReportPath $reportPath -ApprovalPath $approvalPath -SchemaPath $schemaPath -OutPath $planPath -StageDisabled
    Save-Json @{
        SourceSha256 = $expectedXmlHash; ReviewSha256 = (Get-FileHash -LiteralPath $reportPath).Hash
        ApprovalSha256 = (Get-FileHash -LiteralPath $approvalPath).Hash
        PlanSha256 = (Get-FileHash -LiteralPath $planPath).Hash
    } $statePath
}

$plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json -AsHashtable
if ($plan.StagingMode -ne 'DisabledUnassigned' -or -not $plan.UnassignedOnly -or $plan.TargetTenantId -ne $TenantId.ToString() -or
    @($plan.Rules | Where-Object { $_.Enabled -isnot [bool] -or $_.Enabled }).Count) {
    throw 'Refusing to continue: the plan is not disabled/unassigned and tenant-bound as required.'
}

$verified = @()
if (-not $PrepareOnly) {
    Write-Host "`nPublishing to Microsoft Graph (GCC High)..." -ForegroundColor Cyan
    $null = Publish-TrellixFirewallPlan -PlanPath $planPath -ReceiptPath $receiptPath -Confirm:$false
    Write-Host 'Reading the policy back from Microsoft to confirm it matches and is still unassigned...' -ForegroundColor Cyan
    $verified = @(Test-TrellixFirewallPolicies -PlanPath $planPath -ReceiptPath $receiptPath)
    if ($verified.Count -ne $plan.Policies.Count -or @($verified | Where-Object {
        -not $_.SettingsMatch -or $_.AssignmentCount -ne 0 -or $_.IsAssigned
    }).Count) { throw 'Verification failed after publishing. Do not assume the deployment succeeded.' }
}
Disconnect-TrellixGcch

# Build the source-rule -> native-rule name table for display.
$rulePolicies = @{}
$firstPolicyName = ''
$firstPolicyLink = ''
$offset = 0
foreach ($policy in $plan.Policies) {
    $cloud = @($verified | Where-Object Name -ceq $policy.Name)
    $policyId = if ($cloud.Count -eq 1) { $cloud[0].PolicyId } else { '(not published — PrepareOnly run)' }
    $policyUrl = if ($cloud.Count -eq 1) { "https://security.microsoft.us/policy-inventory/$($cloud[0].PolicyId)?implementationType=DcV2&viewid=settingsValues&tid=$TenantId" } else { '' }
    if ($offset -eq 0) { $firstPolicyName = $policy.Name; $firstPolicyLink = $policyUrl }
    foreach ($rule in @($plan.Rules)[$offset..($offset + $policy.RuleCount - 1)]) {
        $rulePolicies[$rule.Name] = [pscustomobject]@{
            TrellixRule = $rule.SourceName; DefenderRule = $rule.Name
            Policy = $policy.Name; PolicyId = $policyId; PolicyLink = $policyUrl
        }
    }
    $offset += $policy.RuleCount
}

Write-Host "`n================  MAPPED AND DEPLOYED (disabled, unassigned)  ================" -ForegroundColor Green
$rulePolicies.Values | Sort-Object TrellixRule | Format-Table TrellixRule, DefenderRule, Policy -AutoSize

if ($verified.Count) {
    Write-Host "Policy link: $firstPolicyLink`n" -ForegroundColor Green
}

Write-Host "================  OPEN — not mapped (no change made for these)  ================" -ForegroundColor Yellow
@($openRules + $openGroups) | Sort-Object Name | ForEach-Object {
    $why = if ($_.Kind -ne 'FirewallRule') { 'Rule group / ordering container — no native Defender equivalent' }
        else { ($_.ReviewCodes -join ', ') }
    [pscustomobject]@{ TrellixRule = $_.Name; Reason = $why }
} | Format-Table TrellixRule, Reason -AutoSize

Write-Host "SUMMARY: $($candidates.Count) Trellix rules mapped to $($plan.Rules.Count) Defender rules in 1 policy (disabled, 0 assignments). $($openRules.Count) rules and $($openGroups.Count) groups left OPEN for manual/alternative handling.`n" -ForegroundColor Cyan

if ($PrepareOnly) {
    Write-Host "This was a DRY RUN (-PrepareOnly). Nothing was signed in or published. Rerun without -PrepareOnly to deploy." -ForegroundColor Yellow
}

# ---- Build a human-friendly Results.html the customer can open and send around ----
function ConvertTo-HtmlText([string]$Value) { [Net.WebUtility]::HtmlEncode($Value) }

$mappedHtmlRows = [Text.StringBuilder]::new()
foreach ($row in ($rulePolicies.Values | Sort-Object TrellixRule)) {
    $linkCell = if ($row.PolicyLink) {
        '<a target="_blank" rel="noopener noreferrer" href="' + (ConvertTo-HtmlText $row.PolicyLink) + '">' + (ConvertTo-HtmlText $row.Policy) + '</a>'
    } else { ConvertTo-HtmlText $row.Policy }
    $null = $mappedHtmlRows.Append('<tr><td>' + (ConvertTo-HtmlText $row.TrellixRule) + '</td><td><code>' +
        (ConvertTo-HtmlText $row.DefenderRule) + '</code></td><td>' + $linkCell + '</td></tr>')
}

$openHtmlRows = [Text.StringBuilder]::new()
foreach ($item in (@($openRules + $openGroups) | Sort-Object Name)) {
    $why = if ($item.Kind -ne 'FirewallRule') { 'Rule group / ordering container — no native Defender equivalent' }
        else { ($item.ReviewCodes -join ', ') }
    $null = $openHtmlRows.Append('<tr><td>' + (ConvertTo-HtmlText $item.Name) + '</td><td>' + (ConvertTo-HtmlText $why) + '</td></tr>')
}

$modeLabel = if ($PrepareOnly) { 'DRY RUN — nothing was published' } else { 'PUBLISHED — disabled, unassigned' }

$resultsTemplate = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Results-template.html') -Raw
$resultsHtml = $resultsTemplate.
    Replace('{{TENANT}}', (ConvertTo-HtmlText $TenantId)).
    Replace('{{TIME}}', (ConvertTo-HtmlText ([DateTimeOffset]::Now.ToString('f')))).
    Replace('{{MODE}}', (ConvertTo-HtmlText $modeLabel)).
    Replace('{{MAPPED_COUNT}}', [string]$candidates.Count).
    Replace('{{NATIVE_COUNT}}', [string]$plan.Rules.Count).
    Replace('{{OPEN_COUNT}}', [string]$openRules.Count).
    Replace('{{GROUP_COUNT}}', [string]$openGroups.Count).
    Replace('{{POLICY_NAME}}', (ConvertTo-HtmlText $firstPolicyName)).
    Replace('{{POLICY_LINK}}', (ConvertTo-HtmlText $firstPolicyLink)).
    Replace('{{MAPPED_ROWS}}', $mappedHtmlRows.ToString()).
    Replace('{{OPEN_ROWS}}', $openHtmlRows.ToString())

$resultsPath = Join-Path $PSScriptRoot "Results-$TenantId.html"
Set-Content -LiteralPath $resultsPath -Value $resultsHtml -Encoding utf8
Write-Host "A formatted report was saved to: $resultsPath" -ForegroundColor Cyan
Write-Host "Open it in any web browser to see the mapped/open rules and policy link.`n" -ForegroundColor Cyan
