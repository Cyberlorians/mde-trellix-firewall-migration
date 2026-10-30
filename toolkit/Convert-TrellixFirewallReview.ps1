<#
.SYNOPSIS
Creates an offline Defender Firewall mapping review from a Trellix ENS Firewall XML export.
.DESCRIPTION
Preserves source rule order and conditions and identifies Defender XDR policy destinations.
Does not create deployable policies, contact
Microsoft Graph, resolve DNS names, change the firewall, or assign policies.
.PARAMETER XmlPath
Local ePO XML export containing ENS Firewall rules, rule lists and aggregate conditions.
.PARAMETER OutDir
Local output directory for trellix-firewall-review.json.
.EXAMPLE
.\Convert-TrellixFirewallReview.ps1 -XmlPath 'C:\exports\TrellixFirewall.xml' -OutDir '.\review'
.NOTES
All mappings remain review-only. This is a separate firewall preprocessing stage, not
an input to the AV-exclusion publisher. Source audit usernames, timestamps and notes
are omitted from the normalized operational settings.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$XmlPath,
    [Parameter(Mandatory)]
    [string]$OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Setting {
    param([hashtable]$Settings, [string]$Name)
    if ($Settings.ContainsKey($Name)) { return $Settings[$Name] }
    return $null
}

function Get-RequiredSetting {
    param([hashtable]$Settings, [string]$Name)
    if (-not $Settings.ContainsKey($Name)) { throw "Required setting is missing: $Name" }
    return $Settings[$Name]
}

function Get-IndexedSettings {
    param([hashtable]$Settings, [string]$Name)
    $pattern = '^\+' + [regex]::Escape($Name) + '#(\d+)$'
    $entries = @(
        foreach ($key in $Settings.Keys) {
            if ($key -match $pattern) {
                [pscustomobject]@{ Index = [int]$Matches[1]; Value = $Settings[$key] }
            }
        }
    ) | Sort-Object Index
    for ($i = 0; $i -lt @($entries).Count; $i++) {
        if ($entries[$i].Index -ne $i) { throw "Noncontiguous indexed settings: $Name" }
    }
    if ($Settings.ContainsKey("_$Name") -and [int]$Settings["_$Name"] -ne @($entries).Count) {
        throw "Indexed setting count does not match _$Name."
    }
    foreach ($entry in $entries) { $entry.Value }
}

function Convert-Address {
    param([string]$Value)
    $result = [ordered]@{ Source = $Value; Kind = 'Unrecognized'; Candidate = $null; ReviewCode = $null }
    if ($Value -eq '[trusted]') {
        $result.Kind = 'VendorNetworkToken'
        $result.ReviewCode = 'TrustedNetworkDefinitionRequired'
        return [pscustomobject]$result
    }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Value, [ref]$ip)) {
        $result.Kind = 'IPAddress'
        $result.Candidate = if ($ip.IsIPv4MappedToIPv6) { $ip.MapToIPv4().ToString() } else { $ip.ToString() }
        if ($result.Candidate -in @('::', '0.0.0.0')) {
            $result.ReviewCode = 'UnspecifiedAddressSemanticsRequireReview'
        }
        return [pscustomobject]$result
    }
    if ($Value -match '^(.+)/(\d+)$') {
        $address = $Matches[1]
        $prefix = [int]$Matches[2]
        if ([System.Net.IPAddress]::TryParse($address, [ref]$ip)) {
            $maximum = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
            if ($prefix -gt $maximum) { throw "Invalid address prefix: $Value" }
            $result.Kind = 'CIDR'
            if ($ip.IsIPv4MappedToIPv6) {
                if ($prefix -lt 96) {
                    $result.ReviewCode = 'MappedPrefixCannotBecomeIPv4CIDR'
                }
                else {
                    $result.Candidate = '{0}/{1}' -f $ip.MapToIPv4(), ($prefix - 96)
                }
            }
            else { $result.Candidate = '{0}/{1}' -f $ip, $prefix }
            return [pscustomobject]$result
        }
    }
    $parts = $Value -split '-', 2
    $first = $null
    $last = $null
    if ($parts.Count -eq 2 -and
        [System.Net.IPAddress]::TryParse($parts[0], [ref]$first) -and
        [System.Net.IPAddress]::TryParse($parts[1], [ref]$last)) {
        if ($first.IsIPv4MappedToIPv6) { $first = $first.MapToIPv4() }
        if ($last.IsIPv4MappedToIPv6) { $last = $last.MapToIPv4() }
        if ($first.AddressFamily -ne $last.AddressFamily) { throw "Mixed-family address range: $Value" }
        $firstBytes = $first.GetAddressBytes()
        $lastBytes = $last.GetAddressBytes()
        for ($i = 0; $i -lt $firstBytes.Length; $i++) {
            if ($firstBytes[$i] -gt $lastBytes[$i]) { throw "Reversed address range: $Value" }
            if ($firstBytes[$i] -lt $lastBytes[$i]) { break }
        }
        $result.Kind = 'IPRange'
        $result.Candidate = '{0}-{1}' -f $first, $last
    }
    elseif ([System.Uri]::CheckHostName($Value) -eq [System.UriHostNameType]::Dns) {
        $result.Kind = 'DNSName'
        $result.ReviewCode = 'FqdnMechanismAndDevicePrerequisitesRequired'
    }
    else { $result.ReviewCode = 'UnrecognizedAddressSyntax' }
    return [pscustomobject]$result
}

function Convert-Ports {
    param([string[]]$Values)
    foreach ($value in $Values) {
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        foreach ($part in ($value -split ',')) {
            $token = $part.Trim()
            if ($token -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') { throw "Unrecognized port expression: $token" }
            $first = [int]$Matches[1]
            $last = if ($Matches.ContainsKey(2) -and $Matches[2]) { [int]$Matches[2] } else { $first }
            if ($first -gt 65535 -or $last -gt 65535 -or $first -gt $last) { throw "Invalid port expression: $token" }
            $token
        }
    }
}

function Get-OperationalSettings {
    param([hashtable]$Settings)
    $copy = [ordered]@{}
    foreach ($key in ($Settings.Keys | Sort-Object)) {
        if ($key -match '(?i)LastModified|LastModifyingUsername|Note') { continue }
        $copy[$key] = $Settings[$key]
    }
    return $copy
}

$source = Get-Item -LiteralPath $XmlPath
$readerSettings = [System.Xml.XmlReaderSettings]::new()
$readerSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
$readerSettings.XmlResolver = $null
$readerSettings.MaxCharactersInDocument = 20000000
$reader = [System.Xml.XmlReader]::Create($source.FullName, $readerSettings)
$document = [System.Xml.XmlDocument]::new()
$document.XmlResolver = $null
try { $document.Load($reader) } finally { $reader.Dispose() }
if ($document.DocumentElement.LocalName -ne 'EPOPolicySchema') { throw 'Expected an ePO policy export.' }

$objects = @(
    foreach ($node in $document.SelectNodes('/*/EPOPolicySettings')) {
        if ($node.GetAttribute('featureid') -ne 'ENDP_FW_META_FW' -or
            $node.GetAttribute('categoryid') -ne 'FireCore_FW_Rules') {
            throw 'This reviewer accepts only Trellix ENS Firewall rule exports.'
        }
        if ($node.GetAttribute('param_str') -notin @('100', '101', 'AggregateCriterion')) {
            throw "Unsupported policy settings type: $($node.GetAttribute('param_str'))"
        }
        $sections = @($node.SelectNodes('./Section'))
        if ($sections.Count -ne 1) { throw 'Expected exactly one Section per settings object.' }
        $map = @{}
        foreach ($setting in $node.SelectNodes('./Section/Setting')) {
            if (-not $setting.HasAttribute('name') -or -not $setting.HasAttribute('value')) {
                throw 'Each Setting must have name and value attributes.'
            }
            $name = $setting.GetAttribute('name')
            if ($map.ContainsKey($name)) { throw "Duplicate setting name: $name" }
            $map[$name] = $setting.GetAttribute('value')
        }
        [pscustomobject]@{ ObjectName = $node.GetAttribute('name'); Type = $node.GetAttribute('param_str'); Settings = $map }
    }
)
$policyNodes = @($document.SelectNodes('/*/EPOPolicyObject'))
if ($policyNodes.Count -ne 1) { throw 'Expected exactly one policy object.' }
$policy = $policyNodes[0]
$referencedObjects = @($policy.SelectNodes('./PolicySettings') | ForEach-Object { $_.InnerText })
if ($referencedObjects.Count -ne $objects.Count -or
    @(Compare-Object ($objects.ObjectName | Sort-Object -Unique) ($referencedObjects | Sort-Object -Unique)).Count -gt 0) {
    throw 'Policy settings object references do not match the exported objects.'
}

$ruleMap = @{}
$aggregateMap = @{}
$listMap = @{}
foreach ($object in $objects) {
    switch ($object.Type) {
        '101' {
            $id = Get-RequiredSetting $object.Settings 'GUID'
            if ($ruleMap.ContainsKey($id)) { throw "Duplicate rule GUID: $id" }
            foreach ($field in @('Name', 'Action', 'Direction', 'Enabled')) {
                $null = Get-RequiredSetting $object.Settings $field
            }
            if ($object.Settings.Enabled -notin @('0', '1')) { throw "Invalid Enabled value for $id" }
            $ruleMap[$id] = $object
        }
        'AggregateCriterion' {
            $id = Get-RequiredSetting $object.Settings 'GUID'
            if ($aggregateMap.ContainsKey($id)) { throw "Duplicate aggregate GUID: $id" }
            $aggregateMap[$id] = $object
        }
        '100' {
            $id = Get-Setting $object.Settings 'RuleListID'
            if ([string]::IsNullOrEmpty($id)) { $id = 'ROOT' }
            if ($listMap.ContainsKey($id)) { throw "Duplicate rule list ID: $id" }
            $listMap[$id] = $object
        }
    }
}
if (-not $listMap.ContainsKey('ROOT')) { throw 'The root rule list is missing.' }
$orderedRules = [System.Collections.Generic.List[object]]::new()
$seenRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$seenLists = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
function Visit-RuleList {
    param([string]$ListId, [string[]]$ParentGroups, [bool]$ParentEnabled)
    if (-not $listMap.ContainsKey($ListId)) { throw "Missing rule list: $ListId" }
    if (-not $seenLists.Add($ListId)) { throw "Repeated or cyclic rule list: $ListId" }
    $index = 0
    foreach ($id in @(Get-IndexedSettings $listMap[$ListId].Settings 'RuleIDSequence')) {
        if (-not $ruleMap.ContainsKey($id)) { throw "Unresolved rule reference: $id" }
        if (-not $seenRules.Add($id)) { throw "Repeated rule reference: $id" }
        $rule = $ruleMap[$id]
        $enabled = $ParentEnabled -and ($rule.Settings.Enabled -eq '1')
        $orderedRules.Add([pscustomobject]@{
            Rule = $rule; ListId = $ListId; Index = $index; ParentGroups = @($ParentGroups); EffectiveEnabled = $enabled
        })
        if ($rule.Settings.Action -eq 'JUMP') {
            Visit-RuleList $id @($ParentGroups + $rule.Settings.Name) $enabled
        }
        $index++
    }
}
Visit-RuleList 'ROOT' @() $true
if ($seenRules.Count -ne $ruleMap.Count -or $seenLists.Count -ne $listMap.Count) {
    throw 'Some exported rules or rule lists are unreachable from the root policy.'
}

$aggregates = @(
    foreach ($id in ($aggregateMap.Keys | Sort-Object)) {
        $map = $aggregateMap[$id].Settings
        $paths = @(Get-IndexedSettings $map 'AppPath')
        $hashes = @(Get-IndexedSettings $map 'AppHash')
        $signers = @(Get-IndexedSettings $map 'AppSigner')
        $descriptions = @(Get-IndexedSettings $map 'AppDescription')
        $codes = @()
        if (@($paths | Where-Object { $_ -match '[*?]' }).Count) { $codes += 'ApplicationWildcardNeedsExactPaths' }
        if ($paths -contains '<System>') { $codes += 'VendorSystemApplicationTokenRequiresReview' }
        if ($paths -contains '') { $codes += 'EmptyApplicationPathRequiresReview' }
        if (@($hashes | Where-Object { $_ -and $_ -notmatch '^0+$' }).Count) { $codes += 'ApplicationHashConditionRequiresDesign' }
        if (@($signers | Where-Object { $_ }).Count) { $codes += 'ApplicationSignerConditionRequiresDesign' }
        if (@($descriptions | Where-Object { $_ }).Count) { $codes += 'ApplicationDescriptionConditionRequiresReview' }
        $local = @(Get-IndexedSettings $map 'LocalAddress' | ForEach-Object { Convert-Address $_ })
        $remote = @(Get-IndexedSettings $map 'RemoteAddress' | ForEach-Object { Convert-Address $_ })
        $codes += @(@($local) + @($remote) | Where-Object ReviewCode | ForEach-Object ReviewCode)
        if ((Get-RequiredSetting $map 'Type') -notin @('65541', '65546', '65547')) { $codes += 'UnknownAggregateType' }
        [pscustomobject]@{
            Id = $id; Type = $map.Type; ApplicationPaths = $paths; LocalAddresses = $local; RemoteAddresses = $remote
            ReviewCodes = @($codes | Sort-Object -Unique); SourceSettings = Get-OperationalSettings $map
        }
    }
)
$normalizedAggregates = @{}
foreach ($aggregate in $aggregates) { $normalizedAggregates[$aggregate.Id] = $aggregate }
$usedAggregates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$records = @(
    foreach ($entry in $orderedRules) {
        $map = $entry.Rule.Settings
        $codes = @()
        $refs = @(Get-IndexedSettings $map 'AggRef')
        $conditions = @(
            foreach ($id in $refs) {
                if (-not $normalizedAggregates.ContainsKey($id)) { throw "Unresolved aggregate reference: $id" }
                $null = $usedAggregates.Add($id)
                $normalizedAggregates[$id]
            }
        )
        $codes += @($conditions | ForEach-Object ReviewCodes)
        if ($refs.Count -gt 1) { $codes += 'CompoundAggregateBooleanSemanticsRequireReview' }
        $directions = switch ($map.Direction) {
            'IN' { 'Inbound' }
            'OUT' { 'Outbound' }
            'EITHER' { 'Inbound'; 'Outbound' }
            default { throw "Unknown source direction: $($map.Direction)" }
        }
        $action = switch ($map.Action) {
            'ALLOW' { 'Allow' }
            'BLOCK' { 'Block' }
            'JUMP' { $null }
            default { throw "Unknown source action: $($map.Action)" }
        }
        $etherTypes = @(Get-IndexedSettings $map 'NetworkProtocol')
        $layer2 = @($etherTypes | Where-Object { $_ -notin @('2048', '34525') })
        if ($layer2.Count) { $codes += 'NonIpEtherTypeHasNoStandardFirewallRuleEquivalent' }
        if (-not $etherTypes.Count -and $map.Action -ne 'JUMP') { $codes += 'UnspecifiedEtherTypeRequiresScopeReview' }
        $protocols = @(Get-IndexedSettings $map 'TransportProtocol')
        foreach ($protocol in $protocols) {
            $number = 0
            if (-not [int]::TryParse($protocol, [ref]$number) -or $number -lt 0 -or $number -gt 255) {
                throw "Invalid transport protocol: $protocol"
            }
        }
        foreach ($field in @('Invert', 'Intrusion', 'ScheduleEnabled', 'ScheduleDisableDuringTime', 'WeekMask', 'ClickTimeout')) {
            $value = Get-Setting $map $field
            if ($null -ne $value -and $value -ne '0') { $codes += "Vendor${field}SemanticsRequireReview" }
        }
        foreach ($flag in @(Get-IndexedSettings $map 'TcpFlags')) {
            if ($flag -ne '0') { $codes += 'TcpFlagMatchingRequiresDesign' }
        }
        if ((Get-Setting $map 'OffHours') -notin @($null, 'NONE')) { $codes += 'OffHoursScheduleRequiresDesign' }
        if ((Get-Setting $map 'Logged') -eq '1') { $codes += 'PerRuleLoggingRequiresReview' }
        if ((Get-Setting $map 'ViewOnly') -eq '1') { $codes += 'VendorReadOnlyRuleRequiresReview' }
        if (@(Get-IndexedSettings $map 'MessageType').Count) { $codes += 'IcmpMessageTypeSemanticsRequireReview' }
        if (-not $entry.EffectiveEnabled) { $codes += 'PreserveDisabledState' }
        $localPorts = @(Convert-Ports @(Get-IndexedSettings $map 'LocalPort'))
        $remotePorts = @(Convert-Ports @(Get-IndexedSettings $map 'RemotePort'))
        $kind = if ($map.Action -eq 'JUMP') { 'GroupContainer' } else { 'FirewallRule' }
        $classification = if ($kind -eq 'GroupContainer') { 'GroupContainer' }
            elseif ($layer2.Count) { 'UnsupportedLayer2' }
            elseif ($codes -contains 'ApplicationWildcardNeedsExactPaths') { 'ApplicationResolutionRequired' }
            elseif ($codes.Count) { 'AdditionalSemanticReviewRequired' }
            else { 'FieldMappingDraft' }
        $groupConstraints = @($codes | Where-Object {
            $_ -notin @('VendorReadOnlyRuleRequiresReview', 'PreserveDisabledState', 'PerRuleLoggingRequiresReview')
        })
        if ($kind -eq 'GroupContainer' -and ($refs.Count -or $map.Direction -ne 'EITHER' -or
            $etherTypes.Count -or $protocols.Count -or $localPorts.Count -or $remotePorts.Count -or $groupConstraints.Count)) {
            throw "Constrained JUMP group needs an inheritance-aware converter: $($map.Name)"
        }
        [pscustomobject]@{
            SourceGuid = $map.GUID; Name = $map.Name; Kind = $kind
            SourceListId = $entry.ListId; SourceListIndex = $entry.Index; ParentGroups = @($entry.ParentGroups)
            SourceEnabled = ($map.Enabled -eq '1'); EffectiveEnabled = $entry.EffectiveEnabled
            SourceAction = $map.Action; SourceDirection = $map.Direction; AggregateReferences = $refs
            MappingClass = $classification; DeploymentReady = $false
            XdrDestination = [ordered]@{
                Portal = 'https://security.microsoft.us/policy-inventory'
                Area = 'Endpoint security policies'
                Platform = if ($kind -eq 'GroupContainer' -or $layer2.Count) { $null } else { 'Windows' }
                Template = if ($kind -eq 'GroupContainer' -or $layer2.Count) { $null } else { 'Microsoft Defender Firewall Rules' }
                Disposition = if ($kind -eq 'GroupContainer') { 'OrganizationAndOrderingReviewOnly' }
                    elseif ($layer2.Count) { 'NoDirectStandardDefenderFirewallRuleEquivalent' }
                    else { 'FirewallRuleDraftPendingScopeAndSemanticReview' }
            }
            ReviewCodes = @($codes | Sort-Object -Unique)
            FieldMapping = if ($kind -eq 'GroupContainer') { $null } else {
                [ordered]@{
                    Action = $action; Directions = @($directions); TransportProtocolNumbers = $protocols
                    LocalPorts = $localPorts; RemotePorts = $remotePorts; SourceEtherTypes = $etherTypes
                    Profiles = $null; ApplicationSetSelectors = @(Get-IndexedSettings $map 'AppExeSet')
                    ResolvedConditions = $conditions
                }
            }
            SourceSettings = Get-OperationalSettings $map
        }
    }
)
$leaf = @($records | Where-Object Kind -eq 'FirewallRule')
$summary = [ordered]@{
    SourceObjects = $objects.Count; RuleRecords = $records.Count; LeafRules = $leaf.Count
    GroupContainers = @($records | Where-Object Kind -eq 'GroupContainer').Count
    RuleLists = $listMap.Count; AggregateDefinitions = $aggregates.Count
    ApplicationDefinitions = @($aggregates | Where-Object Type -eq '65547').Count
    WildcardApplicationDefinitions = @($aggregates | Where-Object { $_.ReviewCodes -contains 'ApplicationWildcardNeedsExactPaths' }).Count
    AllowRules = @($leaf | Where-Object SourceAction -eq 'ALLOW').Count
    BlockRules = @($leaf | Where-Object SourceAction -eq 'BLOCK').Count
    DisabledLeafRules = @($leaf | Where-Object { -not $_.EffectiveEnabled }).Count
    NonIpLeafRules = @($leaf | Where-Object MappingClass -eq 'UnsupportedLayer2').Count
    XdrFirewallRuleCandidates = @($leaf | Where-Object { $_.XdrDestination.Template -eq 'Microsoft Defender Firewall Rules' }).Count
    EnabledIpLeafDirectionDrafts = @($leaf | Where-Object { $_.EffectiveEnabled -and $_.MappingClass -ne 'UnsupportedLayer2' } | ForEach-Object { $_.FieldMapping.Directions }).Count
    DeploymentReadyRules = 0
    UnreferencedAggregateDefinitions = @($aggregates | Where-Object { -not $usedAggregates.Contains($_.Id) }).Count
    MappingClasses = @($records | Group-Object MappingClass | ForEach-Object { [pscustomobject]@{ Class = $_.Name; Count = $_.Count } })
    ReviewCodeCounts = @($leaf | ForEach-Object ReviewCodes | Group-Object | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Code = $_.Name; Count = $_.Count } })
}
$report = [ordered]@{
    SchemaVersion = 1; Purpose = 'Offline review only. Not a deployable policy or an assertion of behavioral equivalence.'
    SourceFileName = $source.Name; SourceSha256 = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash
    PolicyName = $policy.GetAttribute('name'); SourceProduct = 'Trellix ENS Firewall'; Target = 'Microsoft Defender Firewall'
    XdrLandingGuide = [ordered]@{
        Portal = 'https://security.microsoft.us/policy-inventory'
        Navigation = 'Endpoints > Configuration management > Endpoint security policies'
        Platform = 'Windows'
        RuleTemplate = 'Microsoft Defender Firewall Rules'
        BaselineTemplate = 'Microsoft Defender Firewall'
        BaselineCaution = 'Profile enablement, default inbound/outbound actions, policy merging and profile-level logging require a separate baseline review; do not infer them from this rules-only export.'
        NotEquivalentDestinations = @('Antivirus exclusions', 'Attack Surface Reduction rules', 'IP/domain indicators', 'Custom detection rules')
        FieldDestinations = @(
            [ordered]@{ Source = 'Name'; Target = 'Firewall rule name'; Conversion = 'Preserve the source name and GUID provenance.' }
            [ordered]@{ Source = 'Action ALLOW / BLOCK'; Target = 'Rule action'; Conversion = 'Allow / Block; separately assess Windows block precedence.' }
            [ordered]@{ Source = 'Direction IN / OUT / EITHER'; Target = 'Rule direction'; Conversion = 'Inbound / Outbound / separate inbound and outbound drafts.' }
            [ordered]@{ Source = 'Enabled'; Target = 'Rule enabled state'; Conversion = 'Preserve effective enabled state, including disabled ancestors. Never re-enable disabled source rules.' }
            [ordered]@{ Source = '+TransportProtocol'; Target = 'IP protocol'; Conversion = 'Use the transport/IP protocol number: 6=TCP, 17=UDP, 1=ICMPv4, 2=IGMP, 58=ICMPv6.' }
            [ordered]@{ Source = '+NetworkProtocol'; Target = 'IP-family scope review, not the IP protocol field'; Conversion = '2048 and 34525 are IPv4/IPv6 EtherTypes. Other Ethernet types cannot be copied to the standard rule template.' }
            [ordered]@{ Source = '+LocalPort / +RemotePort'; Target = 'Local / remote port ranges'; Conversion = 'Preserve source endpoints and ranges; split comma-separated lists without swapping local and remote for outbound rules.' }
            [ordered]@{ Source = '+AppPath through +AggRef'; Target = 'Application file path or other supported application identity'; Conversion = 'Resolve wildcard paths and vendor tokens; preserve signer/hash/description restrictions for design review.' }
            [ordered]@{ Source = '+LocalAddress / +RemoteAddress through +AggRef'; Target = 'Local / remote address ranges'; Conversion = 'Normalize mapped IPv4 addresses and prefixes; retain FQDN and trusted-network blockers instead of widening scope.' }
            [ordered]@{ Source = 'FQDN address conditions'; Target = 'Supported firewall FQDN/dynamic-keyword mechanism'; Conversion = 'Verify device and management-channel support. Do not substitute Defender IP/domain indicators.' }
            [ordered]@{ Source = 'Logged'; Target = 'Separate Firewall baseline profile logging and monitoring review'; Conversion = 'Profile logging is not a one-to-one replacement for per-rule logging.' }
            [ordered]@{ Source = 'JUMP / RuleIDSequence'; Target = 'Policy organization and precedence review only'; Conversion = 'Retain source groups and numeric order for analysis; there is no direct JUMP or administrator-assigned priority equivalent.' }
            [ordered]@{ Source = 'Firewall profiles, interfaces and default actions'; Target = 'Firewall rules scope plus separate Firewall baseline'; Conversion = 'Obtain and approve the missing scope/defaults. This export cannot determine them.' }
        )
    }
    GlobalReviewRequirements = @(
        'Review every draft before policy creation; all DeploymentReady values are deliberately false.'
        'Windows Firewall explicit blocks override conflicting allows and does not preserve administrator-assigned rule order.'
        'Source numeric ordering and JUMP ancestry are retained for analysis, not translated into Windows precedence.'
        'Confirm firewall profile scope, interface scope, defaults, trusted-network definitions and policy merging outside this rule export.'
        'Do not replace unresolved applications, addresses, tokens or conditions with Any.'
        'Confirm wildcard expansion, application-set Boolean logic, vendor sentinel values and IPv4/IPv6 scope before conversion.'
        'FQDNs are not resolved; a supported dynamic-keyword design and device prerequisites require review.'
        'Confirm the target management channel and sovereign-cloud firewall template availability before building Graph payloads.'
        'The documented Intune Windows Firewall rules profile limit is 150 rules; split after review and any direction/application expansion.'
    )
    References = @(
        'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/rules'
        'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords'
        'https://learn.microsoft.com/intune/device-configuration/endpoint-security/firewall'
    )
    Summary = $summary; Rules = $records; AggregateDefinitions = $aggregates
}
$null = New-Item -ItemType Directory -Path $OutDir -Force
$reportPath = Join-Path $OutDir 'trellix-firewall-review.json'
$report | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $reportPath -Encoding utf8
[pscustomobject]@{ Report = $reportPath; Summary = [pscustomobject]$summary }
