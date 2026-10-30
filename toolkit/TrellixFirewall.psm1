#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:GraphContext = $null
$script:GraphBase = 'https://graph.microsoft.us/beta'

function Connect-TrellixGcch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$TenantId,
        [guid]$ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e',
        [scriptblock]$DeviceCodeHandler
    )
    $script:GraphContext = $null
    $authority = "https://login.microsoftonline.us/$TenantId/oauth2/v2.0"
    $device = Invoke-RestMethod -Method Post -Uri "$authority/devicecode" -Body @{
        client_id = $ClientId.ToString()
        scope = 'https://graph.microsoft.us/DeviceManagementConfiguration.ReadWrite.All'
    }
    if ($DeviceCodeHandler) {
        & $DeviceCodeHandler ([pscustomobject]@{
            UserCode = $device.user_code
            VerificationUri = $device.verification_uri
            ExpiresAt = [DateTimeOffset]::UtcNow.AddSeconds([int]$device.expires_in).ToString('o')
        })
    } else { Write-Host $device.message }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds([int]$device.expires_in)
    $interval = [int]$device.interval
    $token = $null
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $token = Invoke-RestMethod -Method Post -Uri "$authority/token" -Body @{
                grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id = $ClientId.ToString()
                device_code = $device.device_code
            }
            break
        }
        catch {
            if (-not $_.ErrorDetails.Message) { throw }
            $oauthError = $_.ErrorDetails.Message | ConvertFrom-Json -AsHashtable
            switch ($oauthError.error) {
                'authorization_pending' { continue }
                'slow_down' { $interval += 5; continue }
                default { throw "GCCH authentication failed: $($oauthError.error): $($oauthError.error_description)" }
            }
        }
    }
    if ($null -eq $token) { throw 'GCCH device authentication expired without approval.' }
    $parts = $token.access_token.Split('.')
    if ($parts.Count -ne 3) { throw 'The returned token cannot be checked for the expected tenant.' }
    $encoded = $parts[1].Replace('-', '+').Replace('_', '/')
    $encoded = $encoded.PadRight($encoded.Length + (4 - $encoded.Length % 4) % 4, '=')
    $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json -AsHashtable
    if ($claims.tid -ne $TenantId.ToString()) { throw 'Authentication returned a different tenant than requested.' }
    $script:GraphContext = @{
        TenantId = $TenantId.ToString()
        ClientId = $ClientId.ToString()
        Token = ConvertTo-SecureString -String $token.access_token -AsPlainText -Force
        ExpiresAt = [DateTimeOffset]::UtcNow.AddSeconds([int]$token.expires_in)
    }
    $token = $null
    [pscustomobject]@{
        TenantId = $script:GraphContext.TenantId
        Environment = 'USGov / GCC High'
        ExpiresAt = $script:GraphContext.ExpiresAt
    }
}

function Disconnect-TrellixGcch {
    $script:GraphContext = $null
}

function Assert-TrellixGraphContext {
    param([string]$ExpectedTenantId)
    if ($null -eq $script:GraphContext) { throw 'Run Connect-TrellixGcch in this PowerShell session first.' }
    if ($script:GraphContext.ExpiresAt -le [DateTimeOffset]::UtcNow.AddMinutes(2)) {
        throw 'The GCCH access token is expired or about to expire. Reconnect before continuing.'
    }
    if ($ExpectedTenantId -and $script:GraphContext.TenantId -ne $ExpectedTenantId) {
        throw 'The authenticated tenant does not match the approved target tenant.'
    }
}

function Invoke-TrellixGraph {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Body
    )
    Assert-TrellixGraphContext
    $uri = if ($Path.StartsWith('/deviceManagement/')) { "$script:GraphBase$Path" } else { $Path }
    $parsed = [uri]$uri
    if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'graph.microsoft.us' -or
        -not $parsed.IsDefaultPort -or $parsed.UserInfo -or $parsed.Fragment -or
        $parsed.AbsolutePath -notlike '/beta/deviceManagement/*') {
        throw "Refusing a Graph request outside the GCCH device-management API: $uri"
    }
    if (($Method -eq 'POST' -and $parsed.AbsolutePath -cne '/beta/deviceManagement/configurationPolicies') -or
        ($Method -eq 'DELETE' -and $parsed.AbsolutePath -notmatch '^/beta/deviceManagement/configurationPolicies/[a-fA-F0-9-]{36}$')) {
        throw 'Graph writes are restricted to policy creation and exact-ID deletion. Assignments are not supported.'
    }
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        try {
            $parameters = @{
                Method = $Method; Uri = $uri; Authentication = 'Bearer'; Token = $script:GraphContext.Token
            }
            if ($PSBoundParameters.ContainsKey('Body')) {
                $parameters.Body = $Body | ConvertTo-Json -Depth 80 -Compress
                $parameters.ContentType = 'application/json'
            }
            return Invoke-RestMethod @parameters
        }
        catch {
            $responseProperty = $_.Exception.PSObject.Properties['Response']
            $status = if ($responseProperty -and $responseProperty.Value) { [int]$responseProperty.Value.StatusCode } else { 0 }
            if ($Method -ne 'GET' -or $status -notin @(429, 503) -or $attempt -eq 3) { throw }
            $wait = [int][Math]::Pow(2, $attempt + 1)
            Write-Warning "GCCH returned HTTP $status for a read. Retrying in $wait seconds."
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-TrellixGraphCollection {
    param([Parameter(Mandatory)][string]$Path)
    $next = $Path
    $pages = 0
    while ($next) {
        if (++$pages -gt 1000) { throw 'Graph pagination exceeded the supported safety limit.' }
        $response = Invoke-TrellixGraph -Method GET -Path $next | ConvertTo-Json -Depth 80 | ConvertFrom-Json -AsHashtable
        if (-not $response.ContainsKey('value')) { throw 'Expected a Graph collection response.' }
        foreach ($item in $response.value) { $item }
        $next = $response['@odata.nextLink']
    }
}

function Get-TrellixFirewallSchema {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutPath)
    $templates = @(Get-TrellixGraphCollection -Path "/deviceManagement/configurationPolicyTemplates?`$filter=templateFamily%20eq%20%27endpointSecurityFirewall%27")
    $matches = @($templates | Where-Object {
        $_.displayName -eq 'Windows Firewall Rules' -and $_.lifecycleState -eq 'active' -and
        $_.platforms -eq 'windows10' -and $_.technologies -match 'microsoftSense'
    })
    if ($matches.Count -ne 1) { throw 'Expected exactly one active Windows Firewall Rules template supporting MDE management.' }
    $template = $matches[0]
    $settings = @(Get-TrellixGraphCollection -Path "/deviceManagement/configurationPolicyTemplates/$($template.id)/settingTemplates")
    if ($settings.Count -ne 1 -or $settings[0].settingInstanceTemplate['@odata.type'] -ne
        '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstanceTemplate') {
        throw 'The active Firewall Rules template has an unsupported root shape.'
    }
    $root = $settings[0].settingInstanceTemplate
    if ($root.groupSettingCollectionValueTemplate.Count -ne 1) { throw 'Expected a single firewall-rule group template.' }
    $definitions = @{}
    $implementedFields = @('description', 'direction', 'enabled', 'app_filepath', 'interfacetypes',
        'localaddressranges', 'localportranges', 'name', 'profiles', 'protocol',
        'remoteaddressranges', 'remoteportranges', 'action_type')
    $definitionIds = @($root.settingDefinitionId) + @($root.groupSettingCollectionValueTemplate[0].children |
        Where-Object { $_.settingDefinitionId.Substring($root.settingDefinitionId.Length + 1) -in $implementedFields } |
        ForEach-Object { $_.settingDefinitionId })
    foreach ($id in $definitionIds) {
        $escaped = [uri]::EscapeDataString($id)
        $definition = Invoke-TrellixGraph -Method GET -Path "/deviceManagement/configurationSettings/$escaped"
        $definitions[$id] = $definition | ConvertTo-Json -Depth 60 | ConvertFrom-Json -AsHashtable
    }
    $schema = [ordered]@{
        SchemaVersion = 1; GraphHost = 'graph.microsoft.us'; RetrievedAt = [DateTimeOffset]::UtcNow.ToString('o')
        Template = $template; Root = $root; Definitions = $definitions
    }
    $parent = Split-Path -Parent $OutPath
    if ($parent) { $null = New-Item -ItemType Directory -Path $parent -Force }
    $schema | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath $OutPath -Encoding utf8
    [pscustomobject]@{ SchemaPath = $OutPath; TemplateId = $template.id; DefinitionCount = $definitions.Count }
}

function New-TrellixFirewallApproval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$OutPath
    )
    if (Test-Path -LiteralPath $OutPath) { throw 'The approval file already exists. Refusing to overwrite review decisions.' }
    $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json -AsHashtable
    if ($report.SourceProduct -ne 'Trellix ENS Firewall') { throw 'Expected a Trellix Firewall review report.' }
    $approval = [ordered]@{
        SchemaVersion = 1; SourceSha256 = $report.SourceSha256
        ReviewSha256 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash
        TargetTenantId = ''; PolicyNamePrefix = 'Trellix Firewall Migration'
        Profiles = @(); InterfaceTypes = @()
        Acknowledgements = [ordered]@{
            RuleOrderingAndBlockPrecedenceReviewed = $false
            FirewallBaselineAndScopeReviewed = $false
            VendorMatchingAndEmptyPortsReviewed = $false
            IPv4IPv6ScopeReviewed = $false
        }
        ApprovedRuleIds = @()
        ApplicationPathResolutions = @{}
        ApplicationIdentityReplacements = @{}
        StraightforwardCandidates = @($report.Rules | Where-Object MappingClass -eq 'FieldMappingDraft' |
            ForEach-Object { [ordered]@{ SourceGuid = $_.SourceGuid; Name = $_.Name } })
    }
    $parent = Split-Path -Parent $OutPath
    if ($parent) { $null = New-Item -ItemType Directory -Path $parent -Force }
    $approval | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutPath -Encoding utf8
    [pscustomobject]@{ ApprovalPath = $OutPath; ApprovedRules = 0; CandidateRules = $approval.StraightforwardCandidates.Count }
}

function Get-TrellixTextHash {
    param([Parameter(Mandatory)][string]$Text)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))
}

function Write-TrellixJson {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { $null = New-Item -ItemType Directory -Path $parent -Force }
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $Value | ConvertTo-Json -Depth 90 | Set-Content -LiteralPath $temporary -Encoding utf8
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    }
}

function New-TrellixSetting {
    param([hashtable]$Schema, [string]$Field, [object[]]$Values)
    $id = $Schema.Root.settingDefinitionId + '_' + $Field
    $templates = @($Schema.Root.groupSettingCollectionValueTemplate[0].children |
        Where-Object settingDefinitionId -eq $id)
    if ($templates.Count -ne 1 -or -not $Schema.Definitions.ContainsKey($id)) {
        throw "The retrieved schema does not define the implemented field: $Field"
    }
    $template = $templates[0]
    $definition = $Schema.Definitions[$id]
    $kind = $template['@odata.type'].Replace('Template', '')
    # Repeated rule groups use definition IDs, not duplicate template references.
    $instance = @{
        '@odata.type' = $kind
        settingDefinitionId = $id
    }
    $collection = $kind -like '*CollectionInstance'
    if (-not $collection -and $Values.Count -ne 1) { throw "Expected one value for $Field." }
    if ($collection -and ($Values.Count -lt $definition.minimumCount -or $Values.Count -gt $definition.maximumCount)) {
        throw "Value count exceeds the retrieved schema limits for $Field."
    }
    if ($kind -like '*ChoiceSetting*') {
        $converted = @(
            foreach ($value in $Values) {
                $options = @($definition.options | Where-Object { [string]$_.optionValue.value -ceq [string]$value })
                if ($options.Count -ne 1) { throw "The schema does not define the requested $Field option: $value" }
                @{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value = $options[0].itemId
                    children = @()
                }
            }
        )
        if ($collection) { $instance.choiceSettingCollectionValue = $converted }
        else { $instance.choiceSettingValue = $converted[0] }
    }
    elseif ($kind -like '*SimpleSetting*') {
        $valueType = $definition.valueDefinition['@odata.type']
        $converted = @(
            foreach ($value in $Values) {
                if ($valueType -like '*IntegerSettingValueDefinition') {
                    $number = 0
                    if (-not [int]::TryParse([string]$value, [ref]$number) -or
                        $number -lt $definition.valueDefinition.minimumValue -or
                        $number -gt $definition.valueDefinition.maximumValue) { throw "Invalid integer for $Field." }
                    $scalar = $number
                    $scalarType = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'
                }
                elseif ($valueType -like '*StringSettingValueDefinition') {
                    $scalar = [string]$value
                    if ($scalar.Length -lt $definition.valueDefinition.minimumLength -or
                        $scalar.Length -gt $definition.valueDefinition.maximumLength) { throw "Invalid string length for $Field." }
                    $scalarType = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                }
                else { throw "Unsupported value type for $Field." }
                @{
                    '@odata.type' = $scalarType
                    value = $scalar
                }
            }
        )
        if ($collection) { $instance.simpleSettingCollectionValue = $converted }
        else { $instance.simpleSettingValue = $converted[0] }
    }
    else { throw "Unsupported setting instance type for $Field." }
    $instance
}

function Get-TrellixAddressFamily {
    param([string]$Value)
    if ($Value -match '^(.+)/(\d+)$') {
        $first = $Matches[1]; $prefix = [int]$Matches[2]
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($first, [ref]$ip)) { throw "Non-IP address is not deployable: $Value" }
        $maximum = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        if ($prefix -gt $maximum) { throw "Invalid IP prefix: $Value" }
    }
    elseif ($Value.Contains('-')) {
        $bounds = $Value.Split('-')
        $ip = $null; $end = $null
        if ($bounds.Count -ne 2 -or -not [Net.IPAddress]::TryParse($bounds[0], [ref]$ip) -or
            -not [Net.IPAddress]::TryParse($bounds[1], [ref]$end) -or $ip.AddressFamily -ne $end.AddressFamily) {
            throw "Invalid IP range: $Value"
        }
        $left = $ip.GetAddressBytes(); $right = $end.GetAddressBytes()
        for ($i = 0; $i -lt $left.Length; $i++) {
            if ($left[$i] -gt $right[$i]) { throw "Reversed IP range: $Value" }
            if ($left[$i] -lt $right[$i]) { break }
        }
    }
    else {
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($Value, [ref]$ip)) { throw "Non-IP address is not deployable: $Value" }
    }
    if ($ip.IsIPv4MappedToIPv6) { throw 'Expected a normalized address, not IPv4-mapped IPv6.' }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
}

function Assert-TrellixPorts {
    param([object[]]$Ports)
    foreach ($port in $Ports) {
        if ([string]$port -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') { throw "Unsupported port expression: $port" }
        $start = [int]$Matches[1]
        $end = if ($Matches[2]) { [int]$Matches[2] } else { $start }
        if ($start -gt 65535 -or $end -gt 65535 -or $end -lt $start) { throw "Invalid port range: $port" }
    }
}

function Get-TrellixSourceSequence {
    param([hashtable]$Settings, [string]$Name)
    $entries = @($Settings.GetEnumerator() | Where-Object { $_.Key -match "^\+$Name#\d+$" } |
        Sort-Object { [int]($_.Key.Split('#')[-1]) })
    if (-not $Settings.ContainsKey("_$Name") -or [string]$Settings["_$Name"] -cne [string]$entries.Count) {
        throw "The source $Name selector count is invalid."
    }
    for ($i = 0; $i -lt $entries.Count; $i++) {
        if ($entries[$i].Key -ine "+$Name#$i") { throw "The source $Name selector sequence is invalid." }
        [string]$entries[$i].Value
    }
}

function New-TrellixFirewallPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$ApprovalPath,
        [Parameter(Mandatory)][string]$SchemaPath,
        [Parameter(Mandatory)][string]$OutPath,
        [switch]$StageDisabled
    )
    if (Test-Path -LiteralPath $OutPath) { throw 'The plan already exists. Refusing to overwrite an approved snapshot.' }
    $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json -AsHashtable
    $approval = Get-Content -LiteralPath $ApprovalPath -Raw | ConvertFrom-Json -AsHashtable
    $schema = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -AsHashtable
    if ($report.SourceProduct -ne 'Trellix ENS Firewall' -or $report.SchemaVersion -ne 1 -or
        $approval.SchemaVersion -ne 1 -or $schema.SchemaVersion -ne 1 -or $schema.GraphHost -ne 'graph.microsoft.us') {
        throw 'Unsupported report, approval or GCC High schema version.'
    }
    if ($report.SourceSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $report.SourceSha256 -ne $approval.SourceSha256 -or
        (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash -ne $approval.ReviewSha256) {
        throw 'The review or original-source hash does not match the approval.'
    }
    $tenant = [guid]::Empty
    if (-not [guid]::TryParse($approval.TargetTenantId, [ref]$tenant) -or $tenant -eq [guid]::Empty) {
        throw 'An explicit target tenant GUID is required.'
    }
    foreach ($key in @('RuleOrderingAndBlockPrecedenceReviewed', 'FirewallBaselineAndScopeReviewed',
        'VendorMatchingAndEmptyPortsReviewed', 'IPv4IPv6ScopeReviewed')) {
        if ($approval.Acknowledgements[$key] -isnot [bool] -or -not $approval.Acknowledgements[$key]) {
            throw "Required acknowledgement is missing: $key"
        }
    }
    $profileValues = @{ Domain = 1; Private = 2; Public = 4; All = 2147483647 }
    $interfaceValues = @{ Lan = 'Lan'; Wireless = 'Wireless'; RemoteAccess = 'RemoteAccess'; MBB = 'MBB'; All = 'All' }
    foreach ($scope in @(@{ Values = @($approval.Profiles); Options = $profileValues; Name = 'Profiles' },
        @{ Values = @($approval.InterfaceTypes); Options = $interfaceValues; Name = 'InterfaceTypes' })) {
        if ($scope.Values.Count -eq 0 -or @($scope.Values | Select-Object -Unique).Count -ne $scope.Values.Count -or
            @($scope.Values | Where-Object { -not $scope.Options.ContainsKey([string]$_) }).Count -gt 0 -or
            ($scope.Values -contains 'All' -and $scope.Values.Count -ne 1)) { throw "Invalid explicit $($scope.Name) scope." }
    }
    $prefix = [string]$approval.PolicyNamePrefix
    if ([string]::IsNullOrWhiteSpace($prefix) -or $prefix.Length -gt 150 -or $prefix -match '[\r\n]') {
        throw 'PolicyNamePrefix must contain 1-150 characters and no newlines.'
    }
    $approvedIds = @($approval.ApprovedRuleIds)
    if ($approvedIds.Count -eq 0 -or @($approvedIds | Select-Object -Unique).Count -ne $approvedIds.Count) {
        throw 'Approve at least one source rule and do not duplicate GUIDs.'
    }
    $rules = [Collections.Generic.List[object]]::new()
    foreach ($sourceId in $approvedIds) {
        $found = @($report.Rules | Where-Object SourceGuid -eq $sourceId)
        if ($found.Count -ne 1) { throw "Approved rule GUID is not unique in the review: $sourceId" }
        $source = $found[0]
        $allowedCodes = @('ApplicationWildcardNeedsExactPaths', 'PreserveDisabledState')
        if ($source.Kind -ne 'FirewallRule' -or
            $source.MappingClass -notin @('FieldMappingDraft', 'ApplicationResolutionRequired', 'AdditionalSemanticReviewRequired') -or
            @($source.ReviewCodes | Where-Object { $_ -notin $allowedCodes }).Count -gt 0) {
            throw "Approved rule still has unsupported semantics: $($source.Name) [$($source.ReviewCodes -join ', ')]"
        }
        $supportedRuleKeys = @('GUID', 'Name', 'Action', 'Direction', 'Enabled', 'ViewOnly', 'Logged',
            'Intrusion', 'Invert', 'ClickTimeout', 'OffHours', 'ScheduleEnabled', 'ScheduleDisableDuringTime',
            'ScheduleEndHours', 'ScheduleEndMinutes', 'ScheduleStartHours', 'ScheduleStartMinutes',
            'StartTime', 'EndTime', 'WeekMask', 'NetworkProtocol', 'TransportProtocol', 'LocalPort',
            'RemotePort', 'TcpFlags', 'MessageType', 'AggRef', 'AppExeSet', 'AppGUID', 'AppName')
        foreach ($key in $source.SourceSettings.Keys) {
            $baseKey = $key -replace '^\+(.+)#\d+$', '$1' -replace '^_', ''
            if ($baseKey -notin $supportedRuleKeys) { throw "Unimplemented source rule setting: $key" }
        }
        $mapping = $source.FieldMapping
        if (@($mapping.ApplicationSetSelectors | Where-Object { $_ -ne '0' }).Count -gt 0) {
            throw 'Unimplemented Trellix application-set selection semantics.'
        }
        if ($mapping.Action -notin @('Allow', 'Block') -or $source.EffectiveEnabled -isnot [bool] -or
            @($mapping.Directions).Count -eq 0 -or
            @($mapping.Directions | Where-Object { $_ -notin @('Inbound', 'Outbound') }).Count -gt 0) {
            throw "Invalid rule action, enabled state or direction: $($source.Name)"
        }
        $etherTypes = @($mapping.SourceEtherTypes | Select-Object -Unique)
        if ($etherTypes.Count -eq 0 -or @($etherTypes | Where-Object { $_ -notin @('2048', '34525') }).Count -gt 0) {
            throw "An explicit IP-family mapping is required: $($source.Name)"
        }
        $conditions = @($mapping.ResolvedConditions)
        if ($conditions.Count -gt 1) { throw "Compound aggregate semantics require separate engineering: $($source.Name)" }
        $identityReplacement = $null
        $hasIdentitySelectors = @($source.SourceSettings.Keys | Where-Object { $_ -match '^(?:_|\+)App(?:GUID|Name)(?:#\d+)?$' }).Count -gt 0
        if ($hasIdentitySelectors) {
            if (-not $approval.ContainsKey('ApplicationIdentityReplacements') -or
                -not $approval.ApplicationIdentityReplacements.ContainsKey([string]$sourceId)) {
                throw 'Explicit application-identity replacement approval is required; Trellix GUID/name selectors cannot be silently ignored.'
            }
            $replacement = $approval.ApplicationIdentityReplacements[[string]$sourceId]
            if ($replacement.Reviewed -isnot [bool] -or -not $replacement.Reviewed -or
                ([string]$replacement.Reason).Trim().Length -lt 20 -or ([string]$replacement.Reason).Length -gt 2000) {
                throw 'Application-identity replacement requires an explicit acknowledgement and a specific 20-2000 character rationale.'
            }
            $selectorGuids = @(Get-TrellixSourceSequence $source.SourceSettings 'AppGUID')
            $selectorNames = @(Get-TrellixSourceSequence $source.SourceSettings 'AppName')
            $selectorGuid = [guid]::Empty
            if ($selectorGuids.Count -ne 1 -or $selectorNames.Count -ne 1 -or
                -not [guid]::TryParseExact($selectorGuids[0], 'D', [ref]$selectorGuid) -or $selectorGuid -eq [guid]::Empty -or
                $conditions.Count -ne 1 -or $conditions[0].Type -ne '65547' -or
                @($conditions[0].ApplicationPaths).Count -ne 1 -or
                $selectorNames[0] -ine [string]$conditions[0].SourceSettings['+AppName#0']) {
                throw 'The source application identity cannot be bounded to one matching exported application condition.'
            }
            $identityReplacement = @{
                Mode = 'Explicit replacement, not certified equivalence'
                SourceAppGuids = $selectorGuids; SourceAppNames = $selectorNames
                Reason = ([string]$replacement.Reason).Trim()
            }
        }
        $local = @(); $remote = @(); $application = ''
        foreach ($condition in $conditions) {
            foreach ($key in $condition.SourceSettings.Keys) {
                $baseKey = $key -replace '^\+(.+)#\d+$', '$1' -replace '^_', ''
                if ($baseKey -notin @('GUID', 'Name', 'Type', 'AppName', 'AppPath', 'AppHash', 'AppSigner',
                    'AppDescription', 'LocalAddress', 'RemoteAddress', 'RemoteNetID')) {
                    throw "Unimplemented source aggregate setting: $key"
                }
            }
            if (@($condition.ReviewCodes | Where-Object { $_ -notin $allowedCodes }).Count -gt 0) {
                throw "Aggregate contains unresolved conditions: $($source.Name)"
            }
            foreach ($entry in @($condition.LocalAddresses)) {
                if ($entry.ReviewCode -or $entry.Kind -notin @('IPAddress', 'CIDR', 'IPRange') -or -not $entry.Candidate) {
                    throw "Unresolved local address: $($source.Name)"
                }
                $local += $entry.Candidate
            }
            foreach ($entry in @($condition.RemoteAddresses)) {
                if ($entry.ReviewCode -or $entry.Kind -notin @('IPAddress', 'CIDR', 'IPRange') -or -not $entry.Candidate) {
                    throw "Unresolved remote address: $($source.Name)"
                }
                $remote += $entry.Candidate
            }
            if (@($condition.ApplicationPaths).Count -gt 1) { throw 'Multiple application alternatives require separate review.' }
            if (@($condition.ApplicationPaths).Count -eq 1) { $application = [string]$condition.ApplicationPaths[0] }
        }
        foreach ($address in @($local) + @($remote)) { $null = Get-TrellixAddressFamily -Value $address }
        if ($etherTypes.Count -eq 1) {
            $family = if ($etherTypes[0] -eq '2048') { 'IPv4' } else { 'IPv6' }
            foreach ($address in @($local) + @($remote)) {
                if ((Get-TrellixAddressFamily -Value $address) -ne $family) { throw "Conflicting source IP family: $($source.Name)" }
            }
            $anyInFamily = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
            if ($local.Count -eq 0) { $local = @($anyInFamily) }
            if ($remote.Count -eq 0) { $remote = @($anyInFamily) }
        }
        $applications = @('')
        if ($application) {
            if ($application -match '[*?]') {
                if (-not $approval.ApplicationPathResolutions.ContainsKey([string]$sourceId)) {
                    throw "Exact application-path resolutions are missing: $($source.Name)"
                }
                $applications = @($approval.ApplicationPathResolutions[[string]$sourceId])
            }
            else { $applications = @($application) }
            if ($applications.Count -eq 0 -or @($applications | Select-Object -Unique).Count -ne $applications.Count) {
                throw 'Application resolutions must contain at least one unique exact path.'
            }
            foreach ($path in $applications) {
                if ($path -notmatch '^[A-Za-z]:\\' -or $path -match '[\x00-\x1f/*?<>|"%]' -or
                    $path.Substring(2).Contains(':') -or $path -match '(?:^|\\)\.\.?(?:\\|$)' -or
                    $path.Substring(3) -match '\\\\|[. ](?:\\|$)' -or
                    -not [WildcardPattern]::new($application, [Management.Automation.WildcardOptions]::IgnoreCase).IsMatch($path)) {
                    throw "Resolution is not an exact drive-qualified path matching the original application: $path"
                }
            }
        }
        elseif ($source.ReviewCodes -contains 'ApplicationWildcardNeedsExactPaths') {
            throw "The source wildcard application condition is missing: $($source.Name)"
        }
        Assert-TrellixPorts -Ports @($mapping.LocalPorts)
        Assert-TrellixPorts -Ports @($mapping.RemotePorts)
        $protocols = @($mapping.TransportProtocolNumbers)
        if ($protocols.Count -eq 0) { $protocols = @($null) }
        foreach ($protocol in $protocols) {
            $number = 0
            if ($null -ne $protocol -and (-not [int]::TryParse([string]$protocol, [ref]$number) -or $number -lt 0 -or $number -gt 255)) {
                throw "Invalid source IP protocol: $protocol"
            }
            if ((@($mapping.LocalPorts).Count + @($mapping.RemotePorts).Count) -gt 0 -and
                ($null -eq $protocol -or $number -notin @(6, 17))) { throw 'Port restrictions require TCP or UDP.' }
            foreach ($direction in $mapping.Directions) {
                for ($appIndex = 0; $appIndex -lt $applications.Count; $appIndex++) {
                    $shortName = [string]$source.Name
                    if ($shortName.Length -gt 115) { $shortName = $shortName.Substring(0, 115) }
                    $protocolLabel = if ($null -eq $protocol) { 'Any' } else { [string]$number }
                    $name = "$shortName [$sourceId.$direction.$protocolLabel.$appIndex]"
                    $rules.Add([ordered]@{
                        Name = $name; SourceGuid = $sourceId; SourceName = $source.Name
                        SourceListId = $source.SourceListId; SourceListIndex = $source.SourceListIndex
                        ParentGroups = @($source.ParentGroups)
                        Enabled = ($source.EffectiveEnabled -and -not $StageDisabled)
                        IntendedEnabled = $source.EffectiveEnabled
                        ApplicationIdentityReplacement = $identityReplacement
                        Action = $mapping.Action; Direction = $direction
                        Protocol = $(if ($null -eq $protocol) { $null } else { $number })
                        Profiles = @($approval.Profiles); InterfaceTypes = @($approval.InterfaceTypes)
                        ApplicationPath = $applications[$appIndex]
                        LocalAddresses = $local; RemoteAddresses = $remote
                        LocalPorts = @($mapping.LocalPorts); RemotePorts = @($mapping.RemotePorts)
                    })
                }
            }
        }
    }
    $rulesJson = ConvertTo-Json -InputObject $rules.ToArray() -Depth 20 -Compress
    $rulesHash = Get-TrellixTextHash -Text $rulesJson
    $root = $schema.Root
    $policies = @(
        for ($offset = 0; $offset -lt $rules.Count; $offset += 150) {
            $count = [Math]::Min(150, $rules.Count - $offset)
            $groups = @(
                foreach ($rule in $rules.GetRange($offset, $count)) {
                    $children = @(
                        New-TrellixSetting $schema 'name' @($rule.Name)
                        New-TrellixSetting $schema 'description' @("Trellix source GUID: $($rule.SourceGuid). Ordering is provenance only.")
                        New-TrellixSetting $schema 'enabled' @([int]$rule.Enabled)
                        New-TrellixSetting $schema 'action_type' @($(if ($rule.Action -eq 'Allow') { 1 } else { 0 }))
                        New-TrellixSetting $schema 'direction' @($(if ($rule.Direction -eq 'Inbound') { 'IN' } else { 'OUT' }))
                        New-TrellixSetting $schema 'profiles' @($rule.Profiles | ForEach-Object { $profileValues[$_] })
                        New-TrellixSetting $schema 'interfacetypes' @($rule.InterfaceTypes | ForEach-Object { $interfaceValues[$_] })
                        if ($null -ne $rule.Protocol) { New-TrellixSetting $schema 'protocol' @($rule.Protocol) }
                        if ($rule.ApplicationPath) { New-TrellixSetting $schema 'app_filepath' @($rule.ApplicationPath) }
                        foreach ($field in @(@{ Name = 'localaddressranges'; Values = $rule.LocalAddresses },
                            @{ Name = 'remoteaddressranges'; Values = $rule.RemoteAddresses },
                            @{ Name = 'localportranges'; Values = $rule.LocalPorts },
                            @{ Name = 'remoteportranges'; Values = $rule.RemotePorts })) {
                            if ($field.Values.Count -gt 0) { New-TrellixSetting $schema $field.Name $field.Values }
                        }
                    )
                    @{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingValue'
                        children = $children
                    }
                }
            )
            $batch = [int]($offset / 150) + 1
            @{
                Name = ('{0} - {1} - {2:D3}' -f $prefix, $rulesHash.Substring(0, 10), $batch)
                RuleCount = $count
                Body = @{
                    name = ('{0} - {1} - {2:D3}' -f $prefix, $rulesHash.Substring(0, 10), $batch)
                    description = "Trellix migration; SourceSHA256=$($report.SourceSha256); RulesSHA256=$rulesHash. Unassigned; requires separate endpoint pilot."
                    platforms = 'windows10'; technologies = 'mdm,microsoftSense'; roleScopeTagIds = @('0')
                    templateReference = @{ templateId = $schema.Template.id }
                    settings = @(@{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSetting'
                        settingInstance = @{
                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                            settingDefinitionId = $root.settingDefinitionId
                            settingInstanceTemplateReference = @{ settingInstanceTemplateId = $root.settingInstanceTemplateId }
                            groupSettingCollectionValue = $groups
                        }
                    })
                }
            }
        }
    )
    $plan = [ordered]@{
        SchemaVersion = 1; GraphHost = 'graph.microsoft.us'; TargetTenantId = $tenant.ToString()
        CreatedAt = [DateTimeOffset]::UtcNow.ToString('o')
        SourceSha256 = $report.SourceSha256; ReviewSha256 = $approval.ReviewSha256
        ApprovalSha256 = (Get-FileHash -LiteralPath $ApprovalPath -Algorithm SHA256).Hash
        TemplateId = $schema.Template.id; RulesSha256 = $rulesHash
        ApprovedSourceRules = $approvedIds.Count; ExpandedRules = $rules.Count
        UnassignedOnly = $true; Rules = $rules.ToArray(); Policies = $policies
        StagingMode = $(if ($StageDisabled) { 'DisabledUnassigned' } else { 'SourceStateUnassigned' })
        StagingDisabledOptionId = $(if ($StageDisabled) {
            @($schema.Definitions[$schema.Root.settingDefinitionId + '_enabled'].options |
                Where-Object { [string]$_.optionValue.value -ceq '0' })[0].itemId
        } else { $null })
        ExcludedRecords = @($report.Rules | Where-Object { $_.SourceGuid -notin $approvedIds } |
            ForEach-Object { @{ SourceGuid = $_.SourceGuid; Name = $_.Name; MappingClass = $_.MappingClass; ReviewCodes = $_.ReviewCodes } })
    }
    Write-TrellixJson -Value $plan -Path $OutPath
    [pscustomobject]@{ PlanPath = $OutPath; ApprovedSourceRules = $approvedIds.Count; ExpandedRules = $rules.Count; Policies = $policies.Count; UnassignedOnly = $true }
}

function Read-TrellixPlan {
    param([string]$Path)
    $plan = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    if ($plan.SchemaVersion -ne 1 -or $plan.GraphHost -ne 'graph.microsoft.us' -or
        $plan.UnassignedOnly -isnot [bool] -or -not $plan.UnassignedOnly -or @($plan.Policies).Count -eq 0) {
        throw 'Expected a supported, unassigned-only GCC High plan.'
    }
    $tenant = [guid]::Empty
    if (-not [guid]::TryParse($plan.TargetTenantId, [ref]$tenant) -or $tenant -eq [guid]::Empty) {
        throw 'The plan does not specify a valid tenant.'
    }
    $total = 0
    if ($plan.ContainsKey('StagingMode') -and $plan.StagingMode -eq 'DisabledUnassigned') {
        if (@($plan.Rules).Count -ne $plan.ExpandedRules -or
            @($plan.Rules | Where-Object { $_.Enabled -isnot [bool] -or $_.Enabled }).Count -gt 0 -or
            -not $plan.StagingDisabledOptionId) { throw 'Staging requires every rule to be explicitly disabled.' }
        foreach ($policy in $plan.Policies) {
            foreach ($group in $policy.Body.settings[0].settingInstance.groupSettingCollectionValue) {
                $enabled = @($group.children | Where-Object {
                    $_.settingDefinitionId -ceq 'vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_enabled'
                })
                if ($enabled.Count -ne 1 -or $enabled[0].choiceSettingValue.value -cne $plan.StagingDisabledOptionId) {
                    throw 'A staged policy contains an enabled rule or an ambiguous enabled setting.'
                }
            }
        }
    }
    foreach ($policy in $plan.Policies) {
        $body = $policy.Body
        foreach ($key in $body.Keys) {
            if ($key -notin @('name', 'description', 'platforms', 'technologies', 'roleScopeTagIds', 'templateReference', 'settings')) {
                throw "Unexpected policy payload property: $key"
            }
        }
        if ($body.name -cne $policy.Name -or $body.platforms -ne 'windows10' -or
            $body.technologies -ne 'mdm,microsoftSense' -or $body.templateReference.templateId -ne $plan.TemplateId -or
            @($body.settings).Count -ne 1 -or $policy.RuleCount -lt 1 -or $policy.RuleCount -gt 150 -or
            @($body.settings[0].settingInstance.groupSettingCollectionValue).Count -ne $policy.RuleCount) {
            throw "Invalid policy payload or rule count: $($policy.Name)"
        }
        $null = Get-TrellixSettingsMeaning -Settings @($body.settings)
        $total += $policy.RuleCount
    }
    if ($total -ne $plan.ExpandedRules -or
        @($plan.Policies.Name | Select-Object -Unique).Count -ne @($plan.Policies).Count) {
        throw 'The plan has inconsistent rule counts or duplicate policy names.'
    }
    $plan
}

function Get-TrellixSettingsMeaning {
    param([object[]]$Settings)
    if ($Settings.Count -ne 1) { throw 'Expected exactly one firewall rule collection setting.' }
    $root = $Settings[0].settingInstance
    if ($root['@odata.type'] -ne '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance' -or
        $root.settingDefinitionId -cne 'vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}') {
        throw 'Unexpected firewall setting root.'
    }
    $groups = @(
        foreach ($group in $root.groupSettingCollectionValue) {
            $seen = @{}
            $fields = @(
                foreach ($child in $group.children) {
                    $id = [string]$child.settingDefinitionId
                    if ($seen.ContainsKey($id)) { throw "Duplicate setting within one rule: $id" }
                    $seen[$id] = $true
                    $type = [string]$child['@odata.type']
                    switch ($type) {
                        '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance' {
                            $values = @($child.simpleSettingValue.value)
                        }
                        '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance' {
                            $values = @($child.simpleSettingCollectionValue | ForEach-Object { $_.value })
                        }
                        '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance' {
                            if (@($child.choiceSettingValue.children).Count -gt 0) { throw 'Unexpected nested choice settings.' }
                            $values = @($child.choiceSettingValue.value)
                        }
                        '#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance' {
                            foreach ($value in $child.choiceSettingCollectionValue) {
                                if (@($value.children).Count -gt 0) { throw 'Unexpected nested choice settings.' }
                            }
                            $values = @($child.choiceSettingCollectionValue | ForEach-Object { $_.value })
                        }
                        default { throw "Unsupported persisted setting type: $type" }
                    }
                    $valueJson = ConvertTo-Json -InputObject @($values | Sort-Object -CaseSensitive) -Compress -Depth 10
                    "$id|$type|$valueJson"
                }
            )
            $fields = @($fields | Sort-Object -CaseSensitive)
            $fields -join "`n"
        }
    )
    ConvertTo-Json -InputObject @($groups | Sort-Object -CaseSensitive) -Compress -Depth 10
}

function Assert-TrellixLiveTemplate {
    param([hashtable]$Plan)
    $template = Invoke-TrellixGraph -Method GET -Path "/deviceManagement/configurationPolicyTemplates/$($Plan.TemplateId)" |
        ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable
    if ($template.lifecycleState -ne 'active' -or $template.displayName -ne 'Windows Firewall Rules' -or
        $template.platforms -ne 'windows10' -or $template.technologies -notmatch 'microsoftSense') {
        throw 'The approved template is no longer the active Windows/MDE Firewall Rules template.'
    }
    $settings = @(Get-TrellixGraphCollection -Path "/deviceManagement/configurationPolicyTemplates/$($Plan.TemplateId)/settingTemplates")
    if ($settings.Count -ne 1) { throw 'The live template root has changed.' }
    $root = $settings[0].settingInstanceTemplate
    foreach ($policy in $Plan.Policies) {
        $instance = $policy.Body.settings[0].settingInstance
        if ($instance.settingDefinitionId -ne $root.settingDefinitionId -or
            $instance.settingInstanceTemplateReference.settingInstanceTemplateId -ne $root.settingInstanceTemplateId) {
            throw 'The plan does not match the live root template.'
        }
        foreach ($group in $instance.groupSettingCollectionValue) {
            if ($group['settingValueTemplateReference']) { throw 'Repeated rule groups must not duplicate template references.' }
            foreach ($child in $group.children) {
                $matches = @($root.groupSettingCollectionValueTemplate[0].children |
                    Where-Object settingDefinitionId -eq $child.settingDefinitionId)
                if ($matches.Count -ne 1 -or $child['@odata.type'] -cne $matches[0]['@odata.type'].Replace('Template', '') -or
                    $child['settingInstanceTemplateReference']) { throw 'A planned field does not match the live template.' }
                switch ($child['@odata.type']) {
                    '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance' {
                        $values = @($child.simpleSettingValue)
                    }
                    '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance' {
                        $values = @($child.simpleSettingCollectionValue)
                    }
                    '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance' {
                        $values = @($child.choiceSettingValue)
                    }
                    '#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance' {
                        $values = @($child.choiceSettingCollectionValue)
                    }
                    default { throw 'Unsupported planned field type.' }
                }
                foreach ($value in $values) {
                    if ($value['settingValueTemplateReference']) { throw 'Repeated values must not duplicate template references.' }
                }
            }
        }
    }
}

function Read-TrellixReceipt {
    param([string]$Path, [string]$PlanPath, [hashtable]$Plan, [switch]$AllowNew)
    $hash = (Get-FileHash -LiteralPath $PlanPath -Algorithm SHA256).Hash
    if (Test-Path -LiteralPath $Path) {
        $receipt = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
        if ($receipt.SchemaVersion -ne 1 -or $receipt.PlanSha256 -ne $hash -or
            $receipt.TargetTenantId -ne $Plan.TargetTenantId) { throw 'The receipt belongs to a different plan or tenant.' }
        if (@($receipt.Policies.PolicyId | Select-Object -Unique).Count -ne @($receipt.Policies).Count -or
            @($receipt.Policies.Name | Select-Object -Unique).Count -ne @($receipt.Policies).Count) {
            throw 'The receipt contains duplicate policy identities.'
        }
        foreach ($entry in $receipt.Policies) {
            $id = [guid]::Empty
            if (-not [guid]::TryParse($entry.PolicyId, [ref]$id) -or $id -eq [guid]::Empty -or $entry.Name -notin $Plan.Policies.Name) {
                throw 'The receipt contains an invalid policy identity.'
            }
        }
        return $receipt
    }
    if (-not $AllowNew) { throw 'The required import receipt does not exist.' }
    @{
        SchemaVersion = 1; TargetTenantId = $Plan.TargetTenantId; PlanSha256 = $hash
        SourceSha256 = $Plan.SourceSha256; CreatedAt = [DateTimeOffset]::UtcNow.ToString('o')
        Policies = @()
    }
}

function Assert-TrellixStoredPolicy {
    param([hashtable]$Policy, [string]$PolicyId)
    $id = [guid]::Empty
    if (-not [guid]::TryParse($PolicyId, [ref]$id) -or $id -eq [guid]::Empty) { throw 'Invalid policy ID.' }
    $metadata = Invoke-TrellixGraph -Method GET -Path "/deviceManagement/configurationPolicies/$id" |
        ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable
    $settings = @(Get-TrellixGraphCollection -Path "/deviceManagement/configurationPolicies/$id/settings")
    $assignments = @(Get-TrellixGraphCollection -Path "/deviceManagement/configurationPolicies/$id/assignments")
    if ($metadata.name -cne $Policy.Body.name -or $metadata.description -cne $Policy.Body.description -or
        $metadata.platforms -ne $Policy.Body.platforms -or $metadata.technologies -ne $Policy.Body.technologies -or
        $metadata.templateReference.templateId -ne $Policy.Body.templateReference.templateId -or
        (ConvertTo-Json -InputObject @($metadata.roleScopeTagIds | Sort-Object) -Compress) -cne
        (ConvertTo-Json -InputObject @($Policy.Body.roleScopeTagIds | Sort-Object) -Compress)) {
        throw "Persisted policy metadata differs from the plan: $($Policy.Name) [$id]"
    }
    $hasAssignmentFlag = $metadata.ContainsKey('isAssigned')
    if ($assignments.Count -ne 0 -or
        ($hasAssignmentFlag -and ($metadata['isAssigned'] -isnot [bool] -or $metadata['isAssigned']))) {
        throw "Refusing an assigned or unverifiably unassigned policy: $($Policy.Name) [$id]"
    }
    $expected = Get-TrellixSettingsMeaning -Settings @($Policy.Body.settings)
    $actual = Get-TrellixSettingsMeaning -Settings $settings
    if ($actual -cne $expected) { throw "Persisted firewall rules differ from the plan: $($Policy.Name) [$id]" }
    [pscustomobject]@{
        PolicyId = $id.ToString(); Name = $Policy.Name; RuleCount = $Policy.RuleCount
        SettingsMatch = $true; AssignmentCount = 0; IsAssigned = $false
        AssignmentEvidence = 'All pages of the policy assignments endpoint returned zero records'
        MetadataAssignmentFlagPresent = $hasAssignmentFlag
        Validation = 'Cloud configuration round-trip only; endpoint enforcement not tested'
    }
}

function Publish-TrellixFirewallPlan {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory)][string]$PlanPath, [Parameter(Mandatory)][string]$ReceiptPath)
    $plan = Read-TrellixPlan -Path $PlanPath
    Assert-TrellixGraphContext -ExpectedTenantId $plan.TargetTenantId
    Assert-TrellixLiveTemplate -Plan $plan
    $receipt = Read-TrellixReceipt -Path $ReceiptPath -PlanPath $PlanPath -Plan $plan -AllowNew
    foreach ($policy in $plan.Policies) {
        $filter = [uri]::EscapeDataString("name eq '$($policy.Name.Replace("'", "''"))'")
        $existing = @(Get-TrellixGraphCollection -Path "/deviceManagement/configurationPolicies?`$filter=$filter")
        $entries = @($receipt.Policies | Where-Object Name -eq $policy.Name)
        if ($existing.Count -gt 1) { throw "Duplicate policy names require manual review: $($policy.Name)" }
        if ($existing.Count -eq 1) {
            $id = [string]$existing[0].id
            if ($entries.Count -eq 1 -and ($entries[0].PolicyId -ne $id -or $entries[0].Status -eq 'Deleted')) {
                throw 'The current policy identity conflicts with the receipt.'
            }
            $result = Assert-TrellixStoredPolicy -Policy $policy -PolicyId $id
            if (-not $WhatIfPreference) {
                if ($entries.Count -eq 0) {
                    $receipt.Policies += @{
                        Name = $policy.Name; PolicyId = $id; CreatedByThisReceipt = $false; Status = 'Verified'
                    }
                }
                else { $entries[0].Status = 'Verified' }
                Write-TrellixJson -Value $receipt -Path $ReceiptPath
            }
            $result | Add-Member -NotePropertyName Disposition -NotePropertyValue 'ReusedExactUnassignedMatch' -PassThru
            continue
        }
        if ($entries.Count -ne 0) { throw 'A policy recorded in the receipt is missing. Refusing automatic replacement.' }
        if (-not $PSCmdlet.ShouldProcess("$($plan.TargetTenantId) / $($policy.Name)", 'Create UNASSIGNED Firewall Rules policy')) { continue }
        try {
            $created = Invoke-TrellixGraph -Method POST -Path '/deviceManagement/configurationPolicies' -Body $policy.Body
        }
        catch {
            $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            throw [InvalidOperationException]::new(
                "Create did not complete successfully for '$($policy.Name)'. No automatic POST retry was attempted. Check the portal; a rerun verifies an exact existing match. $detail", $_.Exception)
        }
        $id = [string]$created.id
        $validId = [guid]::Empty
        if (-not [guid]::TryParse($id, [ref]$validId) -or $validId -eq [guid]::Empty) {
            throw 'The create response did not contain a valid policy ID. Inspect the portal before rerunning.'
        }
        Write-Host "Created unassigned policy $id ($($policy.Name)); saving its receipt."
        $entry = @{
            Name = $policy.Name; PolicyId = $id; CreatedByThisReceipt = $true
            Status = 'CreatedPendingVerification'; CreatedAt = [DateTimeOffset]::UtcNow.ToString('o')
        }
        $receipt.Policies += $entry
        Write-TrellixJson -Value $receipt -Path $ReceiptPath
        $result = Assert-TrellixStoredPolicy -Policy $policy -PolicyId $id
        $entry.Status = 'Verified'
        Write-TrellixJson -Value $receipt -Path $ReceiptPath
        $result | Add-Member -NotePropertyName Disposition -NotePropertyValue 'CreatedAndVerified' -PassThru
    }
}

function Test-TrellixFirewallPolicies {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PlanPath, [Parameter(Mandatory)][string]$ReceiptPath)
    $plan = Read-TrellixPlan -Path $PlanPath
    Assert-TrellixGraphContext -ExpectedTenantId $plan.TargetTenantId
    $receipt = Read-TrellixReceipt -Path $ReceiptPath -PlanPath $PlanPath -Plan $plan
    if (@($receipt.Policies).Count -ne @($plan.Policies).Count) { throw 'The receipt does not contain every planned policy.' }
    foreach ($policy in $plan.Policies) {
        $entries = @($receipt.Policies | Where-Object Name -eq $policy.Name)
        if ($entries.Count -ne 1 -or $entries[0].Status -eq 'Deleted') { throw 'A planned policy has no active receipt entry.' }
        Assert-TrellixStoredPolicy -Policy $policy -PolicyId $entries[0].PolicyId
    }
}

function Remove-TrellixFirewallTestPolicies {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$PlanPath, [Parameter(Mandatory)][string]$ReceiptPath)
    $plan = Read-TrellixPlan -Path $PlanPath
    Assert-TrellixGraphContext -ExpectedTenantId $plan.TargetTenantId
    $receipt = Read-TrellixReceipt -Path $ReceiptPath -PlanPath $PlanPath -Plan $plan
    foreach ($entry in $receipt.Policies) {
        if ($entry.Status -eq 'Deleted') { continue }
        if (-not $entry.Name.StartsWith('Trellix GCCH TEST - ', [StringComparison]::Ordinal) -or
            $entry.CreatedByThisReceipt -isnot [bool] -or -not $entry.CreatedByThisReceipt) {
            throw 'Cleanup is limited to TEST-prefixed policies created by this exact receipt.'
        }
        $policies = @($plan.Policies | Where-Object Name -eq $entry.Name)
        if ($policies.Count -ne 1) { throw 'The cleanup identity does not match exactly one planned policy.' }
        $filter = [uri]::EscapeDataString("id eq '$($entry.PolicyId)'")
        $lookupPath = "/deviceManagement/configurationPolicies?`$filter=$filter"
        $existing = @(Get-TrellixGraphCollection -Path $lookupPath)
        if ($existing.Count -gt 1 -or @($existing | Where-Object id -ne $entry.PolicyId).Count -gt 0) {
            throw 'The exact-ID cleanup lookup returned an unexpected policy identity.'
        }
        if ($existing.Count -eq 0) {
            if (-not $WhatIfPreference) {
                $entry.Status = 'Deleted'
                Write-TrellixJson -Value $receipt -Path $ReceiptPath
            }
            [pscustomobject]@{
                PolicyId = $entry.PolicyId; Name = $entry.Name; DeletedAndVerified = $true
                Disposition = 'AlreadyAbsent'; DeletionEvidence = 'Exact receipt ID absent from the policy collection'
            }
            continue
        }
        $null = Assert-TrellixStoredPolicy -Policy $policies[0] -PolicyId $entry.PolicyId
        if (-not $PSCmdlet.ShouldProcess("$($plan.TargetTenantId) / $($entry.Name) / $($entry.PolicyId)", 'Delete verified UNASSIGNED test policy')) { continue }
        $null = Invoke-TrellixGraph -Method DELETE -Path "/deviceManagement/configurationPolicies/$($entry.PolicyId)"
        if (@(Get-TrellixGraphCollection -Path $lookupPath).Count -ne 0) {
            throw "The delete request returned, but policy $($entry.PolicyId) is still present in the policy collection."
        }
        $entry.Status = 'Deleted'
        Write-TrellixJson -Value $receipt -Path $ReceiptPath
        [pscustomobject]@{
            PolicyId = $entry.PolicyId; Name = $entry.Name; DeletedAndVerified = $true
            Disposition = 'Deleted'; DeletionEvidence = 'Exact receipt ID absent from the policy collection after DELETE'
        }
    }
}

Export-ModuleMember -Function Connect-TrellixGcch, Disconnect-TrellixGcch, Get-TrellixFirewallSchema,
    New-TrellixFirewallApproval, New-TrellixFirewallPlan, Publish-TrellixFirewallPlan,
    Test-TrellixFirewallPolicies, Remove-TrellixFirewallTestPolicies
