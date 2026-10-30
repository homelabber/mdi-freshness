<#
.SYNOPSIS
  Creates the AD visibility-layer custom detection rules in Microsoft Defender XDR through the Microsoft Graph
  (beta) security/rules/detectionRules API.

.DESCRIPTION
  Reads detections\rules.json and the matching .kql files. Rules are created DISABLED unless -Enable
  is passed, so they can be reviewed in the Defender portal first. Rules whose display name already
  exists are skipped. Use -WhatIf to print the request bodies without calling Graph.

  Requires the Microsoft.Graph.Authentication module and the CustomDetection.ReadWrite.All permission.

.EXAMPLE
  .\Deploy-CustomDetections.ps1 -WhatIf
  .\Deploy-CustomDetections.ps1
  .\Deploy-CustomDetections.ps1 -Enable -IncludeOptional
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Enable,
    [switch]$IncludeOptional,
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'
$ruleDir = Join-Path $PSScriptRoot 'detections'
$rules = Get-Content -LiteralPath (Join-Path $ruleDir 'rules.json') -Raw | ConvertFrom-Json
$endpoint = 'https://graph.microsoft.com/beta/security/rules/detectionRules'

$selected = @($rules | Where-Object { $_.deploy -or $IncludeOptional })

$existing = @()
if (-not $WhatIfPreference) {
    if (-not (Get-MgContext)) {
        $connect = @{ Scopes = 'CustomDetection.ReadWrite.All'; NoWelcome = $true }
        if ($TenantId) { $connect.TenantId = $TenantId }
        Connect-MgGraph @connect
    }
    $uri = $endpoint
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri
        $existing += $page.value | ForEach-Object { $_.displayName }
        $uri = $page.'@odata.nextLink'
    }
}

foreach ($rule in $selected) {
    $query = Get-Content -LiteralPath (Join-Path $ruleDir $rule.file) -Raw

    $untuned = [regex]::Matches($query, '(?m)^let\s+(\w+)\s*=\s*dynamic\(\[\]\);\s*//\s*TUNE') | ForEach-Object { $_.Groups[1].Value }
    if ($untuned) {
        Write-Warning "$($rule.displayName): placeholder list(s) still empty: $($untuned -join ', '). Edit $($rule.file) before enabling."
    }

    if ($rule.displayName -in $existing) {
        Write-Host "SKIP (exists): $($rule.displayName)"
        continue
    }

    $assets = foreach ($a in $rule.impactedAssets) {
        @{
            '@odata.type' = if ($a.type -eq 'device') { '#microsoft.graph.security.impactedDeviceAsset' } else { '#microsoft.graph.security.impactedUserAsset' }
            identifier    = $a.identifier
        }
    }

    $body = @{
        displayName     = $rule.displayName
        isEnabled       = [bool]$Enable
        queryCondition  = @{ queryText = $query }
        schedule        = @{ period = $rule.period }
        detectionAction = @{
            alertTemplate = @{
                title              = $rule.displayName
                description        = $rule.description
                severity           = $rule.severity
                category           = $rule.category
                recommendedActions = $rule.recommendedActions
                mitreTechniques    = @($rule.mitreTechniques)
                impactedAssets     = @($assets)
            }
            organizationalScope = $null
            responseActions     = @()
        }
    } | ConvertTo-Json -Depth 10

    if ($PSCmdlet.ShouldProcess($rule.displayName, 'Create custom detection rule')) {
        $created = Invoke-MgGraphRequest -Method POST -Uri $endpoint -Body $body -ContentType 'application/json'
        Write-Host "CREATED: $($rule.displayName) (id $($created.id), enabled=$([bool]$Enable))"
    } else {
        Write-Host "---- $($rule.displayName) ----"
        Write-Host $body
    }
}
