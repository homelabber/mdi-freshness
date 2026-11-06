<#
.SYNOPSIS
  Exports the repo (write-up, custom detections, hunting queries and workbook tiles) to a single,
  self-contained HTML file for offline review, change boards or sharing with people who don't live in Git.

.DESCRIPTION
  Reads AD-Detection-Gaps-2026.md, detections\rules.json and the .kql files, dashboards\hunting\*.kql and
  dashboards\AD-Gap-Workbook.json, and writes one HTML file with inline CSS/JS (no external resources).
  The page has a filter box, copy buttons for every query and flags any rule whose // TUNE lists are still empty.

  The write-up is rendered with ConvertFrom-Markdown (PowerShell 7+). On Windows PowerShell 5.1 it is
  included as preformatted text instead.

.EXAMPLE
  .\Export-Html.ps1
  .\Export-Html.ps1 -OutputPath C:\temp\ad-visibility.html -Open
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'export\mdi-freshness.html'),
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
function Enc([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }
function Get-Untuned([string]$kql) {
    [regex]::Matches($kql, '(?m)^let\s+(\w+)\s*=\s*dynamic\(\[\]\);\s*//\s*TUNE') | ForEach-Object { $_.Groups[1].Value }
}
function Slug([string]$s) { ($s.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-') }
function QueryBlock([string]$id, [string]$kql) {
    "<div class=""code""><button class=""copy"" data-target=""$id"">Copy</button><pre id=""$id""><code>$(Enc $kql.TrimEnd())</code></pre></div>"
}

$root = $PSScriptRoot
$reportPath = Join-Path $root 'AD-Detection-Gaps-2026.md'
$rules = Get-Content -LiteralPath (Join-Path $root 'detections\rules.json') -Raw | ConvertFrom-Json
$workbook = Get-Content -LiteralPath (Join-Path $root 'dashboards\AD-Gap-Workbook.json') -Raw | ConvertFrom-Json
$hunting = Get-ChildItem -LiteralPath (Join-Path $root 'dashboards\hunting') -Filter *.kql | Sort-Object Name

# Write-up
$md = Get-Content -LiteralPath $reportPath -Raw
if (Get-Command ConvertFrom-Markdown -ErrorAction SilentlyContinue) {
    $reportHtml = ($md | ConvertFrom-Markdown).Html
} else {
    Write-Warning 'ConvertFrom-Markdown not available (needs PowerShell 7+); embedding the write-up as plain text.'
    $reportHtml = "<pre class=""plain"">$(Enc $md)</pre>"
}

# Detections
$untunedTotal = 0
$detRows = foreach ($r in $rules) {
    $kql = Get-Content -LiteralPath (Join-Path $root "detections\$($r.file)") -Raw
    $untuned = @(Get-Untuned $kql)
    $untunedTotal += [int]($untuned.Count -gt 0)
    $id = Slug $r.file
    $tune = if ($untuned) { "<span class=""badge warn"" title=""Empty TUNE lists"">TUNE: $(Enc ($untuned -join ', '))</span>" } else { '' }
    $opt = if (-not $r.deploy) { '<span class="badge opt">optional</span>' } else { '' }
    $mitre = ($r.mitreTechniques | ForEach-Object { "<a href=""https://attack.mitre.org/techniques/$($_ -replace '\.', '/')/"">$(Enc $_)</a>" }) -join ' '
    @"
<details class="item" id="$id" data-search="$(Enc ("$($r.displayName) $($r.category) $($r.mitreTechniques -join ' ') $($r.description)".ToLowerInvariant()))">
<summary><span class="sev $($r.severity)">$(Enc $r.severity)</span> $(Enc $r.displayName) $opt $tune</summary>
<dl>
<dt>File</dt><dd><code>detections\$(Enc $r.file)</code></dd>
<dt>Category</dt><dd>$(Enc $r.category)</dd>
<dt>MITRE</dt><dd>$mitre</dd>
<dt>Frequency</dt><dd>$(Enc $r.period)</dd>
<dt>Entities</dt><dd>$(Enc (($r.impactedAssets | ForEach-Object { "$($_.type):$($_.identifier)" }) -join ', '))</dd>
<dt>Description</dt><dd>$(Enc $r.description)</dd>
<dt>Response</dt><dd>$(Enc $r.recommendedActions)</dd>
</dl>
$(QueryBlock "q-$id" $kql)
</details>
"@
}

# Hunting queries
$huntRows = foreach ($h in $hunting) {
    $kql = Get-Content -LiteralPath $h.FullName -Raw
    $title = ($kql -split "`r?`n" | Where-Object { $_ -match '^\s*//' } | Select-Object -First 1) -replace '^\s*//\s*', ''
    if (-not $title) { $title = $h.BaseName }
    $id = Slug $h.Name
    @"
<details class="item" id="$id" data-search="$(Enc ("$($h.Name) $title".ToLowerInvariant()))">
<summary><code>$(Enc $h.Name)</code> &ndash; $(Enc $title)</summary>
$(QueryBlock "q-$id" $kql)
</details>
"@
}

# Workbook tiles
$tiles = @($workbook.items | Where-Object { $_.type -eq 3 })
$tileRows = foreach ($t in $tiles) {
    $id = Slug "tile-$($t.name)"
    $title = if ($t.content.title) { $t.content.title } else { $t.name }
    @"
<details class="item" id="$id" data-search="$(Enc $title.ToLowerInvariant())">
<summary>$(Enc $title) <span class="badge">$(Enc $t.content.visualization)</span></summary>
$(QueryBlock "q-$id" $t.content.query)
</details>
"@
}

$generated = Get-Date -Format 'yyyy-MM-dd HH:mm zzz'
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mdi-freshness &ndash; AD visibility layer for Defender for Identity</title>
<style>
:root{--bg:#fff;--fg:#1b1b1b;--muted:#5f6368;--line:#e1e4e8;--accent:#0f6cbd;--code:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#161b22;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--accent:#4aa3ff;--code:#0d1117}}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:20px 32px;border-bottom:1px solid var(--line)}header h1{margin:0 0 4px;font-size:1.5em}header p{margin:0;color:var(--muted)}
nav{position:sticky;top:0;z-index:2;display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:10px 32px;background:var(--bg);border-bottom:1px solid var(--line)}
nav a{color:var(--accent);text-decoration:none;font-weight:600}nav input{margin-left:auto;padding:6px 10px;min-width:260px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
main{max-width:1200px;margin:0 auto;padding:8px 32px 48px}section{margin-top:28px}h2{border-bottom:1px solid var(--line);padding-bottom:4px}
a{color:var(--accent)}table{border-collapse:collapse;width:100%;margin:12px 0;font-size:.93em}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--code)}
code{font-family:Consolas,"Cascadia Mono",monospace;font-size:.92em}pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:12px;overflow:auto;margin:0}
.item{border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:0 14px}.item[open]{padding-bottom:12px}.item summary{cursor:pointer;padding:10px 0;font-weight:600}
dl{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;margin:4px 0 12px}dt{color:var(--muted)}dd{margin:0}
.code{position:relative}.copy{position:absolute;top:6px;right:6px;padding:3px 10px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg);cursor:pointer}
.badge{display:inline-block;font-size:.75em;font-weight:600;padding:1px 8px;border-radius:10px;border:1px solid var(--line);color:var(--muted);margin-left:6px}
.badge.warn{border-color:#d29922;color:#d29922}.badge.opt{border-style:dashed}
.sev{display:inline-block;min-width:62px;text-align:center;font-size:.75em;text-transform:uppercase;padding:1px 6px;border-radius:4px;color:#fff;margin-right:6px}
.sev.high{background:#c42b1c}.sev.medium{background:#bc6c00}.sev.low{background:#5c7e10}.sev.informational{background:#5f6368}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-top:12px}.stat{border:1px solid var(--line);border-radius:8px;padding:8px 14px}.stat b{display:block;font-size:1.4em}
.hidden{display:none}.plain{white-space:pre-wrap}footer{color:var(--muted);font-size:.85em;padding:24px 32px;border-top:1px solid var(--line)}
@media print{nav,.copy{display:none}details{display:block}details>*{display:block}}
</style>
</head>
<body>
<header>
<h1>mdi-freshness</h1>
<p>An extra visibility layer for Microsoft Defender for Identity &ndash; built on telemetry MDI and Defender for Endpoint already collect.</p>
<div class="stats">
<div class="stat"><b>$($rules.Count)</b>custom detections</div>
<div class="stat"><b>$($hunting.Count)</b>hunting queries</div>
<div class="stat"><b>$($tiles.Count)</b>workbook tiles</div>
<div class="stat"><b>$untunedTotal</b>rules with empty TUNE lists</div>
</div>
</header>
<nav>
<a href="#detections">Detections</a><a href="#hunting">Hunting</a><a href="#tiles">Workbook tiles</a><a href="#report">Write-up</a>
<input id="filter" type="search" placeholder="Filter by name, MITRE ID, category&hellip;" aria-label="Filter">
</nav>
<main>
<section id="detections"><h2>Custom detections</h2>
<p>Deploy with <code>Deploy-CustomDetections.ps1</code>. Rules flagged <span class="badge warn">TUNE</span> still have empty allow-lists.</p>
$($detRows -join "`n")
</section>
<section id="hunting"><h2>Advanced Hunting queries</h2>
$($huntRows -join "`n")
</section>
<section id="tiles"><h2>Workbook tiles</h2>
<p>From <code>dashboards\AD-Gap-Workbook.json</code> (Sentinel syntax: <code>TimeGenerated</code>, <code>{TimeRange}</code> and workbook parameters).</p>
$($tileRows -join "`n")
</section>
<section id="report"><h2>Write-up</h2>
$reportHtml
</section>
</main>
<footer>Generated $(Enc $generated) by Export-Html.ps1 &middot; Not validated against a live tenant &ndash; tune before enabling.</footer>
<script>
document.querySelectorAll('.copy').forEach(function(b){b.addEventListener('click',function(){
var t=document.getElementById(b.dataset.target).innerText;navigator.clipboard.writeText(t).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy'},1500)})})});
document.getElementById('filter').addEventListener('input',function(e){var q=e.target.value.toLowerCase().trim();
document.querySelectorAll('.item').forEach(function(i){i.classList.toggle('hidden',q!==''&&i.dataset.search.indexOf(q)<0&&i.innerText.toLowerCase().indexOf(q)<0)})});
window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=true})});
</script>
</body>
</html>
"@

$dir = Split-Path -Parent $OutputPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
[System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
Write-Host "Exported $($rules.Count) detections, $($hunting.Count) hunting queries and $($tiles.Count) tiles to $OutputPath"
if ($Open) { Invoke-Item -LiteralPath $OutputPath }
