# mdi-freshness

Custom detections and dashboards for Active Directory attacker tradecraft seen Feb–Oct 2026 that Microsoft Defender for Identity (MDI) does not alert on out of the box, even though MDI (or Defender for Endpoint on DCs) already collects the telemetry.

- **[AD-Detection-Gaps-2026.md](AD-Detection-Gaps-2026.md)** – the gap analysis (12 gaps, what's already covered, what has no telemetry, sources).
- **`detections\`** – 14 Defender XDR custom-detection queries + `rules.json` metadata.
- **`Deploy-CustomDetections.ps1`** – creates the rules via Microsoft Graph (`-WhatIf`, `-Enable`, `-IncludeOptional`).
- **`dashboards\AD-Gap-Workbook.json`** – Sentinel workbook (RC4/encryption posture, NTLM downgrade, edge-account activity, LAPS/gMSA reads).
- **`dashboards\hunting\`** – the same tiles as Advanced Hunting queries, plus ActionType discovery.

## Quick start
1. Run `dashboards\hunting\00-discover-action-types.kql` and align string matches to what your sensors emit.
2. Fill in every `// TUNE` list in `detections\*.kql`.
3. Test each query in Advanced Hunting over 30 days.
4. `.\Deploy-CustomDetections.ps1 -WhatIf`, then run it (rules are created disabled unless `-Enable`).

> ⚠️ Not validated against a live tenant. Queries parse cleanly with Kusto.Language; MDI `ActionType`/`AdditionalFields` values are undocumented and may need adjustment. Use at your own risk.
