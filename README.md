# mdi-freshness

> Defender for Identity already keeps an eye on your domain controllers. This repo gives it some extra perspectives.

**mdi-freshness** is a set of add-on detections, hunting queries and a dashboard for on-prem Active Directory. It is built entirely on telemetry that **Microsoft Defender for Identity (MDI)** and **Defender for Endpoint** on your DCs already collect. Think of it as a seasonal menu next to a kitchen that already knows its classics. MDI's built-in alerts handle the staples (DCSync, Golden Tickets, Kerberoasting, NTLM relay, password spray). These rules add 2026 tradecraft and the multi-step playbooks Microsoft Threat Intelligence has documented this year.

No new agents, sensors or licences. You only ask better questions of data you already have.

## What's in the box

| Path | What it does |
|---|---|
| [`AD-Detection-Gaps-2026.md`](AD-Detection-Gaps-2026.md) | The write-up: each technique, its 2026 evidence, how it relates to built-in MDI alerts, the KQL and sources. |
| `detections\01a`–`12` | **14 "AD Visibility" rules**. They cover 2026 techniques such as GPO-delivered ransomware, ResetNightmare/KerberLoss-style abuse, AD FS DKM ACL changes, edge-device service accounts, gMSA/LAPS reads and more. |
| `detections\13`–`19` | **7 "AD Sequence" rules**. These are multi-step attack chains from Microsoft Threat Intelligence reporting, stitched into a single alert (details below). |
| `detections\rules.json` | Rule metadata (names, severity, MITRE mapping, deploy flags). |
| `Deploy-CustomDetections.ps1` | Creates the rules in Defender XDR through Microsoft Graph. Supports `-WhatIf`, `-Enable` and `-IncludeOptional`. |
| `dashboards\AD-Gap-Workbook.json` | Sentinel workbook with **10 tiles**: crypto/NTLM posture, edge-account activity, LAPS/gMSA reads, plus the sequence views listed below. |
| `dashboards\hunting\` | **12 Advanced Hunting queries**: the same views for tenants without Sentinel, plus an ActionType discovery helper. |

## The sequences (Microsoft Threat Intelligence, Mar–Sep 2026)

Individually, most of these steps look like a normal Tuesday for an admin. In this order, on these hosts, they look much less normal.

| # | Chain | Seen with |
|---|---|---|
| 13 | RMM or tunnel tool lands on a DC → NTDS.dit / hive extraction within 24h | Storm-2570, Storm-1175 (Medusa) |
| 14 | Scheduled task created on a DC → ntdsutil/archiver runs → task deleted within 15 min | Microsoft domain-compromise case studies |
| 15 | GPO edited → payload **and** trigger dropped in that policy's SYSVOL folder | GPO-ransomware case study, Storm-1175 |
| 16 | Privileged account's password reset by someone else → that account signs in | Domain-compromise case study |
| 17 | wmiexec/atexec/psexec/smbexec/WinRM into Entra Connect | Domain-compromise and high-value-asset posts |
| 18 | Defender tampered with on a DC → mass deployment (PsExec `@list`, PDQ, remote GPUpdate) | Storm-2570, Storm-1175 |
| 19 | Fake help-desk Quick Assist/MSI session → AD recon or WinRM toward Tier 0 | Teams IT-support impersonation campaign |

Single steps that MDI or MDE already alert on (spray, Kerberoasting, remote code execution on a DC, suspicious service creation, NTLM relay, Defender-disabling GPOs, Entra Connect auth anomalies) are deliberately not duplicated.

**New dashboard tiles:** AD kill-chain progression (accounts reaching 3+ stages in a week), RMM/tunnel tools on Tier 0, privileged password resets by actor, and inbound WinRM/RDP to Tier 0.

## Quick start

1. **Calibrate.** Run `dashboards\hunting\00-discover-action-types.kql` and align the string matches with what your sensors actually emit.
2. **Tune.** Fill in every `// TUNE` list: `GpoAdmins`, `EdgeAccounts`/`EdgeIPs`, `ApprovedJoiners`, `KnownDelegationTargets`, `TrustAccounts`, `ExtraDCs`, `ApprovedReaders`, `ApprovedRmm`, `ApprovedResetters`, `ExtraEntraConnect` and `TierZeroExtra`. Empty allow-lists are honest, but loud.
3. **Rehearse.** Run each query in Advanced Hunting over 30 days, swapping `ago(1h)` for `ago(30d)`.
4. **Deploy.**
   ```powershell
   Unblock-File .\Deploy-CustomDetections.ps1
   .\Deploy-CustomDetections.ps1 -WhatIf -IncludeOptional
   .\Deploy-CustomDetections.ps1 -IncludeOptional          # rules are created disabled
   ```
   Add `-Enable` once you're happy with the noise level.
5. **Dashboard.** In Sentinel, go to Workbooks → Add → Advanced editor and paste `AD-Gap-Workbook.json`. This needs the Defender XDR connector to stream the Identity* tables. No Sentinel? Save the `dashboards\hunting` queries as shared Advanced Hunting queries.

## Upgrading from an earlier version

Rules used to be named **"AD Gap N"**. They are now **"AD Visibility N"** (and **"AD Sequence N"** for the new chains). The deploy script skips rules by display name, so it will create the renamed rules alongside the old ones. Delete the old "AD Gap" rules in Defender XDR to avoid double alerts.

## Requirements

- MDI sensor v3.x on DCs (and on AD CS/AD FS servers where relevant), with automatic Windows auditing and directory-change (5136) auditing enabled.
- Defender for Endpoint on DCs and Tier-0 servers, for the process, file, registry and network sequences.
- To deploy: a Graph app or user with `CustomDetection.ReadWrite.All`.

## Fine print

> ⚠️ **Not tested against a live tenant.** Every query parses cleanly with Kusto.Language against an Identity*/Device* schema, and the deploy script builds all 21 payloads in `-WhatIf` mode. MDI `ActionType` and `AdditionalFields` values are not fully documented, so expect to tweak them. Run in audit mode first, tune, then enable. Use at your own risk; no warranty, express, implied or Kerberos-signed.

## Sources

See the [Sources section](AD-Detection-Gaps-2026.md#sources) of the write-up. It covers the MDI alert catalog, CISA/ASD guidance, vendor research, and the Microsoft Threat Intelligence and Microsoft Security blog posts behind sequences 13–19.
