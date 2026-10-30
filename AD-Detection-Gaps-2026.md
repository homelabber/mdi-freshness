# Defender for Identity – an extra visibility layer for 2026 Active Directory tradecraft

MDI already alerts on the classics (DCSync, Golden Ticket, Kerberoasting, NTLM relay, password spray and friends). This document adds a second lens: custom detections and dashboards built on the **same telemetry MDI and Defender for Endpoint already collect**, tuned to techniques disclosed in 2026 and to the multi-step sequences Microsoft Threat Intelligence has reported. Think of it as extra cameras in rooms MDI already watches, not a replacement for the security system.

**Scope:** On-premises AD tradecraft observed or disclosed **Feb–Oct 2026**, mapped against the current MDI alert catalog (classic + XDR-format, `alerts-overview`, Oct 2026), restricted to items where MDI (sensor v3.x) or the MDE agent on DCs already emits telemetry into Advanced Hunting.

> ⚠️ MDI is not an audit log. `ActionType` strings and `AdditionalFields` keys vary by sensor version and are not fully documented. Run **Query 0** first and adjust string matches to what your tenant actually emits. Every query below is written to be tolerant (`has`/`contains`) rather than exact.

---

## Summary table

| # | Technique | 2026 evidence | How it relates to built-in MDI alerts | Telemetry | Recommended use |
|---|---|---|---|---|---|
| 1 | **Malicious GPO creation / domain-root link** (impact or ransomware delivery via GPO) | Kaspersky GERT “PAYLOAD” GPO extortion (Apr 2026 incident, pub. 21 Sep 2026); Five Eyes AD guidance (Sep 2026) | **Extends** – only *Group Policy Tampering* (GPO that disables Defender AV) | `IdentityDirectoryEvents` (GPO events, enriched May 2026 sensor), `DeviceFileEvents` on DCs (SYSVOL writes) | Custom detection (High) |
| 2 | **ResetNightmare – CVE-2026-27912** (UPN set to another account’s sAMAccountName → kpasswd reset of DA) | Semperis disclosure (Aug 2026), public PoC `ResetNightmare.ps1`; patched Apr 2026 | **New angle** (MDI has *sAMAccountName* change, not UPN collision) | `IdentityDirectoryEvents` UPN changes + `IdentityInfo` | Custom detection (High) |
| 3 | **KerberLoss – CVE-2026-25177** (invisible-Unicode duplicate SPN/UPN → Kerberos failure / NTLM downgrade) | Semperis (Aug 2026); patched Mar 2026 | **New angle** (XDR *Suspicious SPN added* targets Kerberoasting, not Unicode collisions) | `IdentityDirectoryEvents`, `IdentityLogonEvents` (NTLM fallback) | Custom detection + dashboard |
| 4 | **Edge-device service-account abuse** (firewall/VPN LDAP bind account used for AD recon or logons) | CL-STA-1132 via PAN-OS CVE-2026-0300; Qilin affiliates post-VPN; PAYLOAD actor via FortiGate SSL VPN | **Extends** – generic LDAP/SAMR recon alerts are learning-based and don’t treat appliance accounts specially | `IdentityQueryEvents`, `IdentityLogonEvents` | Custom detection (watch-list) + dashboard |
| 5 | **AD FS DKM container ACL change – CVE-2026-56155** (KEV 14 Jul 2026) | CISA KEV; Alastor write-up | **Extends** – *AD FS DKM key read* and *Golden SAML* fire on read/use, not on the ACL grant that precedes it | `IdentityDirectoryEvents` (permission changes), MDI sensor on AD FS | Custom detection (High) |
| 6 | **MachineAccountQuota abuse** (non-admin creates computer objects) | Five Eyes guidance (Sep 2026); prerequisite for RBCD, ResetNightmare, Certighost chains | **Extends** – XDR *device addition on-premises*/RBCD alerts fire on later stages | `IdentityDirectoryEvents` `Device Account Created` | Custom detection (Medium) |
| 7 | **Delegation / pre-auth flag flips** (unconstrained or constrained delegation set; DONT_REQ_PREAUTH set → targeted AS-REP roast) | Five Eyes guidance; Secureware 2026 assessments (AS-REP → DA in 4h) | **Extends** – MDI alerts on *new computer unconstrained delegation*, RBCD, and AS-REP roasting traffic, not on user/service-account flag changes | `IdentityDirectoryEvents` account-attribute changes | Custom detection (Medium/High) |
| 8 | **Non-default privileged group additions** (DnsAdmins, Cert Publishers, ESX-admin look-alikes, Exchange Windows Permissions, Hyper-V Admins, etc.) | Ransomware ESXi takeover pattern continues in 2026 (PAYLOAD ESXi locker) | **Extends** – *sensitive group addition* only covers groups tagged sensitive | `IdentityDirectoryEvents` `Group Membership changed` | Custom detection (watch-list) |
| 9 | **NTDS.dit / IFM / VSS extraction on DCs** | Five Eyes guidance (Sep 2026) | **New angle** – adds DC-specific logic alongside generic MDE behaviour alerts | `DeviceProcessEvents` on DCs (MDE is co-installed with sensor v3.x) | Custom detection (High) |
| 10 | **Trust account (TDO) abuse** – one-way trust bypass using `TRUSTEDDOMAIN$` | Five Eyes guidance (Sep 2026) | **New angle** | `IdentityLogonEvents` | Custom detection (High) |
| 11 | **RC4 / encryption-type downgrade posture** | RC4 deprecation; KerberLoss downgrade; Five Eyes (4768/4769) | **Extends** – golden-ticket *encryption downgrade* only | `IdentityDirectoryEvents` (`Supported Encryption Types changed`), `IdentityLogonEvents` | Dashboard |
| 12 | **LAPS / gMSA password attribute reads** by unexpected principals | Secureware 2026 (“LAPS bypass”); Golden gMSA | **Extends** – XDR *sensitive attribute LDAP query* is anomaly-based | `IdentityQueryEvents` | Dashboard + optional detection |

**Out of scope – outside what the sensors record (noted, not built):** Timeroasting (unauthenticated NTP/MS-SNTP – not captured), Silver tickets (no TGS on the DC by design; only indirect PAC-validation signals), GPP `cpassword` reads from SYSVOL (MDI doesn’t log SMB file reads; MDE only sees tooling on the source host).

Already handled by built-in MDI alerts (deliberately not duplicated): Certighost CVE-2026-54121, BadSuccessor/dMSA, Golden gMSA, ESC1/8/11/15, shadow credentials, DCSync, NetSync, diamond ticket, CVE-2025-33073.

---

## Query 0 – Discover the ActionTypes your sensors emit

```kql
union IdentityDirectoryEvents, IdentityQueryEvents, IdentityLogonEvents
| where Timestamp > ago(14d)
| summarize Count = count(), SampleFields = take_any(AdditionalFields) by Type, ActionType
| order by Type, Count desc
```

---

## 1. Malicious GPO creation / domain-root link

```kql
// GPO object created/modified/linked by an account that isn't a known GPO admin
let GpoAdmins = dynamic(["svc-gpo-mgmt","admin.jdoe"]);   // tune
IdentityDirectoryEvents
| where Timestamp > ago(1h)
| where ActionType has_any ("Group Policy", "GPO", "gPLink")
    or tostring(AdditionalFields) has_any ("gPLink", "groupPolicyContainer", "gPCFileSysPath")
| where AccountName !in~ (GpoAdmins)
| extend AF = tostring(AdditionalFields)
| extend LinkedAtRoot = AF has "gPLink" and TargetDeviceName == "" and AF matches regex @"(?i)DC=[^,]+,DC=[^,]+$"
| project Timestamp, ActionType, AccountName, AccountDomain, DeviceName, DestinationDeviceName, LinkedAtRoot, AdditionalFields, ReportId
```

```kql
// Complementary (MDE on DCs): new files staged into SYSVOL Policies/scripts
DeviceFileEvents
| where Timestamp > ago(1h)
| where FolderPath has @"\SYSVOL\" and ActionType in ("FileCreated","FileModified")
| where FileName endswith_cs ".xml" or FileName has_any (".jpg",".png",".bat",".ps1",".exe",".txt","ScheduledTasks.xml","Files.xml","Registry.xml")
| where InitiatingProcessAccountName !in~ ("system")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, ReportId
```

## 2. ResetNightmare (CVE-2026-27912) – UPN collides with another account’s sAMAccountName

```kql
let Sams = IdentityInfo
    | where Timestamp > ago(14d)
    | summarize arg_max(Timestamp, *) by AccountObjectId
    | project VictimSam = tolower(AccountName), VictimUpn = AccountUpn, VictimIsSensitive = IsAccountEnabled;
IdentityDirectoryEvents
| where Timestamp > ago(1h)
| where ActionType has "Upn"
| extend NewUpn = tolower(tostring(AdditionalFields["TO Upn"])), OldUpn = tostring(AdditionalFields["FROM Upn"])
| extend NewUpn = iff(isempty(NewUpn), tolower(extract(@"(?i)TO[^:]*Upn""?\s*:\s*""([^""]*)", 1, tostring(AdditionalFields))), NewUpn)
| where isnotempty(NewUpn) and NewUpn !contains "@"          // bare UPN with no suffix is the key indicator
| join kind=inner Sams on $left.NewUpn == $right.VictimSam
| where tolower(TargetAccountUpn) != tolower(VictimUpn)
| project Timestamp, ActionType, ActorAccount = AccountName, TargetAccountUpn, NewUpn, OldUpn, CollidesWith = VictimUpn, ReportId
```

Hunt follow-up: a password change on the victim within ~1h after the UPN change, initiated by a different account (`ActionType has "Password"`).

## 3. KerberLoss (CVE-2026-25177) – invisible Unicode in UPN/SPN/name + NTLM fallback

```kql
// Zero-width / format / odd-space characters written to identity attributes
IdentityDirectoryEvents
| where Timestamp > ago(1h)
| where ActionType has_any ("Upn", "Name", "Spn", "Service Principal", "Account Created")
| extend AF = tostring(AdditionalFields)
| where AF matches regex @"[\x{00A0}\x{00AD}\x{034F}\x{061C}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180E}\x{2000}-\x{200F}\x{2028}-\x{202F}\x{205F}-\x{206F}\x{3000}\x{3164}\x{FEFF}\x{FFA0}]"
    or TargetAccountDisplayName matches regex @"[\x{200B}-\x{200F}\x{2060}-\x{206F}\x{FEFF}]"
| project Timestamp, ActionType, AccountName, TargetAccountUpn, TargetAccountDisplayName, AdditionalFields, ReportId
```

```kql
// Dashboard: services that suddenly switch from Kerberos to NTLM (downgrade symptom)
IdentityLogonEvents
| where Timestamp > ago(14d) and ActionType == "LogonSuccess"
| where isnotempty(DestinationDeviceName)
| summarize Krb = countif(Protocol =~ "Kerberos"), Ntlm = countif(Protocol =~ "Ntlm") by DestinationDeviceName, bin(Timestamp, 1d)
| extend NtlmRatio = round(todouble(Ntlm) / (Krb + Ntlm), 2)
| order by DestinationDeviceName asc, Timestamp asc
| serialize | extend PrevRatio = prev(NtlmRatio), PrevHost = prev(DestinationDeviceName)
| where PrevHost == DestinationDeviceName and PrevRatio < 0.1 and NtlmRatio > 0.5
```

## 4. Edge-device (firewall / VPN) service-account misuse

```kql
// Watch-list of accounts used by PAN-OS/FortiGate/Ivanti/Citrix for LDAP binds
let EdgeAccounts = dynamic(["svc-paloalto-ldap","svc-fortigate","svc-vpn-ldap"]);   // populate
let EdgeIPs = dynamic(["10.0.0.1","10.0.0.2"]);                                      // appliance IPs
let Baseline = IdentityQueryEvents
    | where Timestamp between (ago(30d) .. ago(1d)) and AccountName in~ (EdgeAccounts)
    | summarize by AccountName, QueryType, Query;
IdentityQueryEvents
| where Timestamp > ago(1h) and AccountName in~ (EdgeAccounts)
| join kind=leftanti Baseline on AccountName, QueryType, Query
| summarize NewQueries = dcount(Query), Samples = make_set(Query, 10), SrcIPs = make_set(IPAddress), Sources = make_set(DeviceName) by AccountName, bin(Timestamp, 1h)
| extend FromNonApplianceIP = set_difference(SrcIPs, EdgeIPs)
| where NewQueries >= 5 or array_length(FromNonApplianceIP) > 0
```

```kql
// Same accounts doing interactive/RDP/SMB logons anywhere = credential reuse
IdentityLogonEvents
| where Timestamp > ago(1h) and AccountName in~ (dynamic(["svc-paloalto-ldap","svc-fortigate","svc-vpn-ldap"]))
| where LogonType !in~ ("LDAP", "Ldap") or IPAddress !in (dynamic(["10.0.0.1","10.0.0.2"]))
| project Timestamp, AccountName, LogonType, Protocol, DeviceName, IPAddress, DestinationDeviceName, ActionType, ReportId
```

## 5. AD FS DKM container permission change (CVE-2026-56155)

```kql
IdentityDirectoryEvents
| where Timestamp > ago(1h)
| extend AF = tostring(AdditionalFields)
| where AF has @"CN=ADFS,CN=Microsoft,CN=Program Data"
| where ActionType has_any ("Permission", "ACL", "Security Descriptor", "nTSecurityDescriptor", "Owner")
    or AF has_any ("nTSecurityDescriptor", "ACE")
| project Timestamp, ActionType, AccountName, AccountDomain, DeviceName, AdditionalFields, ReportId
```
Pair with existing alerts: an MDI *AD FS DKM key read* or *Golden SAML* alert within 24h of this event is a confirmed chain.

## 6. MachineAccountQuota abuse

```kql
let PrivCreators = dynamic(["svc-sccm","svc-mdt","joinaccount"]);   // legit join accounts
IdentityDirectoryEvents
| where Timestamp > ago(1h) and ActionType == "Device Account Created"
| where AccountName !in~ (PrivCreators) and not(AccountName endswith "$")
| join kind=leftouter (IdentityInfo | summarize arg_max(Timestamp, Tags, AssignedRoles) by AccountName) on AccountName
| where not(tostring(Tags) has_any ("Sensitive", "Admin"))
| project Timestamp, Creator = AccountName, NewComputer = TargetDeviceName, DeviceName, IPAddress, AdditionalFields, ReportId
```

## 7. Delegation and Kerberos pre-auth flag changes

```kql
IdentityDirectoryEvents
| where Timestamp > ago(1h)
| where ActionType has_any ("Delegation", "Pre-auth", "Preauth", "Kerberos Pre", "Password Not Required", "User Account Control")
    or tostring(AdditionalFields) has_any ("TRUSTED_FOR_DELEGATION", "TrustedForDelegation", "DONT_REQ_PREAUTH", "DoesNotRequirePreAuth", "msDS-AllowedToDelegateTo", "TRUSTED_TO_AUTH_FOR_DELEGATION")
| where not(TargetDeviceName has_any ("DC"))      // DCs legitimately have unconstrained delegation; tune
| project Timestamp, ActionType, Actor = AccountName, TargetAccountUpn, TargetDeviceName, AdditionalFields, ReportId
```

## 8. Non-default privileged group additions

```kql
let WatchGroups = dynamic(["DnsAdmins","Cert Publishers","Exchange Windows Permissions","Exchange Trusted Subsystem",
    "Hyper-V Administrators","Remote Management Users","Event Log Readers","Group Policy Creator Owners",
    "ESX Admins","ESXi Admins","vSphere Admins","VMware Admins","Key Admins","Enterprise Key Admins","Protected Users"]);
IdentityDirectoryEvents
| where Timestamp > ago(1h) and ActionType == "Group Membership changed"
| extend ToGroup = tostring(AdditionalFields["TO.GROUP"]), FromGroup = tostring(AdditionalFields["FROM.GROUP"])
| where ToGroup has_any (WatchGroups) or ToGroup matches regex @"(?i)\b(esx|vcenter|vsphere|hyper-?v|backup|veeam|nutanix)\b.*admin"
| project Timestamp, Actor = AccountName, AddedAccount = TargetAccountUpn, TargetDeviceName, ToGroup, ReportId
```
(`Protected Users` is included for **removals** – check `FromGroup`.)

## 9. NTDS.dit / IFM / shadow-copy extraction on DCs (MDE)

```kql
let DCs = IdentityLogonEvents | where Timestamp > ago(7d) | distinct DestinationDeviceName | where isnotempty(DestinationDeviceName);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where DeviceName has_any (DCs) or DeviceName in~ (DCs)
| where (FileName =~ "ntdsutil.exe" and ProcessCommandLine has_any ("ifm", "create full", "snapshot"))
    or (FileName in~ ("vssadmin.exe","diskshadow.exe","wmic.exe") and ProcessCommandLine has_any ("create shadow", "shadowcopy", "/s"))
    or (ProcessCommandLine has_any (@"\Windows\NTDS\ntds.dit", "HarddiskVolumeShadowCopy") and ProcessCommandLine has_any ("copy","esentutl","robocopy","xcopy"))
    or (FileName =~ "esentutl.exe" and ProcessCommandLine has_all ("/y", "/vss"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, ReportId
```

## 10. Trust account (TDO) used as a normal account

```kql
// Populate with the NetBIOS names of trusted/trusting domains; trust accounts are <DOMAIN>$
let TrustAccounts = dynamic(["PARTNERDOM$","LEGACYDOM$"]);
IdentityLogonEvents
| where Timestamp > ago(1h)
| where AccountName in~ (TrustAccounts) or AccountSid endswith "-$"   // tune
| where Protocol in~ ("Kerberos","Ntlm")
| where LogonType !in~ ("Resource access")    // tune after baselining
| project Timestamp, AccountName, AccountDomain, Protocol, LogonType, DeviceName, IPAddress, DestinationDeviceName, ActionType, ReportId
```

## 11. Dashboard – RC4 / encryption-type posture

```kql
IdentityDirectoryEvents
| where Timestamp > ago(30d) and ActionType has "Encryption"
| extend NewValue = tostring(AdditionalFields["TO Supported Encryption Types"]), OldValue = tostring(AdditionalFields["FROM Supported Encryption Types"])
| summarize Changes = count(), LastChange = max(Timestamp), Values = make_set(NewValue) by TargetAccountUpn, TargetDeviceName, Actor = AccountName
| order by LastChange desc
```

## 12. Dashboard – LAPS / gMSA secret reads

```kql
IdentityQueryEvents
| where Timestamp > ago(7d) and QueryType has "Ldap"
| where Query has_any ("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msDS-ManagedPassword", "msDS-ManagedPasswordId")
| summarize Reads = count(), Targets = dcount(QueryTarget), SampleTargets = make_set(QueryTarget, 10) by AccountName, DeviceName, bin(Timestamp, 1d)
| order by Targets desc
```

---

## Threat-actor sequences (Microsoft Threat Intelligence, Mar–Sep 2026)

Microsoft's 2026 incident write-ups show that the individual steps are often familiar; what's distinctive is the **order** and the **host** they run on. MDI and MDE already alert on many single steps (password spray, Kerberoasting, remote code execution on a DC, suspicious service creation, NTLM relay, Defender-disabling GPOs, suspicious Entra Connect authentication), so those were left alone. The rules below stitch the steps together so the story arrives as one alert.

| # | Sequence | Reported by Microsoft for | Detection | Telemetry |
|---|---|---|---|---|
| 13 | RMM or tunnel tool (MeshAgent, Atera, Splashtop, ScreenConnect, AnyDesk, SimpleHelp, cloudflared, ngrok…) on a DC → NTDS.dit / hive extraction within 24h | Storm-2570 (Sep 2026); Storm-1175 / Medusa (Apr 2026) | `13-rmm-or-tunnel-on-dc-then-ntds.kql` (High) | `DeviceProcessEvents` |
| 14 | Scheduled task created on a DC → ntdsutil / makecab / archiver runs → task deleted within 15 min | Domain-compromise case (Apr 2026); high-value-asset protection (Mar 2026) | `14-hit-and-run-scheduled-task-on-dc.kql` (High) | `DeviceEvents`, `DeviceProcessEvents` |
| 15 | GPO change → executable/script **and** ScheduledTasks.xml / Registry.pol / scripts.ini written to that policy's SYSVOL folder within 30 min | GPO-based ransomware case (Mar 2026); Storm-1175 (Apr 2026) | `15-gpo-deployment-chain.kql` (High) | `IdentityDirectoryEvents`, `DeviceFileEvents` |
| 16 | Privileged / high-criticality account's password reset by a different, non-approved account → that account signs in within 24h | Domain-compromise case (Apr 2026) | `16-privileged-password-reset-then-use.kql` (High) | `IdentityDirectoryEvents`, `IdentityLogonEvents`, `IdentityInfo` |
| 17 | wmiexec / atexec / psexec / smbexec / WinRM execution on an Entra Connect or Cloud Sync server | Domain-compromise case (Apr 2026); high-value-asset protection (Mar 2026) | `17-remote-exec-into-entra-connect.kql` (High) | `DeviceProcessEvents` |
| 18 | Defender tampering on a DC (registry, `Set/Add-MpPreference`, `sc stop WinDefend`) → PsExec `@hostlist`, PDQ or forced remote GPUpdate from that DC within 2h | Storm-2570 (Sep 2026); Storm-1175 (Apr 2026) | `18-defender-tamper-on-dc-then-mass-deploy.kql` (High) | `DeviceRegistryEvents`, `DeviceProcessEvents` |
| 19 | Quick Assist / silent MSI from PowerShell / Node.js in AppData on a workstation → `net … /domain`, nltest, ADSI recon or WinRM to a DC/Tier-0 host within 4h | Teams IT-support impersonation campaign (Sep 2026) | `19-helpdesk-remote-session-to-tier0-winrm.kql` (Medium) | `DeviceProcessEvents`, `DeviceNetworkEvents` |

**Dashboard additions:** an *AD kill-chain progression* tile that flags any account reaching 3+ stages in a week (heavy recon, resetting other accounts' passwords, group changes, GPO edits, remote logons to DCs), plus tiles for RMM/tunnel tools on Tier 0, privileged password resets by actor, and inbound WinRM/RDP to Tier 0 by source.

**Caveats:** some command details in the Microsoft posts appear only in screenshots, so the string matches are deliberately broad. Sequence 14 assumes MDE emits `ScheduledTaskCreated`/`ScheduledTaskDeleted` on your DCs. Sequence 16 relies on `IdentityInfo` criticality or tags being populated.

---

## Deliverables and how to deploy

The inline KQL above shows the approach. The deployable, hardened versions are separate files, and those are the ones to use:

| Path | What it is |
|---|---|
| `detections\01a…12-optional….kql` | 14 custom-detection queries for items 1–10, plus optional item 12. Each projects `Timestamp`, `ReportId` and the entity columns. |
| `detections\13…19-*.kql` | 7 sequence detections based on Microsoft Threat Intelligence reporting (see *Threat-actor sequences* above). |
| `detections\rules.json` | Rule metadata: title, severity, MITRE technique, entity mapping, recommended actions. Rule 12 has `"deploy": false`. |
| `Deploy-CustomDetections.ps1` | Creates the rules through Microsoft Graph (`/beta/security/rules/detectionRules`, scope `CustomDetection.ReadWrite.All`). |
| `dashboards\AD-Gap-Workbook.json` | Sentinel workbook with posture tiles for items 11, 12, 3 (NTLM downgrade) and 4 (edge-account activity), plus four sequence tiles (kill-chain progression, RMM on Tier 0, privileged resets by actor, WinRM/RDP into Tier 0). |
| `dashboards\hunting\*.kql` | The same dashboard tiles as Advanced Hunting queries, plus Query 0 (discovery) and a ResetNightmare follow-up hunt. |

**Steps**
1. Run `dashboards\hunting\00-discover-action-types.kql` and adjust the string matches to the values your tenant actually emits.
2. Fill in every `// TUNE` list: GpoAdmins, EdgeAccounts/EdgeIPs, ApprovedJoiners, KnownDelegationTargets, TrustAccounts, ExtraDCs (optional), ApprovedReaders (rule 12), ApprovedRmm, ApprovedResetters, ExtraEntraConnect and TierZeroExtra.
3. Run each query in Advanced Hunting over 30 days, replacing `ago(1h)` with `ago(30d)`, and tune out the noise.
4. Run `.\Deploy-CustomDetections.ps1 -WhatIf`. Then run `.\Deploy-CustomDetections.ps1`, which creates the rules disabled. Add `-Enable` to create them enabled and `-IncludeOptional` to include rule 12. Rules that already exist with the same display name are skipped.
5. Import the workbook in Sentinel (Workbooks → Add → Advanced editor → paste the JSON). This needs the Defender XDR connector to stream the Identity* tables. Without Sentinel, save the `dashboards\hunting` queries as shared Advanced Hunting queries instead.

**Validation status:** all 43 queries (21 detections, 12 hunting queries, 10 workbook tiles) parse cleanly with Kusto.Language against an Identity*/Device* schema. The deploy script's `-WhatIf -IncludeOptional` run builds all 21 payloads. None of this has been run against a live tenant.

## Deployment notes

- Custom detections in Defender XDR require `Timestamp`, `ReportId` and an entity column (`AccountName`/`DeviceName`) – all queries above project them. Use 1h frequency with `ago(1h)` lookback.
- Requires sensor v3.x on DCs, AD CS and AD FS servers, with automatic Windows auditing (including 5136 for directory changes) and Enhanced RPC auditing enabled.
- For dashboards, the Defender XDR custom-detection/advanced-hunting results can be pinned to a Sentinel workbook or Power BI via the `IdentityDirectoryEvents`/`IdentityLogonEvents` tables in Sentinel.

## Sources

- MDI alerts: learn.microsoft.com/defender-for-identity/alerts-overview, alerts-mdi-classic, alerts-xdr; What’s new (Apr–Oct 2026)
- CISA/ASD et al., *Detecting and mitigating Active Directory compromises* (Sep 2026 update)
- Kaspersky GERT, *Group Policy hijacked: PAYLOAD ransomware weaponizes AD GPO* (securelist.com, 21 Sep 2026)
- Semperis, *Identity Crisis: KerberLoss (CVE-2026-25177) and ResetNightmare (CVE-2026-27912)* (5 Aug 2026); Forestall ResetNightmare detection guide (7 Aug 2026)
- CVE-2026-56155 AD FS DKM ACL EoP (CISA KEV, 14 Jul 2026)
- SecPod KEV review Apr–Sep 2026 (CL-STA-1132 / PAN-OS CVE-2026-0300, Qilin)
- Secureware, *Active Directory Attack Paths in 2026* (24 Apr 2026)
- Microsoft Threat Intelligence, *Beyond ransomware: tracking Storm-2570's consistent tradecraft across deployments* (24 Sep 2026) – https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/
- Microsoft Threat Intelligence, *Impersonating IT support: threat actors turn remote session into enterprise-wide access* (2 Sep 2026) – https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
- Microsoft Security, *Domain compromise: predictive shielding shut down lateral movement* (17 Apr 2026) – https://www.microsoft.com/en-us/security/blog/2026/04/17/domain-compromise-predictive-shielding-shut-down-lateral-movement/
- Microsoft Threat Intelligence, *Storm-1175 focuses gaze on vulnerable web-facing assets in high-tempo Medusa ransomware operations* (6 Apr 2026) – https://www.microsoft.com/en-us/security/blog/2026/04/06/storm-1175-focuses-gaze-on-vulnerable-web-facing-assets-in-high-tempo-medusa-ransomware-operations/
- Microsoft Security, *How Microsoft Defender protects high-value assets* (27 Mar 2026) – https://www.microsoft.com/en-us/security/blog/2026/03/27/microsoft-defender-protects-high-value-assets/
- Microsoft Security, *Case study: predictive shielding – Defender stopped GPO-based ransomware before it started* (23 Mar 2026) – https://www.microsoft.com/en-us/security/blog/2026/03/23/case-study-predictive-shielding-defender-stopped-gpo-based-ransomware-before-started/
