# Endpoint Security Logging Data Model: macOS Operating Systems

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Endpoint; secondary: Authentication, Change), Zero Trust, NIST/macOS Security Compliance Project, CIS macOS Benchmarks.

**Primary solutions:** macOS Tahoe 26.x, Sequoia 15.x, and current Golden Gate 27.x (as of late 2026). Enterprise-managed via MDM (Jamf, Intune, etc.). Growing presence in federal/DoD user endpoints.

## 1. Category Overview
macOS endpoints in enterprise and federal environments. Logging relies on Unified Logging System (primary), Endpoint Security Framework (preferred modern API), and residual OpenBSM (deprecated/disabled by default since Sonoma). MDM and EDR (Jamf Protect, Microsoft Defender, CrowdStrike) often provide enriched telemetry.

## 2. Operational Purpose & Security Rationale
Captures process execution, file activity, authentication, TCC/privacy decisions, Gatekeeper/XProtect events, and persistence mechanisms (LaunchAgents/Daemons, Login Items). Supports Zero Trust continuous verification and reconstruction of macOS-specific attacks (e.g., AMOS, persistence via LaunchAgents).

## 3. Key Questions the Model Must Answer
- Who authenticated or elevated privileges, and what TCC/privacy grants occurred? (CEM, Zero Trust, THIRF)
- What processes were executed, with parent context and code-signing status? (CEM, Hunting, THIRF)
- What files were created/modified in persistence locations (LaunchAgents, Library, etc.)? (THIRF, Forensics)
- Were Gatekeeper, XProtect, or Endpoint Security events indicating malicious activity? (CEM, Investigation)
- What network or XPC activity accompanied the process? (Threat Hunting)

Maps to M-26-14 identity, object access, privilege changes, suspicious activity, and attack vectors.

## 4. Required Event Classes / Log Sources
| Log Source | Priority | Notes |
|------------|----------|-------|
| Unified Logs (/var/db/diagnostics) | Must Have | Query via `log show` / log stream. Subsystems: securityd, TCC, Gatekeeper, loginwindow, mdmclient. Persist Info/Debug where needed. |
| Endpoint Security Framework events | Should Have (Must for Advanced) | Modern replacement for OpenBSM. Process exec, file, network via ES client or EDR. |
| OpenBSM audit (if re-enabled) | Nice to Have / Legacy | Deprecated since Big Sur, disabled by default on Sonoma+. Flags: lo, aa, pc, ad. |
| MDM / management logs | Should Have | Enrollment, policy, software updates. |
| EDR / Jamf Protect / Defender | Should Have | Enriched process, file, network, persistence detection. |
| FSEvents / other | Nice to Have | File system change notifications. |

Prefer Endpoint Security + Unified Logs for modern deployments. Collect via MDM, EDR forwarders, or custom agents.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters | CIM Mapping | Example | Collection Notes |
|------------|-------------|----------------|-------------|---------|------------------|
| timestamp | Event time | Timeline | `_time` | 2026-10-10T14:22:15Z | Unified log epoch |
| dest | Hostname | Endpoint | Endpoint.dest | macbook-01 | |
| user | User or effective user | Identity | Endpoint.user | jdoe | |
| process / process_name / process_path | Process image and path | Execution | Endpoint.process_name, Endpoint.process_path | /usr/bin/osascript | From ES or Unified |
| parent_process_name | Parent process | Lineage | Endpoint.parent_process_name | Terminal | |
| process_id | PID | Correlation | Endpoint.process_id | 1234 | |
| file_path / file_name | File created/modified | Persistence / data access | Endpoint.file_path | ~/Library/LaunchAgents/malicious.plist | ES file events |
| action | exec, create, modify, allow, deny | Outcome | Endpoint.action | created | |
| code_signing_status / team_id | Signature validity | Malware / unsigned | Custom or Endpoint | valid, teamid=... | High value on macOS |
| subsystem / category | Unified log subsystem | Context | Custom | com.apple.TCC | |
| message / eventMessage | Log message | Details | Custom | TCC prompt denied | |
| src / remote | Network source if applicable | Attribution | Network | 10.1.2.3 | |
| vendor_product | macOS version / EDR | Source | Endpoint.vendor_product | macOS 26.7 | |

## 6. CIM Alignment
**Primary:** Endpoint (process report for exec events; endpoint filesystem for file events).  
**Secondary:** Authentication (login, sudo, Platform SSO), Change (persistence config), Malware (XProtect/Gatekeeper).

Map ES process exec → Endpoint.Processes; file create/modify → Endpoint.Filesystem. Unified Logs often require custom parsing or EDR enrichment for full CIM compliance.

## 7. CEM, THIRF & CSIRC Enablement Notes
CEM: Alerts on unsigned process execution, LaunchAgent creation, TCC bypass attempts, anomalous Unified Log patterns, Gatekeeper blocks. Searchable 6 months.  
THIRF: Reconstruct process trees, persistence artifacts, authentication sequences. Retrievable 12 months. Critical for macOS-specific CSIRC investigations.

## 8. Collection, Normalization & Maturity Guidance
Use EDR agents, Jamf Protect streams, or log collection tools that parse Unified Logs / ES events. Common pitfalls: Unified Logs not persisted at Info level, OpenBSM disabled, high volume without predicates, incomplete code-signing fields.  
Gap checklist: Unified Logs collected with relevant subsystems, ES/EDR process+file events, CIM mapping, retention, MDM coverage tracking.

## 9. Stack Comparison Template
| Requirement | Customer Impl | Gap? | Priority | Notes |
|-------------|----------------|------|----------|-------|
| Unified Logs (security, TCC, Gatekeeper) | | | Must | |
| Endpoint Security / EDR process+file | | | Should | |
| CIM Endpoint mapping | | | Must | |
| 6/12 mo retention + SOC availability | | | Must | |
| Code-signing / persistence visibility | | | Should | |

**References:** M-26-14, CISA LRA, Splunk CIM Endpoint, Apple Unified Logging and Endpoint Security docs, NIST macOS Security Compliance Project, CIS macOS Benchmarks.
