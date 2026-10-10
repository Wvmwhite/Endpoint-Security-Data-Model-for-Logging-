# Endpoint Security Logging Data Model: Windows Operating Systems

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Endpoint; secondary: Authentication, Change), Zero Trust Visibility & Analytics, DISA STIGs.

**Primary solutions:** Windows Server 2025 (current LTSC), 2022, 2019; Windows 11 and Windows 10 Enterprise (still widely deployed in federal/DoD). Clients and servers treated together where logging is common; note server-specific Domain Controller events.

## 1. Category Overview
Windows endpoints and servers form the majority of federal/DoD user and infrastructure systems. Logging focuses on authentication, process execution, privilege changes, persistence mechanisms, and object access.

## 2. Operational Purpose & Security Rationale
Provides identity binding, process lineage, file/registry changes, and network activity from the OS kernel and security auditing subsystem. Essential for Zero Trust continuous verification, lateral movement detection, and full attack reconstruction.

## 3. Key Questions the Model Must Answer
- Who logged on (success/failure), from where, with what logon type, and what privileges were assigned? (CEM, THIRF, Zero Trust)
- What processes were created, with what command line, parent process, and user context? (CEM, Threat Hunting, THIRF)
- What files, registry keys, or services were created/modified that indicate persistence or privilege escalation? (THIRF, Forensics)
- Were audit logs cleared or security policies changed? (CEM, Investigation)
- What PowerShell, WMI, or scheduled task activity occurred? (Threat Hunting, THIRF)

Maps to M-26-14 App B identity, privilege changes, object access, suspicious activity, and attack vectors.

## 4. Required Event Classes / Log Sources
| Log Source | Priority | Notes |
|------------|----------|-------|
| Security.evtx (audit policy) | Must Have | 4624/4625 logons, 4688 process, 4720 account, 4732 group, 4697/4698 service/task, 1102 clear |
| Sysmon Operational | Should Have (Must for Advanced/HVA) | Event 1 (process+hash+cmdline), 3 (network), 8/10 (injection), 11-15 (file/registry), 19-21 (WMI) |
| PowerShell Operational | Must Have | 4103/4104 script block logging |
| System.evtx | Must Have | 7045 service install, time changes |
| Application / Defender | Should Have | Malware detections, crashes |
| WMI-Activity / WinRM | Should Have | Remote execution, persistence |

Enable Advanced Audit Policy (Process Creation with command line, Logon, Account Management, Object Access as needed, Privilege Use).

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters | CIM Mapping | Example | Collection Notes |
|------------|-------------|----------------|-------------|---------|------------------|
| timestamp | Event time (UTC preferred) | Timeline | `_time` | 2026-10-10T14:22:15Z | Ensure NTP |
| dest | Hostname / IP | Endpoint identity | Endpoint.dest | SERVER01 | |
| user | Subject or account name | Identity | Endpoint.user / Authentication.user | DOMAIN\jdoe | |
| process_name / process | Process image and command line | Execution context | Endpoint.process_name, Endpoint.process | powershell.exe -enc ... | Enable cmdline in 4688 or use Sysmon 1 |
| parent_process_name / parent_process | Parent image and cmdline | Lineage / injection | Endpoint.parent_process_name | explorer.exe | Sysmon preferred |
| process_id / parent_process_id | PIDs | Correlation | Endpoint.process_id | 1234 | |
| file_path / file_name | File created/modified | Persistence / malware | Endpoint.file_path | C:\Users\Public\malware.exe | Sysmon 11 or Object Access |
| registry_path / registry_value_name | Registry change | Persistence | Endpoint.registry_path | HKLM\...\Run\malware | Sysmon 12-14 or 4657 |
| action | created, deleted, modified, allowed, blocked | Outcome | Endpoint.action | created | |
| src / src_ip | Source for logon or network | Lateral movement | Authentication.src / Network | 10.1.2.3 | Logon Type 3/10 |
| logon_type | 2=Interactive, 3=Network, 10=RDP | Access method | Custom or Authentication | 10 | Critical for 4624 |
| file_hash | SHA256 of process/file | IoC matching | Endpoint.file_hash | a1b2c3... | Sysmon |
| event_id | Native Event ID | Filtering | Custom | 4688, 1 | |
| vendor_product | Windows version / Sysmon | Source | Endpoint.vendor_product | Windows Server 2025 | |

## 6. CIM Alignment
**Primary:** Endpoint (tags: process report for Processes; endpoint filesystem; endpoint registry; service report; listening port)  
**Secondary:** Authentication (tag=authentication), Change (tag=change + account or endpoint), Malware, Network_Traffic (for Sysmon 3).

Map Security 4688/Sysmon 1 → Endpoint.Processes; 4657/Sysmon 12-14 → Endpoint.Registry; file events → Endpoint.Filesystem; 4697/7045 → Endpoint.Services.

## 7. CEM, THIRF & CSIRC Enablement Notes
CEM: Real-time alerts on failed logons, anomalous process creation (LOLBins, encoded PS), new services/tasks, log clears. Searchable 6 months.  
THIRF: Full process trees, persistence reconstruction, logon sequences for lateral movement. Retrievable 12 months. Critical for CSIRC timeline and scope.

## 8. Collection, Normalization & Maturity Guidance
Collect via Winlogbeat, Splunk UF, or WEF. Enable audit policies via GPO. Common pitfalls: missing command-line in 4688, incomplete Sysmon config, high volume without filtering.  
Gap checklist: Advanced Audit Policy enabled, Sysmon deployed with good config, PowerShell script block logging on, logs forwarded and CIM-normalized, retention met, coverage tracked in inventory.

## 9. Stack Comparison Template
| Requirement | Customer Impl | Gap? | Priority | Notes |
|-------------|----------------|------|----------|-------|
| Security log key Event IDs + cmdline | | | Must | |
| Sysmon (key EIDs) | | | Should | |
| PowerShell 4104 | | | Must | |
| CIM Endpoint mapping | | | Must | |
| 6/12 mo retention + SOC availability | | | Must | |

**References:** M-26-14, CISA LRA, Splunk CIM Endpoint, Microsoft Security Auditing docs, Sysmon docs.
