# Endpoint Security Logging Data Model: Linux Operating Systems

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Endpoint; secondary: Authentication, Change), Zero Trust, DISA STIGs / CIS benchmarks for RHEL.

**Primary solutions:** Red Hat Enterprise Linux (RHEL) 9 / 8 (dominant in DoD/federal), Rocky Linux / AlmaLinux (RHEL-compatible), Ubuntu Server LTS (22.04 / 24.04 / 26.04). SUSE less common but noted.

## 1. Category Overview
Linux servers and workstations in federal/DoD environments. Focus on kernel-level auditing (auditd), authentication, process execution, file integrity, and privilege escalation.

## 2. Operational Purpose & Security Rationale
Provides tamper-resistant kernel audit records of system calls, file access, user identity changes, and privileged actions. Supports Zero Trust by binding identity to actions and enabling reconstruction of compromise on Linux hosts.

## 3. Key Questions the Model Must Answer
- Who authenticated (success/failure), via which method, and from where? (CEM, THIRF, Zero Trust)
- What processes were executed (execve), by which user (auid), with what arguments? (CEM, Hunting, THIRF)
- Were critical files (/etc/passwd, /etc/shadow, sudoers, SSH config) modified? (THIRF, Forensics)
- Were privilege escalations (sudo, setuid) or identity changes performed? (CEM, Investigation)
- What network connections or module loads occurred? (Threat Hunting)

Maps to M-26-14 identity, object access, privilege changes, infrastructure changes, suspicious activity.

## 4. Required Event Classes / Log Sources
| Log Source | Priority | Notes |
|------------|----------|-------|
| auditd (/var/log/audit/audit.log) | Must Have | SYSCALL (execve, open, etc.), USER_LOGIN, CONFIG_CHANGE, PATH, CWD. CIS/STIG rules for identity, perm_mod, exec, delete. |
| syslog / journald (auth, secure) | Must Have | SSH, sudo, PAM, cron, systemd |
| systemd journal | Should Have | Service starts, unit failures |
| Application logs (e.g., web, DB) | Should Have | Correlate with OS events |
| osquery / EDR telemetry | Nice to Have / Should for Advanced | Process, file, network snapshots + events |

Configure auditd with persistent rules (augenrules), adequate buffer, and failure mode. Forward via audisp or syslog.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters | CIM Mapping | Example | Collection Notes |
|------------|-------------|----------------|-------------|---------|------------------|
| timestamp | Event time | Timeline | `_time` | 2026-10-10 14:22:15 | NTP required |
| dest | Hostname | Endpoint | Endpoint.dest | rhel-server01 | |
| user / auid | Audit UID (original user) | Identity (even after su) | Endpoint.user / Authentication.user | 1000 (jdoe) | Prefer auid over uid |
| process / exe / comm | Executable and command | Execution | Endpoint.process, Endpoint.process_name | /usr/bin/sudo | From execve |
| process_id / pid | Process ID | Correlation | Endpoint.process_id | 12345 | |
| file_path / name | File accessed or modified | Object access | Endpoint.file_path | /etc/shadow | From PATH record |
| action / success | success=yes/no or syscall result | Outcome | Endpoint.action | success=no | |
| syscall | System call number/name | Type of activity | Custom | execve, openat | |
| src / addr | Source IP for network or login | Attribution | Authentication.src | 10.1.2.3 | SSH or connect |
| key | Audit rule key | Categorization | Custom | identity, exec_commands | |
| vendor_product | Distro + version | Source | Endpoint.vendor_product | RHEL 9.4 | |
| file_hash | Optional hash | IoC | Endpoint.file_hash | | From EDR or post-processing |

## 6. CIM Alignment
**Primary:** Endpoint (process report for execve events; endpoint filesystem for file watches; service report for systemd).  
**Secondary:** Authentication (USER_LOGIN, SSH), Change (account/file config changes).

Map audit SYSCALL execve → Endpoint.Processes; file watches → Endpoint.Filesystem.

## 7. CEM, THIRF & CSIRC Enablement Notes
CEM: Alerts on failed logins, sudo abuse, critical file changes, unexpected exec. Searchable 6 months.  
THIRF: Reconstruct user session, command history via auid, file access sequences. Retrievable 12 months. Essential for Linux host forensics and CSIRC.

## 8. Collection, Normalization & Maturity Guidance
Forward audit.log and syslog via Filebeat/Fluent Bit/Splunk UF or audisp plugins. Common pitfalls: incomplete rules (missing exec or identity), high volume of open() without filters, auid=unset for system processes.  
Gap checklist: auditd running with CIS-aligned rules, logs forwarded and searchable, CIM mapping, retention, inventory coverage.

## 9. Stack Comparison Template
| Requirement | Customer Impl | Gap? | Priority | Notes |
|-------------|----------------|------|----------|-------|
| auditd with key rules (identity, exec, perm) | | | Must | |
| Auth logs (SSH/sudo) | | | Must | |
| CIM Endpoint mapping | | | Must | |
| 6/12 mo retention + SOC availability | | | Must | |

**References:** M-26-14, CISA LRA, Splunk CIM Endpoint, Red Hat Audit System docs, CIS benchmarks.
