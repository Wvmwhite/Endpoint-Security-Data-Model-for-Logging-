# Endpoint Security Logging Data Model: Nutanix Platform

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Change, Authentication, Endpoint, Network_Traffic; secondary: Inventory), Zero Trust Visibility & Analytics, relevant DISA STIGs (Nutanix AOS / AHV), and Nutanix SCMA guidance.

**Primary popular solutions in DoD / federal environments:**  
- Nutanix Cloud Platform (AOS + AHV hypervisor)  
- Prism Element and Prism Central management  
- Nutanix Files (when used)  
- Flow Network Security / Security Central (when enabled)  

**Typical deployment contexts:** Hyper-converged infrastructure (HCI) for mission applications, VDI, databases, and hybrid cloud extensions in federal and DoD environments. Commonly used where simplified management and STIG alignment are required.

## 1. Category Overview
The Nutanix Platform provides hyper-converged compute, storage, and networking with centralized management through Prism. Logging focuses on administrative actions, VM lifecycle events, configuration changes, authentication, and (when enabled) network security policy hits so agencies can reconstruct infrastructure changes and detect unauthorized activity.

## 2. Operational Purpose & Security Rationale
Deployed as a unified infrastructure platform that simplifies operations while meeting high-governance requirements. Primary security functions include:

- Centralized management and change control via Prism  
- VM and storage lifecycle auditing  
- Hypervisor and Controller VM (CVM) hardening (SCMA / STIG alignment)  
- Optional network micro-segmentation and security policy enforcement (Flow)  

Supports Zero Trust by providing identity-bound administrative actions, infrastructure change visibility, and network policy enforcement points.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who performed which administrative or VM lifecycle action (create, power on/off, migrate, delete), against which object, from which source, and with what result? | CEM, THIRF, Investigation, Zero Trust | Core audit trail (M-26-14 App B a–d) |
| What configuration or security policy changes were made to the cluster, hosts, or VMs? | CEM, THIRF | Change accountability |
| Who authenticated (success/failure) to Prism, CVMs, or AHV hosts? | CEM, Investigation | Identity binding |
| What network flows were allowed, monitored, or dropped by Flow security policies? | CEM, Hunting | When Flow is enabled |
| Can the sequence of administrative actions and VM events be reconstructed? | THIRF, CSIRC | Infrastructure timeline |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Audit logs (AUDIT module / consolidated_audit.log) | Must Have | Native | VM create/update/delete/power/migrate, category, and policy changes. Forward via remote syslog. |
| API Audit logs (API_AUDIT module) | Must Have | Native | REST API calls to Prism Element and Prism Central. |
| Syslog module (SYSLOG_MODULE) – CVM and AHV | Must Have | Native | Authentication, system, and host logs. |
| Prism / Acropolis service logs | Should Have | Native | Task and operational context. |
| Security Policy Hit Logs (Flow) | Should Have (Must if Flow enabled) | Enhanced | Network allow/monitor/drop decisions. |
| AHV host logs (libvirt, messages, secure) | Should Have | Native | Hypervisor-level events. |
| Nutanix Files audit (when used) | Nice to Have / Should for file services | Enhanced | File activity if Files is deployed. |

**Configuration guidance:** Enable remote syslog forwarding for AUDIT, API_AUDIT, and SYSLOG_MODULE at INFO level. Use Nutanix remote syslog configuration. Ensure NTP is synchronized. Prefer external shipping so logs cannot be altered on the platform.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| timestamp / creationTimestampUsecs | Event time | Timeline | `_time` | 2026-10-10T14:22:15Z | UTC recommended |
| userName / userUuid | User who performed the action | Identity binding | Change.user or Authentication.user | admin, jdoe | Critical |
| operationType / action | Operation performed | What happened | Change.action | Create, Update, Delete, Migrate | |
| entityType / name / uuid | Target entity | Object accessed | Change.object | vm, Test-VM, uuid | |
| clientIp / source IP | Source IP of the action | Attribution | Authentication.src or Change.src | 10.1.2.3 | |
| defaultMsg / description | Event description | Forensic detail | Custom | Created VM Test | |
| status / result | Outcome | Success/failure | Change.status | Success, Failure | |
| clusterUuid / originatingClusterUuid | Cluster identity | Multi-cluster correlation | Change.dest or Inventory.dest | | |
| src_ip / dest_ip / protocol / action | Flow details (Flow) | Network visibility | Network_Traffic.src, dest, action | allow, drop | Security Policy Hit Logs |
| vendor_product | Platform and version | Source differentiation | Change.vendor_product | Nutanix AOS 6.8, AHV | |

**High-value fields:** alertUid (event type), affectedEntityList, params, session context.

## 6. CIM Alignment
**Primary CIM data models:**  
- **Change** for audit and configuration events (VM lifecycle, policy changes)  
- **Authentication** for login and administrative access events  
- **Endpoint** for host and CVM system events  
- **Network_Traffic** for Flow Security Policy Hit Logs  

**Key mappings:**  
- userName → Change.user / Authentication.user  
- operationType + entityType → Change.action / object  
- clientIp → Authentication.src or Change.src  
- Flow flow fields → Network_Traffic.src/dest/action  

No native Nutanix CIM add-on is widely standardized; use field aliases and calculated fields for normalization.

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time detection of unexpected VM lifecycle events, privilege changes, failed administrative logins, and (when enabled) Flow policy drops. Searchable minimum 6 months.

**THIRF:** Reconstruction of administrative and infrastructure change timelines. Retrievable 12 months. External syslog is required because local audit retention is limited.

**CSIRC:** Authoritative record of who changed the hyper-converged infrastructure and when, required to scope configuration-based or credential compromise.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- Configure remote syslog (AUDIT, API_AUDIT, SYSLOG_MODULE) to Cribl Edge/Stream or equivalent.  
- Forward AHV host logs where possible.  
- Use logbay or Prism log collection for ad-hoc forensics.  
- Centralize multi-cluster logs via Prism Central where practical.

**Common pitfalls:** Relying on local Prism audit views only (limited retention); not enabling remote syslog; missing API_AUDIT; incomplete Flow logging; logs remaining only on CVMs.

**Gap-analysis checklist:**  
- [ ] Remote syslog enabled for AUDIT and API_AUDIT  
- [ ] SYSLOG_MODULE forwarding configured  
- [ ] Key fields mapped to Change and Authentication CIM  
- [ ] Logs externalized and available to SOC  
- [ ] Flow Security Policy Hit Logs collected (if Flow is used)  
- [ ] 6-month searchable / 12-month retrievable met  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| Audit logs (VM lifecycle, config) forwarded | | | Must | |
| API Audit logs forwarded | | | Must | |
| System / auth logs (SYSLOG_MODULE) | | | Must | |
| CIM Change + Authentication mapping | | | Must | |
| Externalized logs + SOC access | | | Must | |
| Flow policy hit logs (if applicable) | | | Should / Must | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

**Analyst notes:** Document AOS/AHV version, Prism Element vs Central, remote syslog configuration, modules enabled, and whether Flow Network Security is in use.

---

**References:**  
- OMB M-26-14 and CISA LRA  
- Nutanix Prism Central / Element documentation (Audit logs, Syslog modules)  
- DISA STIG for Nutanix AOS / AHV  
- Splunk CIM Change, Authentication, Endpoint, and Network_Traffic data models  

This model should be used together with OS, network, and application models for full coverage of workloads running on Nutanix.
