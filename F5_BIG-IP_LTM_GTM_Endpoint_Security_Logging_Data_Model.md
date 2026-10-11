# Endpoint Security Logging Data Model: F5 BIG-IP LTM and GTM

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Network_Traffic, Change, Authentication, Web; secondary: Intrusion_Detection), Zero Trust Visibility & Analytics, relevant DISA STIGs (F5 BIG-IP LTM).

**Primary popular solutions in DoD / federal environments:**  
- F5 BIG-IP Local Traffic Manager (LTM) – load balancing, SSL offload, application delivery  
- F5 BIG-IP Global Traffic Manager (GTM / DNS) – global server load balancing and DNS traffic management  
- Often deployed with AFM (Advanced Firewall Manager), ASM (Application Security Manager), or APM modules  

**Typical deployment contexts:** Application entry points, data center load balancing, SSL/TLS inspection points, multi-site global traffic management, High Value Asset front-ends, and DoDIN APL-approved deployments.

## 1. Category Overview
F5 BIG-IP LTM and GTM act as application delivery controllers that terminate, inspect, load-balance, and route traffic. Logging focuses on virtual server connections, pool member status, configuration changes, authentication events, and (when enabled) security events so agencies can reconstruct application traffic flows and detect policy or configuration issues.

## 2. Operational Purpose & Security Rationale
Deployed to provide high availability, SSL offload, traffic management, and application-layer visibility. Primary security functions include:

- Traffic distribution and health checking across pool members  
- SSL/TLS termination and re-encryption  
- Configuration change accountability (audit logging)  
- Optional advanced security (AFM firewall rules, ASM WAF events, APM access policies)  

Supports Zero Trust by providing a controlled, inspectable entry point for application traffic and generating detailed session and configuration telemetry.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| What client connected to which virtual server / pool member, when, from which source IP, and what was the outcome? | CEM, THIRF, Investigation | Application traffic visibility (M-26-14 App B j) |
| Who made configuration changes (create/modify/delete objects), from where, and what was changed? | CEM, THIRF | Change accountability (App B d) |
| Who authenticated (success/failure) to the management interface or via APM? | CEM, Investigation | Identity binding |
| What security events (firewall drops, ASM violations) occurred against which virtual server? | CEM, Hunting | When AFM/ASM is enabled |
| Can the sequence of connection, configuration, and security events be reconstructed? | THIRF, CSIRC | Attack or outage reconstruction |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| LTM local traffic logs (/var/log/ltm) | Must Have | Native | Virtual server connections, pool member status, errors. |
| Audit logs (/var/log/audit) | Must Have | Enhanced (enable MCP/tmsh audit) | Configuration changes by user or system. |
| System / security logs (authentication, management) | Must Have | Native | Administrative access and system events. |
| GTM / DNS logs (/var/log/gtm) | Must Have if GTM deployed | Native | DNS queries, wide IP decisions, pool status. |
| High-speed logging (HSL) or iRule-generated traffic logs | Should Have | Enhanced | Detailed request/response or connection details when needed. |
| AFM firewall / packet filter logs | Should Have (Must if AFM enabled) | Enhanced | Network firewall decisions. |
| ASM application security logs | Should Have (Must if ASM/WAF enabled) | Enhanced | WAF violations, attack signatures. |
| APM access policy logs | Nice to Have / Should if APM used | Enhanced | User access and authentication decisions. |

**Configuration guidance:** Enable audit logging for MCP and tmsh changes. Forward logs via remote syslog or High-Speed Logging (HSL) to an external collector. Prefer structured or key-value formats where possible for easier parsing.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| timestamp | Event time | Timeline | `_time` | 2026-10-10T14:22:15 | NTP required |
| hostname / bigip_hostname | Device identity | Correlation | Network_Traffic.dvc or Change.dest | f5-ltm-01 | |
| user / login | User who performed action | Identity | Change.user or Authentication.user | admin, tmsh | Audit logs |
| action / event | Action performed | What happened | Change.action or Network_Traffic.action | create, modify, delete, allow, drop | |
| object / object_name | Configuration object or virtual server | Target | Change.object | virtual_server /Common/app-vs | Audit and LTM |
| src_ip / client_ip | Source / client IP | Attribution | Network_Traffic.src or Web.src | 10.1.2.3 | Traffic and ASM logs |
| dest_ip / pool_member | Destination or pool member | Target | Network_Traffic.dest | 10.0.1.50 | |
| virtual_server / context_name | Virtual server or context | Application entry point | Network_Traffic.app or custom | /Common/web-vs | |
| status / result | Outcome | Success/failure | Change.status or Authentication.action | success, failure, drop | |
| protocol / dest_port | Protocol and port | Service context | Network_Traffic.transport, dest_port | tcp, 443 | |
| vendor_product | Platform and version | Source differentiation | Change.vendor_product | F5 BIG-IP 17.1 LTM | |
| message / description | Event description | Forensic detail | Custom | | |

**High-value technology-specific fields:** pool name, partition, session ID, SSL cipher, request URI (when logged), attack type (ASM), rule name (AFM).

## 6. CIM Alignment
**Primary CIM data models:**  
- **Network_Traffic** for LTM connection and traffic events  
- **Change** for audit/configuration change logs  
- **Authentication** for management and APM authentication events  
- **Web** for detailed HTTP request logs (when enabled via iRules or ASM)  
- **Intrusion_Detection** for AFM/ASM security events  

**Key mappings:**  
- client/source IP → Network_Traffic.src or Web.src  
- virtual server / pool → Network_Traffic.app or Change.object  
- user → Change.user / Authentication.user  
- action → Change.action or Network_Traffic.action  
- device hostname → Network_Traffic.dvc  

The Splunk Add-on for F5 BIG-IP provides CIM-compatible knowledge for syslog, iRules, and iControl data.

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time detection of unexpected configuration changes, failed administrative logins, pool member failures, and (when enabled) AFM/ASM security events. Searchable minimum 6 months.

**THIRF:** Reconstruction of client-to-pool-member flows, configuration history, and security decisions. Retrievable 12 months. Externalize logs so the BIG-IP cannot be used to erase evidence.

**CSIRC:** Application entry-point timeline required to scope traffic manipulation, SSL inspection issues, or configuration-based attacks.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- Remote syslog or High-Speed Logging (HSL) to Cribl Edge/Stream or equivalent.  
- Enable audit logging and selective detailed traffic logging via iRules or logging profiles.  
- Use Telemetry Streaming (where available) for structured JSON output.  
- Centralize via management platforms when present.

**Common pitfalls:** Audit logging disabled by default; logs remaining only local on the device; high-volume debug logging without severity filtering; incomplete virtual server logging; missing identity context on management changes.

**Gap-analysis checklist:**  
- [ ] LTM traffic logs collected  
- [ ] Audit logs enabled and collected  
- [ ] System/security logs collected  
- [ ] GTM logs collected (if GTM deployed)  
- [ ] Key fields mapped to Network_Traffic and Change CIM  
- [ ] Logs externalized and available to SOC  
- [ ] 6-month searchable / 12-month retrievable met  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| LTM traffic logs | | | Must | |
| Audit / configuration change logs | | | Must | |
| System and authentication logs | | | Must | |
| GTM / DNS logs (if deployed) | | | Must if GTM | |
| CIM Network_Traffic + Change mapping | | | Must | |
| Externalized logs + SOC access | | | Must | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

**Analyst notes:** Document BIG-IP version and modules (LTM, GTM, AFM, ASM, APM), log forwarding method, whether audit logging is enabled, and any custom iRules or logging profiles in use.

---

**References:**  
- OMB M-26-14 and CISA LRA  
- F5 BIG-IP logging documentation (LTM, GTM, audit, HSL)  
- DISA STIG for F5 BIG-IP Local Traffic Manager  
- Splunk Add-on for F5 BIG-IP and CIM data models  

This model complements the Firewalls/NGFWs and Web Servers models for complete coverage of application traffic paths.
