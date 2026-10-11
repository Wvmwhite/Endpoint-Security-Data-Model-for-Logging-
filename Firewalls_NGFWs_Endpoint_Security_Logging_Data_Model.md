# Endpoint Security Logging Data Model: Firewalls / Next-Generation Firewalls (NGFWs)

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Network_Traffic, Intrusion_Detection, Change, Authentication; secondary: Web, Alerts), Zero Trust Visibility & Analytics, relevant DISA STIGs, and NSA/CISA guidance.

**Primary popular solutions in DoD / federal environments:**  
- Palo Alto Networks PA-Series / Panorama (PAN-OS) – strong presence in enterprise and cloud-adjacent deployments  
- Cisco Secure Firewall (Threat Defense – FTD and ASA) – widely deployed in DoD and civilian agencies, often with FMC management  
- Fortinet FortiGate (FortiOS) – high unit volume, strong price-performance, common in branch and perimeter roles  
- Check Point Quantum (secondary but present in regulated environments)  

**Typical deployment contexts:** Perimeter firewalls, data center segmentation, branch/edge, hybrid cloud (cloud NGFW), High Value Asset protection, and Zero Trust network access enforcement points.

## 1. Category Overview
NGFWs provide stateful inspection, application control, intrusion prevention, URL/file filtering, and user identity awareness. Logging focuses on traffic decisions (allow/deny), threat detections, configuration changes, authentication events, and system activity so agencies can reconstruct network activity and detect policy violations or attacks.

## 2. Operational Purpose & Security Rationale
Deployed as the primary enforcement and visibility point for network traffic. Primary security functions include:

- Traffic allow/deny decisions based on policy, application, user, and content  
- Threat prevention (IPS, malware, URL, file)  
- User identity mapping (User-ID, VPN, SSO)  
- Configuration and administrative change control  

Supports Zero Trust by enforcing least-privilege network access, providing continuous verification of traffic and identity, and generating the network telemetry required for the Visibility & Analytics pillar.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| What traffic was allowed or denied between which source and destination (IP, port, application, user), when, and by which policy? | CEM, THIRF, Investigation, Zero Trust | Core network visibility (M-26-14 App B j) |
| What threats (IPS, malware, URL, file) were detected or blocked, involving which source/destination and signature? | CEM, Hunting, THIRF | Intrusion and malware detection |
| Who made configuration or administrative changes, from where, and what was changed? | CEM, THIRF | Change and privilege control (App B d) |
| Who authenticated (success/failure) via VPN, User-ID, or management interfaces? | CEM, Investigation | Identity binding |
| Can the sequence of traffic, threat, and change events be reconstructed to determine initial access and scope? | THIRF, CSIRC | Attack reconstruction |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Traffic / Connection logs (allow and deny) | Must Have | Native | Primary source. Include start/end or session summary as appropriate. |
| Threat / Security event logs (IPS, malware, URL, file, WildFire/equivalent) | Must Have | Native | Critical for detection and hunting. |
| System / Event logs (authentication, HA, system status) | Must Have | Native | Administrative and operational context. |
| Configuration / Audit logs (admin changes) | Must Have | Native | Change detection and accountability. |
| User-ID / Identity logs | Should Have | Enhanced | When User-ID or equivalent is deployed. |
| VPN / GlobalProtect / SSL VPN logs | Should Have (Must if remote access) | Native | Remote access visibility. |
| Decryption logs | Nice to Have | Enhanced | When SSL inspection is enabled. |

**Policy guidance:** Enable logging on security policies (especially deny and high-risk allow), forward to central collector (syslog or vendor management platform), and ensure both allow and deny traffic is captured. Avoid excessive start-of-session logging if end-of-session provides sufficient detail.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| receive_time / timestamp | Log receipt or event time | Timeline | `_time` | 2026-10-10 14:22:15 | NTP required |
| src / srcip / source_ip | Source IP | Attribution | Network_Traffic.src | 10.1.2.3 | |
| dst / dstip / destination_ip | Destination IP | Target | Network_Traffic.dest | 203.0.113.10 | |
| srcport / src_port | Source port | Context | Network_Traffic.src_port | 49152 | |
| dstport / dst_port | Destination port | Service | Network_Traffic.dest_port | 443 | |
| proto / protocol | Protocol | Transport | Network_Traffic.transport | 6 (TCP), 17 (UDP) | |
| action | Allow/deny/block decision | Outcome | Network_Traffic.action or Intrusion_Detection.action | allow, deny, drop, block | Critical |
| app / application | Application identified | Visibility | Network_Traffic.app | ssl, web-browsing, unknown | NGFW-specific |
| user / srcuser | Identified user | Identity | Network_Traffic.user or Authentication.user | jdoe | When User-ID enabled |
| policyid / rule / policy | Policy that matched | Enforcement context | Network_Traffic.rule | 12, Allow-Web | |
| bytes / sentbyte / rcvdbyte | Bytes transferred | Volume | Network_Traffic.bytes | 12500 | |
| threatid / signature / attack | Threat signature or ID | Detection | Intrusion_Detection.signature | 12345, SQL Injection | Threat logs |
| severity | Threat or event severity | Prioritization | Intrusion_Detection.severity | high, critical | |
| serial / devname / device | Device identity | Multi-device correlation | Network_Traffic.dvc or Change.dest | 001234567890 | |
| vendor_product | Platform and version | Source differentiation | Network_Traffic.vendor_product | PAN-OS 11.1, FortiOS 7.4, FTD 7.4 | |
| status / result | Success/failure | Outcome | Authentication.action or Change.status | success, failure | Auth/change logs |

**High-value technology-specific fields:** sessionid, vsys, zone (src/dst), interface, NAT details, threat category, file hash (WildFire), URL category.

## 6. CIM Alignment
**Primary CIM data models:**  
- **Network_Traffic** (tag=network, communicate) for traffic/connection logs  
- **Intrusion_Detection** (tag=ids, attack) for threat/IPS/malware/URL events  
- **Change** (tag=change) for configuration and administrative changes  
- **Authentication** (tag=authentication) for login, VPN, and User-ID events  

**Key mappings:**  
- src/dst IP and ports → Network_Traffic.src/dest/src_port/dest_port  
- action → Network_Traffic.action or Intrusion_Detection.action  
- app → Network_Traffic.app  
- user → Network_Traffic.user or Authentication.user  
- threat signature → Intrusion_Detection.signature  
- device serial → Network_Traffic.dvc  

Vendor add-ons (Splunk Add-on for Palo Alto, Cisco, Fortinet) provide CIM-compliant field extractions when logs are sent in default formats.

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time detection of denied traffic spikes, high-severity threats, unexpected configuration changes, failed administrative logins, and anomalous application usage. Searchable minimum 6 months.

**THIRF:** Full reconstruction of network sessions, threat detections, policy decisions, and administrative activity. Retrievable 12 months. Externalize logs so the firewall cannot be used to erase evidence.

**CSIRC:** Authoritative network enforcement and threat timeline required to scope lateral movement, command-and-control, or policy bypass.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- Syslog (UDP/TCP/TLS) or vendor-native forwarding (Panorama, FMC, FortiAnalyzer) to Cribl Edge/Stream or equivalent.  
- Prefer default or well-documented formats for reliable parsing.  
- Central management platforms can aggregate before forwarding.  
- Use Cribl Stream for filtering high-volume traffic logs, enrichment (GeoIP, asset lookup), and CIM normalization.

**Common pitfalls:** Logging only allow or only deny; missing threat logs; custom log formats that break parsing; high-volume start-of-session logs without end-of-session; logs remaining only on the device; incomplete User-ID or identity context.

**Gap-analysis checklist:**  
- [ ] Traffic logs (allow + deny) collected  
- [ ] Threat/security event logs collected  
- [ ] Configuration and system/audit logs collected  
- [ ] Key fields mapped to Network_Traffic and Intrusion_Detection CIM  
- [ ] Logs externalized and available to top-level SOC  
- [ ] 6-month searchable / 12-month retrievable met  
- [ ] Identity context (User-ID/VPN) present where deployed  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| Traffic logs (allow + deny) | | | Must | |
| Threat / security event logs | | | Must | |
| Config / audit / system logs | | | Must | |
| CIM Network_Traffic + Intrusion_Detection mapping | | | Must | |
| Externalized logs + SOC access | | | Must | |
| Identity (User-ID/VPN) context | | | Should | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

**Analyst notes:** Document vendor/model/version, log forwarding method and format, which policies have logging enabled, and any filtering applied before the SIEM.

---

**References:**  
- OMB M-26-14 and CISA LRA  
- Palo Alto Networks, Cisco Secure Firewall, and Fortinet logging documentation  
- Relevant DISA STIGs  
- Splunk CIM Network_Traffic, Intrusion_Detection, Change, and Authentication data models  
- Splunk Add-ons for Palo Alto, Cisco, and Fortinet  

This model should be used together with OS, Kubernetes, and cloud platform models for complete coverage of traffic that traverses the NGFW.
