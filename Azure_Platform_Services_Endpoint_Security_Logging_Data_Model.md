# Endpoint Security Logging Data Model: Azure Platform Services

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Change, Authentication, Network_Traffic, Web; secondary: Data Access), Zero Trust Visibility & Analytics, FedRAMP High / DoD IL4–IL5 guidance, Azure Government compliance recommendations.

**Primary popular solutions in DoD / federal environments:**  
- Azure Government (US Gov regions) with FedRAMP High and DoD IL4/IL5 authorizations  
- Core logging foundation: Azure Activity Logs, Azure Monitor / Log Analytics, Diagnostic Settings, NSG Flow Logs / Virtual Network Flow Logs  
- Common supporting services: Azure Storage, Azure App Gateway / Application Gateway, Azure Load Balancer, Azure API Management, Service Bus / Event Hubs, Key Vault, Microsoft Entra ID  

**Typical deployment contexts:** Mission applications, microservices, hybrid systems, High Value Assets, and multi-subscription environments in Azure Government or FedRAMP High boundaries.

## 1. Category Overview
Azure Platform Services represent the control-plane and data-plane logging foundation required for any application hosted in Azure. The model focuses on the services that generate the authoritative record of who did what, network flows, and resource/object access so agencies can meet CEM and THIRF outcomes.

## 2. Operational Purpose & Security Rationale
These services provide durable, centralized auditability of Azure control-plane activity, network traffic, and data access. Primary security functions include:

- Identity-bound resource operation recording (Activity Logs + Entra ID)  
- Network flow visibility (NSG / VNet Flow Logs)  
- Resource and data access logging (Storage, API Management, App Gateway)  
- Diagnostic and audit telemetry via Diagnostic Settings  

They support Zero Trust by enabling continuous verification of identity, network path, and resource access across the cloud boundary.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who (user, service principal, managed identity) performed which control-plane operation against which resource, from which source IP, at what time, and with what result? | CEM, THIRF, Investigation, Zero Trust | Activity Logs identity + object access (M-26-14 App B a–d) |
| What network flows (src/dst IP, ports, protocol, allow/deny, bytes) occurred through NSGs or VNets? | CEM, Hunting, THIRF | Network visibility and lateral movement detection |
| Who accessed or modified which Storage blobs/files or Key Vault secrets? | CEM, THIRF, Investigation | Data access and exfiltration detection |
| What requests were made through Application Gateway, API Management, or Load Balancer (method, path, source IP, status)? | CEM, Investigation | Application entry-point visibility |
| Can the sequence of Activity Logs, flow logs, and resource diagnostic logs be correlated to reconstruct an attack path? | THIRF, CSIRC | Full timeline reconstruction |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Azure Activity Logs (Administrative, Security, Policy) exported via Diagnostic Settings | Must Have | Native (export required) | Control-plane actions. Default retention is 90 days; export for longer retention. |
| Microsoft Entra ID audit and sign-in logs | Must Have | Enhanced | Identity and authentication events. |
| NSG Flow Logs or Virtual Network Flow Logs | Must Have | Enhanced | Capture allow and deny. Prefer version 2+ for packet/byte counts. Note NSG Flow Logs retirement timeline; migrate toward VNet Flow Logs. |
| Diagnostic Settings on sensitive resources (Storage, Key Vault, SQL, App Gateway, API Management) | Must Have for sensitive resources | Enhanced | Resource logs and audit categories. |
| Application Gateway / API Management access logs | Should Have (Must for public/partner) | Enhanced | Request-level visibility. |
| Azure Monitor / Log Analytics workspace ingestion | Should Have | Native | Centralized searchable store; also support export to external SIEM. |
| Storage account diagnostics / blob access | Should Have for sensitive storage | Enhanced | Via Diagnostic Settings. |

**Configuration baseline:** Diagnostic Settings at subscription and resource level routing to a central Log Analytics workspace and/or immutable Storage account, organization-wide coverage where possible, and external shipping via Cribl or equivalent.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| eventTimestamp / TimeGenerated | Event time | Timeline | `_time` | 2026-10-10T14:22:15Z | UTC |
| caller / identity.claims / userPrincipalName | Principal who performed the action | Identity binding | Authentication.user or Change.user | user@agency.gov or app-id | Critical for Zero Trust |
| operationName / action | Operation performed | What happened | Change.action | Microsoft.Compute/virtualMachines/write | |
| resourceId / resourceGroup | Target resource | Object accessed | Change.object | /subscriptions/.../resourceGroups/rg/providers/... | |
| callerIpAddress / sourceIP | Source IP | Attribution | Authentication.src or Network_Traffic.src | 10.1.2.3 | |
| status / resultType | Outcome | Success/failure | Change.status or Authentication.action | Succeeded, Failed | |
| properties (selective) | Additional context | Forensic detail | Custom | | Redact secrets |
| srcIp / destIp / srcPort / destPort / protocol / decision | Flow details | Network visibility | Network_Traffic.src, dest, ports, action | 10.0.1.5, A (allow), D (deny) | NSG/VNet Flow Logs |
| httpMethod / requestUri / statusCode | Request details | Application access | Web.http_method, uri_path, status | GET, /api/data, 200 | App Gateway / API Mgmt |
| subscriptionId / tenantId | Subscription and tenant | Multi-subscription correlation | Change.dest or custom | | |
| vendor_product | Source | Differentiation | Change.vendor_product | Azure Activity Log, NSG Flow Logs | |

## 6. CIM Alignment
**Primary CIM data models:**  
- **Change** and **Authentication** — Activity Logs and Entra ID events  
- **Network_Traffic** — NSG / VNet Flow Logs  
- **Web** — Application Gateway and API Management access logs  
- **Data Access** — Storage and Key Vault diagnostic logs  

**Key mappings:**  
- caller / identity → Authentication.user / Change.user  
- operationName + status → Change.action / status  
- source IP / flow tuples → Authentication.src / Network_Traffic fields  
- resourceId → Change.object  

Use field aliases and calculated fields for subscription, resource type, and outcome normalization.

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time detection of unexpected control-plane changes (RBAC, network rules, public access), denied flows, and anomalous data access. Metric alerts and Log Analytics queries feed the SOC. Searchable minimum 6 months.

**THIRF:** Full reconstruction of identity, resource operations, network path, and data access. Retrievable 12 months. Prefer immutable Storage archive plus hot searchable Log Analytics or external SIEM copy.

**CSIRC:** Authoritative Azure control-plane and network timeline required to scope credential compromise, data exfiltration, or lateral movement.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- Diagnostic Settings → central Log Analytics workspace and/or Storage account.  
- Flow Logs → Storage + optional Traffic Analytics.  
- Ship to Cribl Stream (preferred) or equivalent for routing, filtering, enrichment, and CIM normalization.  
- Ensure multi-subscription coverage and externalization outside the source subscription where possible.

**Common pitfalls:** Relying on default 90-day Activity Log retention without export; incomplete Diagnostic Settings on sensitive resources; NSG Flow Logs not enabled or only capturing allow; logs remaining only in the source subscription; missing Entra ID sign-in/audit logs.

**Gap-analysis checklist:**  
- [ ] Activity Logs exported via Diagnostic Settings (Administrative + Security)  
- [ ] Entra ID audit and sign-in logs collected  
- [ ] NSG or VNet Flow Logs enabled (allow + deny)  
- [ ] Diagnostic Settings on sensitive resources (Storage, Key Vault, etc.)  
- [ ] Key fields mapped to Change, Authentication, Network_Traffic, Web  
- [ ] Logs externalized to central archive and available to top-level SOC  
- [ ] 6-month searchable / 12-month retrievable met  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| Activity Logs exported (Diagnostic Settings) | | | Must | |
| Entra ID audit/sign-in logs | | | Must | |
| Flow Logs (NSG or VNet) enabled | | | Must | |
| Sensitive resource Diagnostic Settings | | | Must for HVA | |
| CIM normalization | | | Must | |
| Centralized archive + SOC access | | | Must | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

---

**References:** OMB M-26-14, CISA LRA, Azure Monitor / Activity Log / Diagnostic Settings / NSG Flow Logs documentation, Microsoft Entra ID logging, Splunk CIM models, FedRAMP and DoD SRG guidance for Azure Government.
