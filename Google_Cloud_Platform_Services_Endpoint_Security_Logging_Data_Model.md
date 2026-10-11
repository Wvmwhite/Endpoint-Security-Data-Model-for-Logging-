# Endpoint Security Logging Data Model: Google Cloud Platform Services

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Change, Authentication, Network_Traffic, Web; secondary: Data Access), Zero Trust Visibility & Analytics, FedRAMP High guidance (Assured Workloads), Google Cloud compliance recommendations.

**Primary popular solutions in DoD / federal environments:**  
- Google Cloud with Assured Workloads (FedRAMP High) and related federal offerings  
- Core logging foundation: Cloud Audit Logs, Cloud Logging, VPC Flow Logs  
- Common supporting services: Cloud Storage, Cloud Load Balancing, API Gateway / Apigee, Pub/Sub, Cloud SQL, Identity and Access Management (IAM), Cloud KMS  

**Typical deployment contexts:** Mission applications, data analytics, microservices, High Value Assets, and multi-project Organizations under Assured Workloads or FedRAMP High boundaries.

## 1. Category Overview
Google Cloud Platform Services represent the control-plane and data-plane logging foundation required for any application hosted in Google Cloud. The model focuses on the services that generate the authoritative record of who did what, network flows, and resource/object access so agencies can meet CEM and THIRF outcomes.

## 2. Operational Purpose & Security Rationale
These services provide durable, centralized auditability of Google Cloud control-plane activity, network traffic, and data access. Primary security functions include:

- Identity-bound API call recording (Cloud Audit Logs – Admin Activity and Data Access)  
- Network flow visibility (VPC Flow Logs)  
- Resource and object access logging (Cloud Storage, Load Balancing, API Gateway)  
- Centralized aggregation via Cloud Logging sinks  

They support Zero Trust by enabling continuous verification of identity, network path, and resource access across the cloud boundary.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who (user, service account, or federated identity) performed which API action against which resource, from which source IP, at what time, and with what result? | CEM, THIRF, Investigation, Zero Trust | Cloud Audit Logs identity + object access (M-26-14 App B a–d) |
| What network flows (src/dst IP, ports, protocol, bytes, packets) occurred inside or across VPCs? | CEM, Hunting, THIRF | Network visibility and lateral movement detection |
| Who accessed or modified which Cloud Storage objects or sensitive resources? | CEM, THIRF, Investigation | Data access and exfiltration detection |
| What requests were made through Cloud Load Balancing or API Gateway (method, path, source IP, status)? | CEM, Investigation | Application entry-point visibility |
| Can the sequence of Audit Logs, VPC Flow Logs, and service logs be correlated to reconstruct an attack path? | THIRF, CSIRC | Full timeline reconstruction |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Cloud Audit Logs – Admin Activity | Must Have | Native (always on) | Control-plane configuration changes. Retained 400 days by default. |
| Cloud Audit Logs – Data Access (selective for sensitive resources) | Should Have (Must for HVA) | Enhanced | High volume; enable for Cloud Storage, BigQuery, Cloud SQL, etc. as needed. |
| VPC Flow Logs (enabled on subnets or organization level) | Must Have | Enhanced | Capture relevant traffic with metadata. Export via sinks. |
| Cloud Logging sinks to central project / BigQuery / Pub/Sub / external | Must Have | Enhanced | Centralized collection and external shipping. |
| Cloud Storage access / data access logs | Must Have for sensitive buckets | Enhanced | Via Audit Logs Data Access or object-level logging. |
| Cloud Load Balancing / API Gateway access logs | Should Have (Must for public) | Enhanced | Request-level visibility. |
| IAM and Organization Policy audit events | Must Have | Native (part of Admin Activity) | Privilege and policy changes. |

**Configuration baseline:** Organization-level or folder-level sinks, Admin Activity always captured, selective Data Access on sensitive resources, VPC Flow Logs enabled with appropriate aggregation and metadata, and export to a central logging project with retention controls.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| timestamp / receiveTimestamp | Event time | Timeline | `_time` | 2026-10-10T14:22:15.123Z | UTC |
| protoPayload.authenticationInfo.principalEmail | Caller identity | Identity binding | Authentication.user or Change.user | user@agency.gov or sa@project.iam.gserviceaccount.com | Critical for Zero Trust |
| protoPayload.methodName / serviceName | API method and service | What happened | Change.action | storage.objects.get, compute.instances.insert | |
| protoPayload.resourceName | Target resource | Object accessed | Change.object | projects/.../buckets/my-bucket/objects/file | |
| protoPayload.requestMetadata.callerIp | Source IP | Attribution | Authentication.src or Network_Traffic.src | 10.1.2.3 or 203.0.113.10 | May be redacted in some cases |
| protoPayload.status / severity | Outcome | Success/failure | Change.status | 0 (OK), error codes | |
| jsonPayload.connection.src_ip / dest_ip / src_port / dest_port / protocol | Flow details | Network visibility | Network_Traffic.src, dest, ports, transport | 10.0.1.5, 443, 6 | VPC Flow Logs |
| httpRequest.requestMethod / requestUrl / status | Request details | Application access | Web.http_method, uri_path, status | GET, /api/v1, 200 | Load Balancing / API Gateway |
| resource.labels.project_id / location | Project and location | Multi-project correlation | Change.dest or custom | my-project, us-central1 | |
| vendor_product | Source | Differentiation | Change.vendor_product | Google Cloud Audit Logs, VPC Flow Logs | |

**High-value fields:** authenticationInfo.principalEmail, methodName, resourceName, callerIp, connection 5-tuple, bytes_sent / packets_sent.

## 6. CIM Alignment
**Primary CIM data models:**  
- **Change** and **Authentication** — Cloud Audit Logs (Admin Activity and identity events)  
- **Network_Traffic** — VPC Flow Logs  
- **Web** — Load Balancing and API Gateway access logs  
- **Data Access** — Cloud Storage and other Data Access audit logs  

**Key mappings:**  
- principalEmail → Authentication.user / Change.user  
- methodName + status → Change.action / status  
- callerIp / src_ip → Authentication.src / Network_Traffic.src  
- resourceName → Change.object  

Use field aliases and calculated fields for project, service, and outcome normalization. Cloud Logging structured logs map cleanly to CIM.

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time detection of unexpected Admin Activity (IAM changes, network modifications, public access), anomalous flows, and sensitive data access. Cloud Monitoring alerts and log-based metrics feed the SOC. Searchable minimum 6 months.

**THIRF:** Full reconstruction of identity, API sequence, network path, and data access. Retrievable 12 months. Use sinks to central project, BigQuery, or external immutable storage.

**CSIRC:** Authoritative Google Cloud control-plane and network timeline required to scope credential compromise, data exfiltration, or lateral movement.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- Cloud Audit Logs and VPC Flow Logs → Cloud Logging.  
- Organization or folder sinks to a central logging project, Pub/Sub, or BigQuery.  
- Ship to Cribl Stream (preferred) or equivalent for routing, filtering, enrichment, and CIM normalization.  
- Ensure Assured Workloads or equivalent controls for FedRAMP High.

**Common pitfalls:** Data Access logs not enabled on sensitive resources; VPC Flow Logs not enabled or filtered too aggressively; logs remaining only in the source project; incomplete organization-level sinks; missing principalEmail or callerIp in some event types.

**Gap-analysis checklist:**  
- [ ] Admin Activity Audit Logs captured (always on)  
- [ ] Selective Data Access logs enabled for sensitive resources  
- [ ] VPC Flow Logs enabled on relevant subnets/networks  
- [ ] Centralized sinks configured and logs externalized  
- [ ] Key fields mapped to Change, Authentication, Network_Traffic, Web  
- [ ] Logs available to top-level SOC  
- [ ] 6-month searchable / 12-month retrievable met  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| Admin Activity Audit Logs | | | Must | |
| Selective Data Access logs (HVA) | | | Must for HVA | |
| VPC Flow Logs enabled | | | Must | |
| Centralized sinks + external shipping | | | Must | |
| CIM normalization | | | Must | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

---

**References:** OMB M-26-14, CISA LRA, Google Cloud Audit Logs, VPC Flow Logs, and Cloud Logging documentation, Assured Workloads / FedRAMP guidance, Splunk CIM models.
