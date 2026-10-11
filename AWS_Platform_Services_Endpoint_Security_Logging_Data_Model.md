# Endpoint Security Logging Data Model: AWS Platform Services

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Network_Traffic, Change, Authentication, Web; secondary: Data Access), Zero Trust Visibility & Analytics, FedRAMP High / DoD IL4–IL5 guidance, AWS Well-Architected Security Pillar.

**Primary popular solutions in DoD / federal environments:**  
- AWS GovCloud (US) and commercial regions under FedRAMP High / IL4–IL5  
- Core logging foundation: AWS CloudTrail, Amazon CloudWatch Logs, VPC Flow Logs  
- Common supporting services used by hosted applications: Amazon S3, Amazon API Gateway, Elastic Load Balancing (ALB/NLB), Amazon SQS, AWS Transit Gateway, VPC endpoints  

**Typical deployment contexts:** Mission applications, microservices, hybrid/cloud-native systems, High Value Assets, and multi-account Organizations in GovCloud or FedRAMP High boundaries.

## 1. Category Overview
AWS Platform Services represent the control-plane and data-plane logging foundation required for any application hosted in AWS. The model focuses on the services that generate the authoritative record of who did what, network flows, and object/API access so agencies can meet CEM and THIRF outcomes without relying solely on application-level logs.

## 2. Operational Purpose & Security Rationale
These services are deployed to provide durable, centralized auditability of AWS API activity, network traffic, and data access. Primary security functions include:

- Identity-bound API call recording (CloudTrail)  
- Network flow visibility (VPC Flow Logs, Transit Gateway flow logs)  
- Object and request-level access logging (S3, API Gateway, ALB/NLB)  
- Message and queue activity (SQS)  

They support Zero Trust by enabling continuous verification of identity, network path, and resource access across the cloud boundary and by feeding the Visibility & Analytics pillar.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who (IAM principal, role, federated identity) performed which API action against which resource, from which source IP, at what time, and with what result? | CEM, THIRF, Investigation, Zero Trust | Core CloudTrail identity + object access (M-26-14 App B a–d) |
| What network flows (src/dst IP, ports, protocol, action ACCEPT/REJECT, bytes) occurred inside or across VPCs, including Transit Gateway paths? | CEM, Hunting, THIRF | Network visibility and lateral movement detection |
| Who accessed or modified which S3 objects or buckets (GetObject, PutObject, DeleteObject), from where, and with what outcome? | CEM, THIRF, Investigation | Data access and exfiltration detection |
| What API Gateway or load-balancer requests were made (method, path, source IP, status, latency, identity)? | CEM, Investigation | Application entry-point visibility |
| Can the sequence of CloudTrail, VPC Flow, and service access logs be correlated to reconstruct an attack path? | THIRF, CSIRC | Full timeline reconstruction |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| CloudTrail management events (all regions, multi-region trail) | Must Have | Native | Control-plane actions. Enable log file validation and Insights where useful. |
| CloudTrail data events (S3 object-level, Lambda, DynamoDB, SQS – selective) | Should Have (Must for HVA / sensitive data) | Enhanced | High volume; scope to sensitive resources. |
| VPC Flow Logs (ALL traffic, custom format with tags/next-hop where available) | Must Have | Native | Capture ACCEPT and REJECT. Prefer S3 or CloudWatch destination with external shipping. |
| Transit Gateway flow logs | Should Have | Native | When TGW is in the path. |
| S3 server access logs or CloudTrail data events for sensitive buckets | Must Have for sensitive buckets | Enhanced | Prefer CloudTrail data events for identity context. |
| API Gateway access logs (execution + access logging enabled) | Must Have for public/partner APIs | Enhanced | JSON format with requestId, sourceIp, method, path, status, principal. |
| ALB/NLB access logs | Should Have | Enhanced | Entry-point visibility. |
| CloudWatch Logs (application, Lambda, etc.) | Should Have | Native | Application and service logs; use subscription filters or export. |
| SQS / SNS data events (selective) | Nice to Have / Should for sensitive queues | Enhanced | Via CloudTrail data events. |

**Configuration baseline:** Organization-level CloudTrail trail, log file validation, S3 Object Lock (Compliance mode) or equivalent for immutability, VPC Flow Logs at VPC level with ALL traffic, and centralized log archive account.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| eventTime / timestamp | Event time | Timeline | `_time` | 2026-10-10T14:22:15Z | UTC, NTP-synced |
| userIdentity.arn / principalId | IAM principal or role | Identity binding | Authentication.user or Change.user | arn:aws:iam::123:role/AppRole | Critical for Zero Trust |
| eventName / action | API action or flow action | What happened | Change.action or Network_Traffic.action | RunInstances, GetObject, ACCEPT, REJECT | |
| eventSource / service | AWS service | Context | Change.app or custom | s3.amazonaws.com, ec2.amazonaws.com | |
| sourceIPAddress / srcaddr | Source IP | Attribution | Authentication.src or Network_Traffic.src | 10.1.2.3 or 203.0.113.10 | |
| requestParameters / responseElements (selective) | Resource identifiers and details | Object access | Change.object or Data_Access.object | bucket, key, instanceId | Redact secrets |
| errorCode / errorMessage / action | Outcome | Success/failure | Change.status or Authentication.action | AccessDenied, success | |
| vpcId / interfaceId / accountId | Network and account context | Correlation | Network_Traffic.dvc or custom | vpc-0abc, eni-123 | |
| srcaddr / dstaddr / srcport / dstport / protocol / bytes / packets | Flow details | Network visibility | Network_Traffic.src, dest, src_port, dest_port, transport, bytes | 10.0.1.5, 443, 6 | VPC Flow Logs |
| requestId / httpMethod / resourcePath / status | API request details | Application access | Web.http_method, uri_path, status | GET, /api/v1/data, 200 | API Gateway / ALB |
| dest / aws_account_id / region | Account and region | Multi-account correlation | Change.dest or Inventory.dest | 123456789012, us-gov-west-1 | |
| vendor_product | Source | Differentiation | Change.vendor_product or custom | AWS CloudTrail, VPC Flow Logs | |

**High-value calculated fields:** user_type (IAMUser, AssumedRole, FederatedUser), resource_arn, flow_direction, pkt-srcaddr/pkt-dstaddr (post-NAT).

## 6. CIM Alignment
**Primary CIM data models:**  
- **Change** and **Authentication** — CloudTrail management and identity events  
- **Network_Traffic** — VPC Flow Logs and Transit Gateway flow logs  
- **Web** — API Gateway access logs and ALB/NLB access logs  
- **Data Access** — S3 object-level and selective data events  

**Key mappings:**  
- userIdentity → Authentication.user / Change.user  
- eventName + errorCode → Change.action / status  
- sourceIPAddress / srcaddr → Authentication.src / Network_Traffic.src  
- resource identifiers → Change.object  
- Flow fields → Network_Traffic.src/dest/ports/bytes/action  

No single native “AWS” CIM model; use field aliases and tags. Recommend calculated fields for account, region, and resource type.

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time detection of unexpected API calls (privilege changes, public S3 access, security group modifications), rejected flows, anomalous data access, and API error spikes. CloudWatch metric filters and alerts feed the SOC. Searchable minimum 6 months.

**THIRF:** Full reconstruction of identity, API sequence, network path, and data access. Retrievable 12 months. Prefer immutable S3 archive (Object Lock Compliance) plus hot searchable copy.

**CSIRC:** Authoritative cloud control-plane and network timeline required to scope credential compromise, data exfiltration, or lateral movement in AWS.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- CloudTrail → S3 (centralized archive account) + optional CloudWatch Logs.  
- VPC Flow Logs → S3 or CloudWatch Logs.  
- Service access logs → CloudWatch Logs or S3.  
- Ship to Cribl Stream (preferred) or equivalent for routing, filtering, enrichment, redaction, and CIM normalization before SIEM/data lake.  
- Use organization trail, log file validation, and cross-account delivery.

**Common pitfalls:** Management events only (missing data events on sensitive S3); VPC Flow Logs set to ACCEPT only; logs remaining only in the source account; incomplete multi-region coverage; high-volume data events without filtering; missing identity context on S3 server access logs.

**Gap-analysis checklist:**  
- [ ] Organization or multi-region CloudTrail trail with log file validation  
- [ ] VPC Flow Logs enabled (ALL) on relevant VPCs  
- [ ] Sensitive S3 buckets have data events or equivalent access logging  
- [ ] API Gateway / load balancer access logging enabled where used  
- [ ] Key fields mapped to Change, Authentication, Network_Traffic, Web  
- [ ] Logs externalized to central archive and available to top-level SOC  
- [ ] 6-month searchable / 12-month retrievable met (immutable preferred)  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| CloudTrail management events (org/multi-region + validation) | | | Must | |
| VPC Flow Logs (ALL traffic) | | | Must | |
| Sensitive resource data events (S3, etc.) | | | Must for HVA | |
| API Gateway / ALB access logs | | | Should / Must if public | |
| CIM normalization (Change, Network_Traffic, Web) | | | Must | |
| Centralized immutable archive + SOC access | | | Must | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

**Analyst notes:** Document accounts in scope, trail configuration, flow log format and destinations, data event selectors, and any Cribl pipelines used for normalization.

---

**References:**  
- OMB M-26-14 and CISA LRA  
- AWS CloudTrail, VPC Flow Logs, S3, API Gateway, and ELB documentation  
- AWS Well-Architected Security Pillar (logging)  
- Splunk CIM Change, Authentication, Network_Traffic, and Web data models  
- FedRAMP and DoD SRG guidance for AWS GovCloud  

This model serves as the foundational logging baseline for any application hosted in AWS and should be used together with application-specific, OS, and Kubernetes models as appropriate.
