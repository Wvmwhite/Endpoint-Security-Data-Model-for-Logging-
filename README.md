# Endpoint Security Logging Data Models for OMB M-26-14 Compliance

Standardized, technology-specific Endpoint Security Logging Data Models designed for U.S. federal civilian and DoD environments.

These models define the events and critical attributes that must be captured from common technical solutions so agencies can:

- Meet **OMB Memorandum M-26-14** outcomes (Continuous Event Monitoring – CEM + Threat Hunting, Investigation, Response, and Forensics – THIRF)
- Support after-the-fact investigations and Zero Trust initiatives
- Achieve normalized, searchable data aligned to the **Splunk Common Information Model (CIM)** (usable across SIEM and analytics platforms)
- Enable CSIRC / incident response capabilities
- Answer the right security and investigative questions based on why the technology was deployed

The models are practical comparison baselines: an analyst can take a customer’s actual technical stack, compare it against the relevant model(s), identify gaps, and define exactly what logs and fields must be collected and normalized.

## Solution Space

Collection, routing, transformation, and normalization in the recommended architecture leverage **Cribl Stream** and **Cribl Edge** (in addition to or instead of direct Splunk Universal Forwarders). 

- **Cribl Edge** handles endpoint and node-level collection with lightweight agents.  
- **Cribl Stream** provides centralized routing, filtering, enrichment, and schema normalization to CIM-aligned fields before delivery to SIEM, data lakes, or analytics platforms.  

This approach supports cost-efficient, flexible pipelines that meet M-26-14 searchable (6 months) and retrievable (12 months) requirements while reducing unnecessary ingest volume.

## Alignment & Authoritative Sources

- OMB Memorandum M-26-14 (Ensuring Effective and Efficient Agency Logging and Network Visibility to Defend Against Evolving Cyber Threats) – rescinds M-21-31
- CISA Logging Reference Architecture (LRA)
- Splunk Common Information Model (CIM) – used as the primary normalization target
- Zero Trust Maturity Model (Visibility & Analytics pillar)
- Relevant DISA STIGs, CIS Benchmarks, and NSA/CISA guidance

## Current Models

| Technology Category | Primary Solutions Covered | Status | File |
|---------------------|---------------------------|--------|------|
| Web Servers | IIS, Apache, Nginx | Complete | [Web_Servers_Endpoint_Security_Logging_Data_Model.md](Web_Servers_Endpoint_Security_Logging_Data_Model.md) |
| Windows Operating Systems | Windows Server 2025/2022/2019, Windows 11/10 | Complete | [Windows_OS_Endpoint_Security_Logging_Data_Model.md](Windows_OS_Endpoint_Security_Logging_Data_Model.md) |
| Linux Operating Systems | RHEL 9/8, Rocky/AlmaLinux, Ubuntu LTS | Complete | [Linux_OS_Endpoint_Security_Logging_Data_Model.md](Linux_OS_Endpoint_Security_Logging_Data_Model.md) |
| macOS | Tahoe 26.x, Sequoia 15.x, Golden Gate 27.x | Complete | [macOS_Endpoint_Security_Logging_Data_Model.md](macOS_Endpoint_Security_Logging_Data_Model.md) |
| Kubernetes Implementations | OpenShift, RKE2/RKE Government, EKS, AKS, GKE | Complete | [Kubernetes_Endpoint_Security_Logging_Data_Model.md](Kubernetes_Endpoint_Security_Logging_Data_Model.md) |
| Relational Databases | Oracle, Microsoft SQL Server, PostgreSQL | Complete | [Relational_Databases_Endpoint_Security_Logging_Data_Model.md](Relational_Databases_Endpoint_Security_Logging_Data_Model.md) |
| NoSQL Databases | MongoDB (primary), Redis, Elasticsearch, DynamoDB, etc. | Complete | [NoSQL_Databases_Endpoint_Security_Logging_Data_Model.md](NoSQL_Databases_Endpoint_Security_Logging_Data_Model.md) |
| AWS Platform Services | CloudTrail, CloudWatch Logs, VPC Flow Logs, S3, API Gateway, ALB/NLB, SQS, Transit Gateway | Complete | [AWS_Platform_Services_Endpoint_Security_Logging_Data_Model.md](AWS_Platform_Services_Endpoint_Security_Logging_Data_Model.md) |
| Azure Platform Services | Activity Logs, Diagnostic Settings, NSG/VNet Flow Logs, Entra ID, Storage, App Gateway, API Management | Complete | [Azure_Platform_Services_Endpoint_Security_Logging_Data_Model.md](Azure_Platform_Services_Endpoint_Security_Logging_Data_Model.md) |
| Google Cloud Platform Services | Cloud Audit Logs, VPC Flow Logs, Cloud Logging, Cloud Storage, Load Balancing, API Gateway | Complete | [Google_Cloud_Platform_Services_Endpoint_Security_Logging_Data_Model.md](Google_Cloud_Platform_Services_Endpoint_Security_Logging_Data_Model.md) |
| Firewalls / NGFWs | Palo Alto Networks, Cisco Secure Firewall (FTD/ASA), Fortinet FortiGate | Complete | [Firewalls_NGFWs_Endpoint_Security_Logging_Data_Model.md](Firewalls_NGFWs_Endpoint_Security_Logging_Data_Model.md) |
| F5 BIG-IP LTM and GTM | F5 BIG-IP Local Traffic Manager and Global Traffic Manager | Complete | [F5_BIG-IP_LTM_GTM_Endpoint_Security_Logging_Data_Model.md](F5_BIG-IP_LTM_GTM_Endpoint_Security_Logging_Data_Model.md) |

## Visual Example: Linux OS Data Model

The diagram below illustrates the structure of a typical model (using Linux OS as the example). It shows the flow from log sources through critical attributes to CIM-aligned outcomes that support CEM and THIRF.

![Linux OS Endpoint Security Logging Data Model](Linux_OS_Data_Model_Diagram.png)

<img width="2065" height="1375" alt="image" src="https://github.com/user-attachments/assets/c79815c8-fe1d-4ada-a6d5-4d040a5636a6" />


This pattern (sources → critical fields → CIM mapping → CEM/THIRF outcomes) is consistent across all models in the repository.



Additional categories (Firewalls/NGFWs, Proxies/Secure Web Gateways, Routers and Network Devices, etc.) are planned.

## Required Structure of Every Model

Each model follows a consistent structure:

1. Category Overview
2. Operational Purpose & Security Rationale
3. Key Questions the Model Must Answer (mapped to CEM / THIRF / Investigation / Zero Trust)
4. Required Event Classes / Log Sources (with priority: Must Have / Should Have / Nice to Have)
5. Critical Attributes / Fields Table (with CIM mappings)
6. CIM Alignment
7. CEM, THIRF & CSIRC Enablement Notes
8. Collection, Normalization & Maturity Guidance (including gap-analysis checklist)
9. Stack Comparison Template

## How to Use These Models

1. Identify the relevant technology category/model for the customer’s stack.
2. Use the **Stack Comparison Template** to evaluate the live implementation.
3. Identify gaps in event classes, critical fields, CIM normalization, retention, and SOC availability.
4. Define collection (Cribl Edge / Stream or equivalent), parsing, routing, and retention requirements to close the gaps.
5. Measure contribution to the Logging Maturity Model elements (Inventory Visibility, Collection Coverage, Collection Operations, Data Retention, Log Management).

Retention baseline per M-26-14:
- Actively searchable for a minimum of **6 months** (CEM)
- Retrievable for a minimum of **12 months** (THIRF)

## Contributing

This is a living set of models. Contributions that improve accuracy, add popular federal/DoD solutions, refine CIM mappings, expand coverage, or improve Cribl Stream/Edge pipeline guidance are welcome. Please open an issue or pull request.

## References

- [OMB Memorandum M-26-14](https://www.whitehouse.gov/wp-content/uploads/2026/05/M-26-14-Ensuring-Effective-and-Efficient-Agency-Logging-and-Network-Visibility-to-Defend-Against-Evolving-Cyber-Threats.pdf)
- CISA Logging Reference Architecture
- Splunk CIM Documentation
- Cribl Stream and Cribl Edge documentation
- Relevant DISA STIGs and CIS Benchmarks

## License

This content is released under the [MIT License](LICENSE) (or your preferred open-source license). Feel free to use, adapt, and share.

---

**Maintained as a practical resource for federal cybersecurity architects, logging engineers, and SOC analysts.**
