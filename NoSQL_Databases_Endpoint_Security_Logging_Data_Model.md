# Endpoint Security Logging Data Model: NoSQL Databases

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Databases; secondary: Authentication, Change, Data Access), Zero Trust Visibility & Analytics.

**Primary popular solutions in DoD / federal environments:**  
- MongoDB (Enterprise and Atlas for Government – FedRAMP Moderate/High capable) – most common document database  
- Redis / Valkey (caching, session stores)  
- Elasticsearch / OpenSearch (search and logging backends)  
- Amazon DynamoDB / DocumentDB, Azure Cosmos DB (cloud-native)  
- Cassandra (select high-scale use cases)  

**Typical deployment contexts:** Modern application backends, microservices data stores, search/analytics, caching layers, and FedRAMP cloud services supporting mission systems.

## 1. Category Overview
NoSQL databases provide flexible, scalable data models (document, key-value, wide-column, search). Logging focuses on authentication, authorization checks, administrative operations, and data access so agencies can reconstruct who accessed or modified what data and detect anomalous activity.

## 2. Operational Purpose & Security Rationale
Deployed for developer agility, horizontal scale, and specialized workloads (documents, search, caching). Security functions include user/role authentication, fine-grained authorization, encryption (including client-side field-level), and audit of operations.

Supports Zero Trust by binding identity to data operations and enabling continuous verification of access patterns at the application data layer.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who authenticated (success/failure), from which IP, using which mechanism? | CEM, THIRF, Investigation, Zero Trust | Identity (M-26-14 App B a, b) |
| Who performed administrative actions (create/drop user/role, create/drop collection/database, index changes)? | CEM, Hunting, THIRF | Privilege and structure changes (App B d) |
| Who read or modified data in which database/collection/document (authCheck success/failure)? | CEM, THIRF | Data access (App B c, j) – volume controlled |
| What was the command/operation and result? | THIRF, Forensics | Reconstruction |
| Were replication, sharding, or configuration changes made? | CEM, Investigation | Availability and integrity |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Audit logs (authenticate, authCheck, administrative actions) | Must Have | Enhanced (audit enabled + filter) | Primary source. MongoDB Enterprise/Atlas audit is the reference. |
| Authentication success and failure | Must Have | Audit filter | Brute-force detection |
| User/role/privilege management | Must Have | Audit | Privilege changes |
| Schema / collection / database create/drop | Must Have | Audit | Structure changes |
| Data access (authCheck for CRUD) – failures always; successes selective | Should Have (Must for HVA) | Audit filter + auditAuthorizationSuccess | High volume – filter carefully |
| Server logs / slow query / error logs | Should Have | Native | Context |
| Replication / sharding / config changes | Should Have | Audit | Cluster integrity |

**MongoDB guidance:** Enable auditing; use filters for authenticate, createUser/dropUser, createCollection/dropCollection, and selective authCheck. Prefer OCSF or JSON output for easier parsing.

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| ts / timestamp | Event time | Timeline | `_time` | 2026-10-10T14:22:15.123Z | |
| users.user / actor.user.name | Authenticated user | Identity | Databases.user or Authentication.user | appuser, admin | |
| remote.ip / src_endpoint.ip | Client source IP | Attribution | Databases.src or Authentication.src | 10.1.2.3 | |
| atype / activity | Action type | What happened | Databases.action | authenticate, authCheck, createCollection, dropUser | |
| param.command / param.ns | Command and namespace | Object and operation detail | Databases.object or Data_Access.object | find, db.collection | |
| result | Outcome code | Success/failure | Databases.status | 0 (success), 18 (auth failed) | |
| roles | Roles held by user | Authorization context | Custom | readWrite, clusterAdmin | |
| local.ip / dest | Server/node identity | Correlation | Databases.dest | 10.0.0.5:27017 | |
| vendor_product | Platform and version | Source differentiation | Databases.vendor_product | MongoDB 7.0, Atlas | |
| param.args (selective) | Command arguments | Forensic detail | Databases.query or custom | | Redact sensitive fields |

## 6. CIM Alignment
**Primary CIM data model:** **Databases**  

**Secondary:** Authentication (authenticate events), Change (admin/schema operations), Data Access (CRUD).

**Key mappings:**  
- User → Databases.user  
- atype / command → Databases.action  
- Namespace / collection → Databases.object  
- Source IP → Databases.src  
- Result → Databases.status  

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Alerts on failed authentication, unexpected user/role creation, collection drops, or anomalous data access patterns. Searchable 6 months.

**THIRF:** Reconstruct who accessed which collections/documents and what administrative changes occurred. Retrievable 12 months. Externalize audit logs.

**CSIRC:** Data-layer timeline for document stores and application backends.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- MongoDB: Audit to JSON/file/syslog or Atlas export → Cribl Edge/Stream.  
- Other NoSQL: Equivalent audit or access logs via agents or cloud APIs.  
Cribl Stream for filtering, redaction, and CIM normalization.

**Common pitfalls:** Auditing disabled by default; enabling full authCheck success without filters (volume); not capturing source IP; failure to externalize; incomplete administrative action coverage.

**Gap-analysis checklist:**  
- [ ] Authentication success/failure captured  
- [ ] User/role management captured  
- [ ] Collection/database DDL captured  
- [ ] Selective data access (authCheck) for HVA  
- [ ] Key fields mapped to Databases CIM  
- [ ] Logs externalized and available to SOC  
- [ ] 6/12 month retention met  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| Audit enabled with authentication + admin actions | | | Must | |
| Source IP captured | | | Must | |
| CIM Databases mapping | | | Must | |
| Externalized logs + SOC access | | | Must | |
| Selective data access auditing (HVA) | | | Should | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

---

**References:** OMB M-26-14, CISA LRA, MongoDB Auditing documentation, Splunk CIM Databases data model.
