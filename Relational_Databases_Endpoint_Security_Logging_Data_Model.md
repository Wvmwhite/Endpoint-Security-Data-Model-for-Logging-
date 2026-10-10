# Endpoint Security Logging Data Model: Relational Databases

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Databases; secondary: Authentication, Change, Data Access), Zero Trust Visibility & Analytics, relevant DISA STIGs and CIS Benchmarks.

**Primary popular solutions in DoD / federal environments:**  
- Oracle Database (19c, 21c, 23ai) – still widely used for mission systems, often with Database Vault  
- Microsoft SQL Server (2019/2022) and Azure SQL Managed Instance  
- PostgreSQL (14–17) – increasingly the default for new builds (RDS, Aurora, Azure Database for PostgreSQL, EDB Postgres)  

**Typical deployment contexts:** Transactional systems of record, High Value Assets, classified/IL4–IL5 enclaves, FedRAMP High cloud services, and mission applications.

## 1. Category Overview
Relational databases store structured data and enforce integrity, authorization, and transactional consistency. Logging focuses on authentication, privilege changes, DDL/DML activity, and administrative actions so agencies can answer who accessed or modified what data, when, from where, and with what outcome.

## 2. Operational Purpose & Security Rationale
Deployed as systems of record for mission data. Primary security functions include authentication/authorization of database users, enforcement of least privilege, protection of sensitive data (encryption, RLS, TDE, Database Vault), and audit of all security-relevant activity.

Supports Zero Trust by providing identity-to-data binding and continuous verification of data access and administrative actions at the data layer.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who authenticated (success/failure), from which host/IP, using which method, and at what time? | CEM, THIRF, Investigation, Zero Trust | Identity & credential usage (M-26-14 App B a, b) |
| Who created, altered, or dropped users, roles, or privileges? | CEM, Hunting, THIRF | Privilege changes (App B d) |
| Who performed DDL (CREATE/ALTER/DROP) or sensitive DML (INSERT/UPDATE/DELETE/SELECT) on which objects? | CEM, THIRF, Investigation | Object access & change (App B c, j) |
| What SQL was executed, against which schema/object, and what was the result? | THIRF, Forensics | Reconstruction of activity |
| Were administrative or security-policy changes made (audit settings, encryption, Database Vault)? | CEM, CSIRC | Configuration integrity |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Unified Audit / SQL Server Audit / pgAudit (session + object) | Must Have | Enhanced (policy required) | Primary source. Cover logon, privilege, DDL, and sensitive DML. |
| Failed login / authentication events | Must Have | Native / policy | Brute-force and credential attacks |
| Privilege and role changes (GRANT/REVOKE, CREATE USER/ROLE) | Must Have | Policy | Privilege escalation detection |
| DDL events (schema changes) | Must Have | Policy | Change detection |
| Sensitive DML / object access (especially on HVA tables) | Should Have (Must for HVA) | Policy / Fine-Grained | Volume management required |
| Database error / alert logs | Should Have | Native | Context and failures |
| Administrative actions (backup, restore, encryption changes) | Should Have | Policy | Integrity and availability |

**Policy guidance:**  
- Oracle: Unified Audit policies for logon, privilege use, DDL, and security-relevant DML.  
- SQL Server: Server and database audit specifications (LOGIN_CHANGE_PASSWORD_GROUP, DATABASE_CHANGE_GROUP, SCHEMA_OBJECT_ACCESS_GROUP, etc.).  
- PostgreSQL: pgAudit with `pgaudit.log = 'ddl, role, write'` (add `read` selectively for HVA).

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| timestamp / event_time | Event time | Timeline | `_time` | 2026-10-10T14:22:15Z | NTP required |
| dbusername / server_principal_name / user_name | Database user | Identity | Databases.user or Authentication.user | APP_USER, sa | |
| os_username / client_host / host | Client OS user / host | Attribution | Databases.src_user or Authentication.src_user | jdoe, app-server01 | |
| client_ip / sourceIP / remote | Source IP | Network attribution | Databases.src or Authentication.src | 10.1.2.3 | |
| action_name / action_id / command | Action performed | What happened | Databases.action or Change.action | LOGON, CREATE TABLE, INSERT, SELECT | Map to success/failure |
| object_schema / object_name / relation | Target object | What was accessed | Databases.object or Data_Access.object | HR.EMPLOYEES, public.users | |
| sql_text / statement / query | SQL statement | Forensic detail | Databases.query or Data_Access.query | SELECT * FROM ... | Truncation/volume control |
| return_code / succeeded / status | Outcome | Success vs failure | Databases.status or Authentication.action | 0, success, failure | |
| privilege_used / roles | Privileges exercised | Privilege context | Custom | SELECT ANY TABLE | |
| session_id | Session identifier | Correlation | Databases.session_id | 12345 | |
| dest / database_name / instance | Database instance | Multi-instance correlation | Databases.dest or Inventory.dest | prod-db-01 | |
| vendor_product | Platform and version | Source differentiation | Databases.vendor_product | Oracle 19c, SQL Server 2022, PostgreSQL 16 | |

## 6. CIM Alignment
**Primary CIM data model:** **Databases** (tags: database, instance, etc.)  

**Secondary:**  
- Authentication (logon/logoff/failure)  
- Change (DDL, privilege changes)  
- Data Access (sensitive reads/writes)  

**Key mappings:**  
- User → Databases.user / Authentication.user  
- Action → Databases.action  
- Object → Databases.object  
- Query → Databases.query  
- Source IP/host → Databases.src  
- Status → Databases.status  

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time alerts on failed logons, privilege grants, unexpected DDL, or bulk sensitive DML. Searchable 6 months.

**THIRF:** Full reconstruction of who accessed or modified data, privilege escalation paths, and administrative changes. Retrievable 12 months. Externalize audit trails.

**CSIRC:** Authoritative data-layer timeline for data exfiltration or integrity investigations.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- Oracle: Unified Audit trail → syslog or file → Cribl Edge/Stream.  
- SQL Server: Audit to file or Windows Security log → Cribl.  
- PostgreSQL: pgAudit via PostgreSQL logs → Cribl.  
Use Cribl Stream for filtering, enrichment, and CIM normalization.

**Common pitfalls:** Audit policies too broad (volume explosion); failure to capture client IP/host; not externalizing logs; missing privilege and DDL coverage; incomplete HVA object auditing.

**Gap-analysis checklist:**  
- [ ] Authentication success/failure captured  
- [ ] Privilege and role changes captured  
- [ ] DDL captured  
- [ ] Sensitive object access captured (HVA)  
- [ ] Key fields mapped to Databases CIM  
- [ ] Logs externalized and available to SOC  
- [ ] 6/12 month retention met  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| Audit policy covering logon, privilege, DDL | | | Must | |
| Client IP / host captured | | | Must | |
| CIM Databases mapping | | | Must | |
| Externalized logs + SOC access | | | Must | |
| Sensitive DML / object audit (HVA) | | | Should | |
| 6 mo searchable / 12 mo retrievable | | | Must | |

---

**References:** OMB M-26-14, CISA LRA, Oracle Unified Audit, SQL Server Audit, pgAudit, Splunk CIM Databases data model.
