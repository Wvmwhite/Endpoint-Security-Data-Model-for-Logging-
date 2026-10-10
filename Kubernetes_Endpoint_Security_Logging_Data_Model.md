# Endpoint Security Logging Data Model: Kubernetes Implementations

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA LRA, Splunk CIM (primary: Change and Authentication; secondary: Endpoint, Inventory, Network_Traffic), Zero Trust Visibility & Analytics, NSA/CISA Kubernetes Hardening Guidance, DISA STIGs, CIS Kubernetes Benchmark.

**Primary popular solutions in DoD / federal environments:**  
- Red Hat OpenShift (Container Platform, Dedicated, ROSA on AWS GovCloud, Azure Red Hat OpenShift) – strong presence with FedRAMP High / IL4/IL5  
- SUSE Rancher Kubernetes Engine 2 (RKE2) / RKE Government – hardened, STIG-validated distributions common in DoD  
- Amazon EKS (GovCloud) and Azure AKS (Azure Government) – managed control planes with FedRAMP High / IL5 support  
- Google GKE (FedRAMP High) and self-managed clusters (kubeadm, K3s for edge)  
- Platform One / Iron Bank ecosystems for DoD container supply chain  

**Typical deployment contexts:** Application platforms for mission systems, DevSecOps pipelines, classified/IL4–IL5 enclaves, edge/tactical nodes, hybrid cloud, and High Value Asset supporting systems.

## 1. Category Overview
Kubernetes (and distributions thereof) orchestrates containerized workloads. Logging focuses on the API server as the control plane chokepoint, node/container runtime activity, admission and policy decisions, and supporting identity/RBAC changes. Complements OS-level models (Windows/Linux nodes) and application logs.

## 2. Operational Purpose & Security Rationale
Kubernetes is deployed to provide scalable, declarative orchestration of containerized applications, service discovery, and infrastructure automation. It is a primary control plane for modern application estates.

Security functions include:  
- Authentication and authorization of all API requests (users, service accounts, nodes)  
- Enforcement of RBAC, Pod Security, network policies, and admission controllers  
- Lifecycle management of pods, deployments, secrets, and configurations  
- Support for Zero Trust by providing identity-to-resource binding at the orchestration layer and enabling continuous verification of workload behavior  

Without high-fidelity API audit logs and node telemetry, agencies cannot reconstruct “who created/modified what resource, from where, and with what outcome,” nor detect privilege escalation, cryptomining, or lateral movement inside the cluster.

## 3. Key Questions the Model Must Answer
| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who (user, service account, or node) performed an API action (verb) against which resource (kind, namespace, name), from which source, at what time, and with what result? | CEM, THIRF, Investigation, Zero Trust | Core identity + object access (M-26-14 App B a, b, c) |
| Were RBAC roles, RoleBindings, ClusterRoles, ServiceAccounts, or Secrets created, modified, or deleted? | CEM, Threat Hunting, THIRF | Privilege and identity changes (App B d) |
| Were pods created with privileged settings, hostPath, or suspicious images, or were exec/attach calls made? | CEM, Hunting, Forensics | Attack vector and lateral movement (App B j) |
| What admission controller or policy decisions (allowed/denied) occurred? | CEM, Automated Alerting | Security tooling telemetry (App B f, k) |
| What container processes ran, with what parent, and did runtime security tools flag anomalous behavior? | CEM, THIRF | Correlate with Endpoint model on nodes |
| Can the sequence of API calls and node events be reconstructed to determine initial access and scope of compromise? | THIRF, CSIRC | Attack reconstruction |

## 4. Required Event Classes / Log Sources
| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Kubernetes API Server Audit Logs | Must Have | Native (policy required; disabled by default) | Primary source. Use audit policy with Metadata for most, Request/RequestResponse for critical resources (RBAC, Secrets metadata only, pods/exec). File or webhook backend. |
| Cluster Events (kubectl get events or event exporter) | Should Have | Native (short retention in etcd) | Useful context; persist externally. |
| Node OS logs (auditd, syslog, Windows Security) | Must Have | Native | Covered by OS models; essential for process/file activity on workers. |
| Container runtime / CRI logs (containerd, CRI-O) | Should Have | Native | Pod stdout/stderr and runtime events. |
| Runtime security (Falco, Tetragon, or EDR) | Should Have (Must for HVA/Internet-facing) | Enhanced | Process, network, and syscall anomalies inside pods. |
| Admission controller / OPA/Kyverno / Gatekeeper logs | Should Have | Enhanced | Policy allow/deny decisions. |
| etcd audit or access logs | Nice to Have | Enhanced | Sensitive; usually not required if API audit is comprehensive. |
| Image registry / supply chain (Iron Bank, etc.) | Should Have | External | Pull events, vulnerability scan results. |

**Audit policy guidance (federal baseline):** Metadata for all; RequestResponse (or Request) for Roles, RoleBindings, ClusterRoles, ClusterRoleBindings, ServiceAccounts, Secrets (Metadata only to avoid body), pods (create/delete/exec/attach), and sensitive ConfigMaps. Omit high-volume noise (health checks, kube-proxy watches).

## 5. Critical Attributes / Fields Table
| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| timestamp | Audit event time | Timeline correlation | `_time` | 2026-10-10T14:22:15.123Z | Ensure NTP on control plane |
| user.username / user.uid | Authenticated principal or service account | Identity binding | Authentication.user or Change.user | system:serviceaccount:ns:sa or user@agency.gov | Critical for Zero Trust |
| user.groups | Groups associated with user | Authorization context | Custom | system:masters | |
| verb | API verb | Action type | Change.action or custom | create, update, patch, delete, get, list, watch, exec | Map create/update/delete → change actions |
| objectRef.resource / kind | Resource type | Object accessed | Change.object or custom | pods, secrets, roles, rolebindings | |
| objectRef.namespace / name | Namespace and resource name | Specific target | Change.object_id or custom | default/my-pod | |
| sourceIPs | Client source IP(s) | Attribution and lateral movement | Authentication.src or Change.src | ["10.1.2.3"] | |
| responseStatus.code / status | HTTP or API status | Success/failure outcome | Change.status or Authentication.action | 200, 403, 401 | |
| requestURI | Full request URI | Context | Custom | /api/v1/namespaces/default/pods | |
| stage | Audit stage | Request lifecycle | Custom | RequestReceived, ResponseComplete | Prefer ResponseComplete for final outcome |
| level | Audit level applied | Fidelity indicator | Custom | Metadata, Request, RequestResponse | |
| annotations / requestObject (selective) | Additional context or body (when logged) | Forensics detail | Custom | | Avoid logging full Secret bodies |
| dest / cluster | Cluster or API server identity | Multi-cluster correlation | Change.dest or Inventory.dest | prod-cluster-1 | |
| vendor_product | Distribution and version | Source differentiation | Change.vendor_product | OpenShift 4.16, RKE2 1.31 | |
| action | Normalized action | Alerting consistency | Change.action | created, modified, deleted, allowed, denied | Derive from verb + status |

**High-value technology-specific fields:** objectRef.subresource (exec, attach, log), impersonatedUser, userAgent, annotations["authorization.k8s.io/decision"], and runtime security fields (process, container_id, image) when available from Falco/EDR.

## 6. CIM Alignment
**Primary CIM data models:**  
- **Change** (tag=change + endpoint or network as appropriate) for resource create/update/delete/patch  
- **Authentication** (tag=authentication) for authn/authz failures and token reviews  

**Secondary:**  
- **Endpoint** (process report, endpoint filesystem) for node/container process and file events (correlate with OS model)  
- **Inventory** for cluster, node, pod, and namespace inventory  
- **Network_Traffic** or **Intrusion_Detection** for CNI or runtime network events  
- **Alerts** for admission denials and runtime detections  

**Key mappings:**  
- user.username → Change.user / Authentication.user  
- verb + status → Change.action / Authentication.action  
- objectRef.resource + name → Change.object  
- sourceIPs → Change.src / Authentication.src  
- responseStatus.code → Change.status  

No native Kubernetes CIM data model exists; use field aliases and tags to populate existing models. Recommend calculated fields for cluster, namespace, and resource_kind.

## 7. CEM, THIRF & CSIRC Enablement Notes
**CEM:** Real-time detection of RBAC modifications, privileged pod creations, exec into pods, repeated 403s, admission denials, and anomalous service account activity. Feed API audit (webhook preferred for low latency) and runtime security into SIEM. Searchable minimum 6 months.

**THIRF:** Full reconstruction of API call sequences, privilege escalation paths, workload compromise timelines, and correlation with node OS logs and identity systems. Retrievable 12 months. Externalize logs so the cluster cannot delete them.

**Retention:** 6 months searchable / 12 months retrievable baseline. Higher fidelity or longer retention for HVA clusters. Protect integrity (immutable storage, access controls).

**CSIRC:** Provides the authoritative control-plane timeline needed to scope container escapes, secret access, or lateral movement within the cluster.

## 8. Collection, Normalization & Maturity Guidance
**Recommended collection:**  
- API server: --audit-policy-file + --audit-log-path (file) or --audit-webhook-config-file (preferred for SIEM).  
- Forward via Fluent Bit, Filebeat, or distribution-native collectors (OpenShift Logging, Rancher, cloud provider integrations).  
- Node logs via OS model collection methods.  
- Runtime security via dedicated agents.  
- Ensure durable transport and external storage per LRA.

**Common pitfalls:** Audit logging disabled or set to None; RequestResponse on high-volume resources causing volume explosion; logging full Secret bodies; failure to externalize logs; missing correlation fields (cluster, namespace); incomplete node OS coverage.

**Maturity contribution:** Supports Inventory Visibility (cluster/node coverage), Collection Coverage, Collection Operations, Data Retention, and Log Management (CIM normalization of API events).

**Gap-analysis checklist:**  
- [ ] API audit policy enabled with appropriate levels for critical resources  
- [ ] Logs externalized and available to top-level SOC  
- [ ] Key fields mapped to Change/Authentication CIM  
- [ ] Node OS logging (per OS models) in place  
- [ ] Runtime security or equivalent for HVA  
- [ ] 6/12 month retention met  
- [ ] Coverage tracked against cluster inventory  

## 9. Stack Comparison Template
| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| API Server audit policy + critical resource coverage | | | Must | |
| Externalized audit logs (file or webhook) | | | Must | |
| CIM Change/Authentication mapping | | | Must | |
| Node OS logs collected (link to OS models) | | | Must | |
| Runtime security events (Falco/EDR) | | | Should | |
| Searchable 6 mo / Retrievable 12 mo + SOC access | | | Must | |
| Admission policy decision logging | | | Should | |

**Analyst notes:** Document distribution (OpenShift, RKE2, EKS, etc.), audit policy content, collection path, any filtering, and known limitations (e.g., managed control plane log availability).

---

**References:**  
- OMB M-26-14 and CISA LRA  
- Kubernetes Auditing documentation  
- NSA/CISA Kubernetes Hardening Guidance  
- DISA STIGs and CIS Kubernetes Benchmark  
- Splunk CIM Change and Authentication data models  

This model is a living baseline and should be cross-referenced with the Windows and Linux OS models for complete node coverage.
