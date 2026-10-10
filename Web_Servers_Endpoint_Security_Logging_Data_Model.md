# Endpoint Security Logging Data Model: Web Servers (IIS, Apache, Nginx)

**Version:** 1.0  
**Date:** 2026-10-10  
**Alignment:** OMB M-26-14 (CEM + THIRF), CISA Logging Reference Architecture (LRA), Splunk CIM (Web data model primary), Zero Trust Maturity Model (Visibility & Analytics), DoD STIG guidance for IIS, federal/DoD enterprise practices.

**Purpose:** Standardized baseline of events and critical attributes required from web server platforms so agencies can meet M-26-14 outcomes, support after-the-fact investigations, achieve CIM normalization, and enable CSIRC. Use as a comparison baseline against live technical stacks.

## 1. Category Overview

**Technology category:** Web Servers / HTTP(S) Application Servers  

**Primary popular solutions in DoD / federal environments:**  
- Microsoft Internet Information Services (IIS) 10.0 / 8.5 on Windows Server (most common for .NET / ASP.NET / SharePoint / WSUS and many line-of-business apps)  
- Apache HTTP Server (httpd) 2.4+ on RHEL / Rocky / Ubuntu (widely used for static, PHP, reverse-proxy, and custom applications)  
- Nginx (open-source and NGINX Plus) on RHEL / Ubuntu (common as reverse proxy, load balancer front-end, or primary web server)  
- Variants: IIS with ASP.NET Core, Apache/Nginx fronting application servers (Tomcat, Node, .NET), and hardened builds under DISA STIGs  

**Typical deployment contexts:**  
Internet-facing or internal web applications, reverse proxies in front of application tiers, load-balanced farms behind F5 / Citrix / AWS ALB / Azure App Gateway, DMZ and enclave-hosted services supporting High Value Assets (HVAs) and High Impact Systems, Zero Trust network access points, and systems requiring detailed access reconstruction for investigations.

## 2. Operational Purpose & Security Rationale

**Why this technology is deployed:**  
Deliver web applications and content, terminate TLS, enforce authentication/authorization, route or reverse-proxy traffic, and serve as the primary entry point for user and system interaction with mission systems.

**Primary security and mission functions:**  
- Authenticate and authorize users (forms, Windows Auth, OAuth, certificates)  
- Serve or proxy application resources and data  
- Enforce request filtering, URL rewriting, and basic rate controls  
- Terminate or inspect TLS  
- Generate the authoritative record of who requested what resource, from where, when, and with what result  

**How it supports Zero Trust and network visibility:**  
Web servers are critical control points in the Visibility & Analytics pillar. Logs provide the identity-to-resource binding, source context, action outcome, and object access needed to enforce least-privilege access decisions, detect anomalous application behavior, reconstruct lateral movement or data exfiltration via web channels, and feed continuous verification. Without high-fidelity web logs, agencies cannot reliably answer “who accessed what data via which application path.”

## 3. Key Questions the Model Must Answer

| Question | Primary Outcome(s) | Notes |
|----------|---------------------|-------|
| Who (identity or authenticated principal) accessed a specific resource or application endpoint, from which source IP / location, at what time, and what was the result (success / failure / status code)? | CEM, THIRF, Investigation, Zero Trust | Core identity + object access question (M-26-14 App B a, b, c) |
| What HTTP method, URI path, and query parameters were used, and did the request contain indicators of injection, path traversal, webshell activity, or anomalous parameters? | CEM, Threat Hunting, THIRF | Supports anomaly and IoC detection |
| What was the response status (including IIS substatus / Win32 status), bytes transferred, and duration? Did large responses or unusual status patterns indicate exfiltration or successful exploitation? | CEM, THIRF, Forensics | Outcome and data quantity (M-26-14 App B i) |
| Which client User-Agent, Referer, and (if available) true client IP (X-Forwarded-For / real_ip) were associated with the request? | CEM, Investigation, Zero Trust | Client context for pivoting and proxy/load-balancer environments |
| Were there authentication failures, privilege changes, or configuration changes affecting access control on the web server? | CEM, THIRF, Investigation | Privilege and infrastructure change (M-26-14 App B d, e) |
| What security tooling (ModSecurity / WAF module, request filtering, IIS Request Filtering) blocked or flagged, and what rule or signature matched? | CEM, Automated Alerting, Threat Hunting | Security tooling telemetry (M-26-14 App B f, g, k) |
| Can the sequence of requests be reconstructed to determine attack vector, initial access, and any subsequent lateral or data-access activity? | THIRF, Forensics, CSIRC | Attack reconstruction and scope |
| What application-level errors, module failures, or anomalous process behavior accompanied the web requests? | THIRF, Investigation | Correlation with error / application logs |

All questions support the eleven minimum activities in M-26-14 Appendix B and LRA operational outcomes for CEM (real-time detection) and THIRF (reconstruction and forensics).

## 4. Required Event Classes / Log Sources

| Log Source / Event Class | Priority | Native vs Enhanced | Notes |
|---------------------------|----------|--------------------|-------|
| Access / Request logs (successful and failed requests) | Must Have | Native (configure fields) | Primary source. IIS W3C Extended; Apache/Nginx Combined or custom JSON. Include all critical fields. |
| Error logs | Must Have | Native | Server errors, module failures, ModSecurity summaries, authz denials. |
| Authentication / Authorization events | Must Have | Native + OS | IIS auth, Apache mod_auth*, application auth. Correlate with Windows Security or Linux auth logs. |
| Security module / WAF logs (ModSecurity audit, IIS Request Filtering, custom) | Should Have (Must for Internet-facing / HVA) | Enhanced | Full transaction or high-fidelity alerts for blocked/malicious requests. |
| Application / framework logs (ASP.NET, PHP, etc.) | Should Have | Application-dependent | Business logic, exception, and data-access events not captured in web server logs. |
| TLS / cipher / protocol negotiation (custom fields) | Nice to Have (Should for Advanced maturity) | Enhanced | Identify weak TLS or anomalous client behavior. |
| Configuration change / management logs | Should Have | OS + application | IIS config, Apache/Nginx conf changes, file integrity. |
| Process / module load and crash events | Nice to Have | OS / ETW / syslog | Correlate with endpoint telemetry for webshell or persistence detection. |

**Priority guidance:** Must Have supports Basic/Intermediate maturity and core CEM/THIRF. Should Have supports Advanced. Nice to Have supports Optimal and deep forensics.

## 5. Critical Attributes / Fields Table

| Field Name | Description | Why It Matters (CEM/THIRF/Investigation) | CIM Data Model & Field Mapping | Example Values | Collection Notes |
|------------|-------------|------------------------------------------|--------------------------------|----------------|------------------|
| timestamp / date + time | Request receipt or completion time (prefer UTC) | Timeline correlation, anomaly detection, reconstruction | `_time` (all models); ensure accurate NTP | 2026-10-10 14:22:15 | IIS: date + time (UTC by default). Apache/Nginx: ensure %t or ISO. Synchronize to agency NTP source. |
| src / c-ip / remote_addr | Client IP address | Source attribution, geo/threat intel pivot, rate detection | Web.src (alias from c-ip, remote_addr) | 203.0.113.45 | Handle proxies: capture X-Forwarded-For or use real_ip module. Prefer true client when possible. |
| dest / s-ip | Server IP that handled the request | Multi-homed or farm correlation | Web.dest | 10.0.0.5 | Useful in load-balanced environments. |
| dest_port / s-port | Destination port | Protocol and binding context | Web.dest_port | 443, 80 | Required for CIM. |
| user / cs-username / remote_user | Authenticated principal (or - for anonymous) | Identity binding for access decisions and investigations | Web.user | domain\jdoe, - | Critical for Zero Trust and M-26-14 identity requirement. |
| http_method / cs-method | HTTP verb | Detect unusual methods (PUT, TRACE, CONNECT) or POST to sensitive paths | Web.http_method | GET, POST, PUT | Prescribed CIM values. |
| uri_path / cs-uri-stem | Requested resource path | Object/resource access; webshell and traversal detection | Web.uri_path | /admin/upload.aspx, /etc/passwd | High-value for hunting. |
| uri_query / cs-uri-query | Query string parameters | Injection, SQLi, command injection indicators | Web.uri_query | id=1' OR '1'='1 | Parse carefully; may contain sensitive data—apply redaction policy if needed. |
| url | Full reconstructed URL | Complete resource identifier | Web.url | https://app.example.gov/path?query | Construct if not native. |
| status / sc-status | HTTP status code | Success/failure outcome; recon vs exploitation | Web.status | 200, 401, 403, 404, 500 | Primary outcome field. |
| sc-substatus (IIS) | IIS-specific substatus | Precise failure reason (e.g., 401.1, 404.11) | Custom or note in status | 401.1, 403.14 | IIS-specific high value for investigations. |
| sc-win32-status (IIS) | Underlying Windows error | OS-level failure detail | Custom | 0, 1326 | Correlates with Windows events. |
| bytes_out / sc-bytes / body_bytes_sent | Response size | Exfiltration detection, large data transfer | Web.bytes_out | 4521 | Critical for data quantity questions. |
| bytes_in / cs-bytes | Request size | Unusual payload detection | Web.bytes_in | 1024 | |
| http_user_agent / cs(User-Agent) | Client user-agent string | Scanner, script, and tool identification | Web.http_user_agent | Mozilla/5.0..., sqlmap/1.0 | Length also useful (http_user_agent_length). |
| http_referrer / cs(Referer) | Referring URL | Context of how resource was reached; CSRF / open redirect clues | Web.http_referrer | https://attacker.example/phish | |
| duration / time-taken / request_time | Request processing time (ms) | Slow queries, DoS, exploitation timing | Web.duration or response_time | 156 | |
| action | Derived server action (allow/deny/block) | Normalized outcome for alerting | Web.action | allowed, blocked, success, failure | Map from status or WAF action. |
| vendor_product | Product identifier | Source differentiation in multi-vendor environments | Web.vendor_product | IIS 10.0, Apache 2.4, Nginx 1.24 | |
| site / s-sitename / server_name | Virtual host or site name | Multi-site correlation | Web.site | Default Web Site, app.agency.gov | |
| cookie (optional) | Cookie values (careful) | Session tracking; sensitive—often limited | Web.cookie | sessionid=abc123 | Collect only if policy allows; high sensitivity. |
| x_forwarded_for / real client | Original client behind proxy | True source in reverse-proxy architectures | Web.src (preferred) or custom | 198.51.100.10 | Essential for accurate attribution. |

**Additional high-value technology-specific fields:**  
- IIS: sc-substatus, sc-win32-status, custom TLS fields (crypt-protocol, crypt-cipher).  
- Apache/Nginx: request line components, upstream status/time (for reverse proxy), ModSecurity unique_id / rule ID / anomaly score when present.  
- All: Ensure fields support M-26-14 identity, network address (src/dest/port), object (uri), outcome (status), and timestamp requirements.

## 6. CIM Alignment

**Primary CIM data model:** Web  

**Required tags:** `web` (and `proxy` when the server functions primarily as a reverse proxy or secure web gateway).  

**Key field mappings:**  
- src ← c-ip / remote_addr / X-Forwarded-For (true client)  
- dest ← s-ip / server address  
- dest_port ← s-port / server port  
- user ← cs-username / remote_user  
- http_method ← cs-method / request method  
- uri_path ← cs-uri-stem / URI path  
- uri_query ← cs-uri-query / query string  
- url ← reconstructed full URL  
- status ← sc-status / %>s  
- bytes_in / bytes_out ← cs-bytes / sc-bytes or body_bytes_sent  
- http_user_agent ← cs(User-Agent) / %{User-Agent}i  
- http_referrer ← cs(Referer) / %{Referer}i  
- vendor_product ← IIS / Apache / Nginx version  
- action ← derived from status or WAF decision (success/failure/blocked)  

**Recommended calculated / alias fields:**  
- http_user_agent_length  
- url_domain / http_referrer_domain  
- bytes = bytes_in + bytes_out  

**Secondary models for correlation:**  
- Authentication (login success/failure events)  
- Endpoint (process, file, service changes if webshell or persistence)  
- Change (configuration modifications)  
- Intrusion_Detection or Alerts (when WAF/ModSecurity events are normalized)  

**Normalization notes:** Apply consistent tagging and field aliasing so data populates Web data model dashboards and searches. Use props.conf / transforms.conf or equivalent for CIM compliance. Prefer JSON structured logging where volume and parsing performance allow.

## 7. CEM, THIRF & CSIRC Enablement Notes

**Real-time monitoring and alerting (CEM):**  
High-fidelity access and error logs enable immediate detection of brute-force authentication, path traversal, webshell uploads (unusual URI + POST + large response or 200 on unexpected extension), scanner User-Agents, anomalous query patterns, and status code bursts (401/403/404 spikes). Feed into SIEM correlation rules and automated alerts covering the M-26-14 baseline activities. Searchable for minimum 6 months.

**Threat hunting, incident reconstruction, and forensics (THIRF):**  
Supports full request sequence reconstruction, identification of initial access vectors (e.g., vulnerable endpoint + successful exploit status), data exfiltration via large responses or unusual downloads, and correlation with identity, network, and endpoint telemetry. Retrievable for 12 months. Critical for CSIRC scope determination, attack vector analysis, and evidence preservation.

**Retention guidance (aligned with M-26-14):**  
- Actively searchable: minimum 6 months (CEM).  
- Retrievable: minimum 12 months (THIRF).  
Higher maturity (Advanced/Optimal) may keep more data searchable longer. Hot storage for recent data; cold/retrievable for older. Special consideration for High Value Assets and High Impact Systems: retain longer or at higher fidelity if risk assessment warrants; protect log integrity (immutable storage, access controls).

**CSIRC enablement:** Provides the authoritative application-layer timeline needed to answer “what data was accessed or modified via the web channel,” supporting incident scoping, containment decisions, and reporting.

## 8. Collection, Normalization & Maturity Guidance

**Recommended collection methods:**  
- File-based forwarders (Splunk Universal Forwarder, Winlogbeat/Filebeat, NXLog, Fluent Bit) tailing access and error logs.  
- For IIS: also consider ETW where real-time is required (IIS has flush delay on file logs).  
- Centralized syslog or HTTPS/HEC ingestion.  
- Ensure reliable transport and buffering per LRA guidance (decoupled, durable).  
- Preserve provenance (originating system, collection path).

**Common parsing / normalization pitfalls:**  
- Incomplete field selection in IIS W3C (missing User-Agent, Referer, bytes, substatus).  
- Failure to capture true client IP behind load balancers/proxies.  
- Timestamp timezone mismatches (IIS UTC vs local).  
- Multi-line ModSecurity audit logs.  
- Query strings containing sensitive data or very long values that break parsers.  
- Missing action derivation for CIM.  
- Volume of 200 OK noise—consider sampling or tiering low-value traffic while retaining high-value (auth, errors, admin paths, WAF hits).

**Contribution to Logging Maturity Model elements:**  
- Inventory Visibility: Web servers must be in asset inventory with logging coverage tracked.  
- Collection Coverage: Percentage of web servers forwarding required fields.  
- Collection Operations: Reliable, monitored collection with low latency for CEM.  
- Data Retention: 6-month searchable / 12-month retrievable.  
- Log Management: Normalization to CIM Web, integrity protection, access control, validation of completeness.

**Gap-analysis checklist:**  
- [ ] Access logs enabled in recommended format with all critical fields.  
- [ ] Error logs collected.  
- [ ] True client IP captured (X-Forwarded-For / real_ip).  
- [ ] Timestamps accurate and synchronized.  
- [ ] Fields mapped to CIM Web (src, dest, user, http_method, uri_path, status, bytes, http_user_agent, etc.).  
- [ ] Data searchable ≥6 months, retrievable ≥12 months and available to top-level SOC.  
- [ ] WAF/security module logs included for Internet-facing or HVA systems.  
- [ ] Correlation possible with identity and network logs.  
- [ ] Coverage measured against asset inventory.  
- [ ] Integrity protections and access controls on logs in place.

## 9. Stack Comparison Template

Use this reusable checklist when evaluating a customer’s actual implementation:

| Model Requirement | Customer Implementation | Gap? | Priority | Remediation Notes |
|-------------------|--------------------------|------|----------|-------------------|
| Access log format & critical fields (src, user, method, uri_path, uri_query, status, bytes, UA, referrer, timestamp) | | | Must | |
| True client IP handling | | | Must | |
| Error log collection | | | Must | |
| CIM Web mapping & tag=web | | | Must | |
| Searchable 6 mo / Retrievable 12 mo | | | Must | |
| Available to top-level SOC | | | Must | |
| WAF / security module logs (if applicable) | | | Should | |
| Auth event correlation | | | Should | |
| NTP time sync | | | Must | |
| Maturity contribution (coverage %) | | | | |

**Analyst notes:** Document native configuration (IIS Select Fields, Apache LogFormat, Nginx log_format), collection path, any sampling or filtering, and known limitations (e.g., behind CDN without proper XFF).

---

**References:**  
- OMB Memorandum M-26-14 (May 22, 2026) – CEM, THIRF, Appendix B minimum activities, maturity model.  
- CISA Logging Reference Architecture (August 2026).  
- Splunk CIM Web data model documentation.  
- DISA STIGs for IIS 10.0 / 8.5 (logging field requirements).  
- Standard Combined Log Format and W3C Extended Log Format specifications.  

This model is a living baseline. Update as LRA guidance evolves or new common federal solutions emerge.
