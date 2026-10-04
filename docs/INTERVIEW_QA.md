# 🎯 Cybersecurity Interview Preparation & Technical Q&A

This guide contains 10 predicted interview questions and high-impact defensive answers designed to showcase hands-on mastery of Cyber Threat Intelligence (CTI), SOC workflows, MITRE ATT&CK, risk scoring, and security awareness.

---

### Question 1: Explain your project.
**Model Answer:**
> "I developed the **Cybersecurity Awareness & Threat Intelligence Dashboard**, a full-stack defensive platform that unites technical cyber threat intelligence with human awareness training. 
> 
> On the technical CTI side, the system processes a dataset of over 2,200 synthetic threat records containing indicators such as IPv4, IPv6, FQDNs, URLs, file hashes, and CVE identifiers. The backend normalizes raw telemetry, syntactically validates indicators, enriches them with local threat context and MITRE ATT&CK behavioral tactics, and calculates separate **Multi-Factor Risk (0–100)** and **Evidentiary Confidence (0–100)** scores. It also includes an alert correlation engine that prevents SOC alert fatigue by grouping repeated observations, as well as a contextual vulnerability prioritizer that pairs CVSS scores with EPSS exploitation probabilities and network exposure.
> 
> On the human defense side, I created an interactive Security Awareness Center with 15 micro-learning modules, a 32-question scenario assessment, and an engine that identifies personal security weaknesses to provide targeted recommendations. The entire project is 100% defensive, offline-safe, tested with 37 automated unit tests, and adheres to RFC 5737/3849 documentation standards."

---

### Question 2: What is Cyber Threat Intelligence (CTI), and what are its four main operational types?
**Model Answer:**
> "Cyber Threat Intelligence (CTI) is analyzed, contextualized information about cyber threats and adversary capabilities that enables organizations to make informed defensive decisions. Raw data alone is not intelligence until it undergoes collection, validation, normalization, and contextual enrichment.
> 
> The four recognized types of CTI are:
> 1. **Strategic CTI**: High-level, non-technical executive briefings focusing on geopolitical trends, threat actor motivations, and business risk.
> 2. **Tactical CTI**: Focuses on adversary tactics, techniques, and procedures (TTPs) using frameworks like MITRE ATT&CK to inform SOC detection engineering.
> 3. **Operational CTI**: Details specific active campaigns, attacker infrastructure, and attack timelines.
> 4. **Technical CTI**: Specific atomic indicators (IOCs) such as malicious IPs, domains, URLs, and file hashes used for automated SIEM/firewall blocking.
> 
> My dashboard specifically operationalizes Technical and Tactical CTI for SOC analysts while translating Strategic insights into Executive Summaries and User Awareness modules."

---

### Question 3: What is an IOC, and why does an IOC match NOT automatically prove that a system is compromised?
**Model Answer:**
> "An **IOC (Indicator of Compromise)** is an observable artifact—such as a file hash, domain name, IP address, or registry modification—that provides forensic evidence of potential unauthorized activity.
> 
> However, an IOC match is an **observation**, not a confirmed verdict of compromise, for several critical reasons:
> - **Shared & Cloud Infrastructure**: A benign website may share an IP address or CDN with malicious hosts.
> - **Indicator Staleness**: Attackers rapidly abandon command-and-control IPs, which are later reassigned to legitimate users.
> - **Benign Lookups**: An endpoint might trigger a DNS lookup for a suspicious domain due to an ad tracker or research query without executing malicious payloads.
> 
> In my project, an IOC is treated as evidence within an investigation lifecycle (Observed → Validated → Enriched → Scored → Investigated → Monitored/Closed) rather than an automated conviction."

---

### Question 4: What is the fundamental difference between your Risk Score and Confidence Score?
**Model Answer:**
> "The **Risk Score** quantifies the potential severity, blast radius, and operational urgency of an indicator or threat event. In my system, it is calculated via a multi-factor formula weighting Severity (30%), Confidence (25%), Recency (15%), Observation Frequency (10%), Source Reliability (10%), and Category Impact (10%).
> 
> The **Confidence Score** measures the reliability, fidelity, and evidentiary backing of the intelligence itself (e.g., whether the observation came from an internal SOC sensor vs. an unverified community feed).
> 
> Keeping these separate is vital: a rumor of an unpatched zero-day on an internal database might carry a **Risk of 95** but a **Confidence of 20%** (requiring cautious verification), whereas a known low-risk port scanner might carry a **Risk of 30** with **Confidence of 95%**."

---

### Question 5: How does your system mitigate SOC Alert Fatigue?
**Model Answer:**
> "SOC alert fatigue occurs when analysts are overwhelmed by thousands of duplicate or low-context alerts, leading to burnout and missed high-severity incidents.
> 
> In my architecture, the `alert_engine.py` implements **alert correlation and deduplication**. If the same suspicious IP or domain is observed 100 times within a short observation window, rather than flooding the triage queue with 100 individual tickets, the engine aggregates them into **one unified alert** with an `observation_count = 100` and an elevated composite risk score. This allows tier-1 analysts to immediately understand campaign velocity without suffering notification overload."

---

### Question 6: What is MITRE ATT&CK, and how did you incorporate behavioral mapping into the project?
**Model Answer:**
> "MITRE ATT&CK is a globally accessible, curated knowledge base of adversary behaviors based on real-world cyber observations. It structures adversary behavior into **Tactics** (the adversary's objective, or 'Why') and **Techniques/Sub-techniques** (the method used, or 'How').
> 
> In my platform, IOCs are mapped to ATT&CK tactics (such as *Initial Access [TA0001]*, *Credential Access [TA0006]*, and *Impact [TA0040]*) only when behavioral context justifies it. For example, a phishing domain is linked to *T1566 (Phishing)* alongside specific defensive controls like email authentication (SPF/DKIM/DMARC) and FIDO2 MFA."

---

### Question 7: Why is CVSS alone insufficient for vulnerability prioritization, and how does your project address this?
**Model Answer:**
> "CVSS (Common Vulnerability Scoring System) measures theoretical technical severity in a vacuum—it does not account for whether an exploit exists in the wild or whether the vulnerable system is exposed to the internet. Treating every CVSS 9.0+ as an emergency leads to wasted engineering effort on air-gapped test machines while actively exploited CVSS 7.5 flaws on edge firewalls go unpatched.
> 
> My project implements **Risk-Based Vulnerability Prioritization** combining:
> - **CVSS Base Score** (40% weight)
> - **EPSS (Exploit Prediction Scoring System)** probability (20% weight)
> - **CISA KEV (Known Exploited Vulnerabilities)** active weaponization signal (+20 points)
> - **Asset Exposure & Criticality** (Internet-facing + Mission-critical: +20 points)
> 
> This provides actionable remediation SLAs (e.g., 24-48 hours vs. 30 days) based on real operational risk."

---

### Question 8: How does the Security Awareness module complement the Technical Threat Intelligence engine?
**Model Answer:**
> "Security is only as strong as the human element. An organization can invest in million-dollar firewalls, but a single employee entering credentials on a reverse-proxy phishing page bypasses perimeter defenses.
> 
> By uniting CTI with Awareness, our platform creates a **closed defensive loop**: when technical feeds observe an uptick in credential phishing campaigns, the system can recommend targeted awareness nudges (such as our *Phishing Awareness & MFA Hygiene* modules) to end-users. The 32-question scenario assessment identifies specific employee knowledge gaps and outputs personalized learning paths."

---

### Question 9: What is the step-by-step workflow of a Tier 1 SOC Analyst using your dashboard during an investigation?
**Model Answer:**
> "When a Tier 1 analyst logs into the dashboard:
> 1. **Triage**: They inspect the **Alert Queue** prioritized by composite risk score.
> 2. **Validation**: They run the suspicious indicator through the **IOC Lookup Tool** to verify syntax and inspect first-seen/last-seen timestamps.
> 3. **Enrichment**: They review enriched context, including related indicators in the same subnet/campaign and associated ATT&CK techniques.
> 4. **Containment & Response**: They consult the automated **Defensive Playbook** (e.g., blocking the domain in DNS sinkholes or revoking user session tokens).
> 5. **Documentation & Status Update**: The analyst records their investigative findings in the **Analyst Notes** log and updates the alert status from `NEW` to `INVESTIGATING`, `MONITORING`, `RESOLVED`, or `FALSE_POSITIVE`."

---

### Question 10: What are the primary limitations of the current implementation, and what future improvements would you build?
**Model Answer:**
> "The current implementation is an offline, synthetic simulation designed for controlled course demonstration and student defense. Its limitations include lack of real-time API integrations and static heuristic correlation.
> 
> In a production evolution, I would implement:
> 1. **STIX 2.1 & TAXII 2.1 feeds** for automated, standardized threat intelligence exchange.
> 2. **Live SIEM/EDR webhook ingestion** (e.g., Splunk, Microsoft Sentinel, or Elastic Security).
> 3. **Automated SOAR playbooks** for instant firewall ACL deployment via REST webhooks.
> 4. **Role-Based Access Control (RBAC)** with JWT authentication distinguishing analysts from end-users.
> 5. **AI-driven behavioral anomaly detection** for automated campaign clustering across unstructured OSINT feeds."
