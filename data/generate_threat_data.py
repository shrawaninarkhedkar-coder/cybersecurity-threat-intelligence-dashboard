"""
Synthetic Threat Intelligence & Vulnerability Dataset Generator
Defensive Cybersecurity Education & SOC Analytics Platform

Generates 2,000+ safe, sanitized synthetic threat records and a companion
vulnerabilities dataset strictly adhering to defensive cybersecurity guidelines
(RFC 5737, RFC 3849, RFC 2606 reserved domains/IPs, synthetic hashes).
"""

import csv
import hashlib
import json
import os
import random
from datetime import datetime, timedelta

# Seed for deterministic and reproducible test data
random.seed(42)

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
THREAT_DATASET_FILE = os.path.join(DATA_DIR, "threat_intelligence_dataset.csv")
VULN_DATASET_FILE = os.path.join(DATA_DIR, "vulnerabilities.csv")

CATEGORIES = [
    "PHISHING",
    "MALWARE",
    "RANSOMWARE",
    "CREDENTIAL THREATS",
    "WEB THREATS",
    "NETWORK THREATS",
    "VULNERABILITY EXPOSURE",
    "SOCIAL ENGINEERING",
    "DATA EXPOSURE",
    "ACCOUNT SECURITY"
]

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]

SOURCES = [
    {"name": "Internal SOC", "reliability": "A - Highly Reliable"},
    {"name": "Security Vendor Feed", "reliability": "B - Usually Reliable"},
    {"name": "Public Threat Feed", "reliability": "C - Fairly Reliable"},
    {"name": "Research Report", "reliability": "A - Highly Reliable"},
    {"name": "Community Submission", "reliability": "C - Fairly Reliable"},
    {"name": "Unknown Source", "reliability": "D - Reliability Unknown"}
]

COUNTRIES = [
    "United States", "Germany", "Japan", "United Kingdom", "Canada",
    "Netherlands", "Australia", "Singapore", "Sweden", "Brazil", "India", "Global / Multi-Region"
]

MITRE_MAP = {
    "PHISHING": [
        ("Initial Access", "Phishing", "T1566"),
        ("Initial Access", "Spearphishing Link", "T1566.002"),
        ("Initial Access", "Spearphishing Attachment", "T1566.001"),
    ],
    "MALWARE": [
        ("Execution", "User Execution", "T1204"),
        ("Defense Evasion", "Obfuscated Files or Information", "T1027"),
        ("Command and Control", "Application Layer Protocol", "T1071"),
    ],
    "RANSOMWARE": [
        ("Impact", "Data Encrypted for Impact", "T1486"),
        ("Infiltration", "Service Stop", "T1489"),
        ("Exfiltration", "Exfiltration Over C2 Channel", "T1041"),
    ],
    "CREDENTIAL THREATS": [
        ("Credential Access", "Brute Force", "T1110"),
        ("Credential Access", "Credentials in Files", "T1552"),
        ("Credential Access", "OS Credential Dumping", "T1003"),
    ],
    "WEB THREATS": [
        ("Initial Access", "Exploit Public-Facing Application", "T1190"),
        ("Defense Evasion", "Drive-by Compromise", "T1189"),
    ],
    "NETWORK THREATS": [
        ("Discovery", "Network Service Discovery", "T1046"),
        ("Command and Control", "Non-Standard Port", "T1571"),
    ],
    "VULNERABILITY EXPOSURE": [
        ("Initial Access", "Exploit Public-Facing Application", "T1190"),
        ("Privilege Escalation", "Exploitation for Privilege Escalation", "T1068"),
    ],
    "SOCIAL ENGINEERING": [
        ("Initial Access", "Phishing", "T1566"),
        ("Reconnaissance", "Search Victim-Owned Websites", "T1594"),
    ],
    "DATA EXPOSURE": [
        ("Collection", "Data from Information Repositories", "T1213"),
        ("Exfiltration", "Exfiltration Over Web Service", "T1567"),
    ],
    "ACCOUNT SECURITY": [
        ("Persistence", "Valid Accounts", "T1078"),
        ("Credential Access", "Account Manipulation", "T1098"),
    ]
}

SAFE_IP_PREFIXES = ["192.0.2.", "198.51.100.", "203.0.113."]
SAFE_IPV6_PREFIX = "2001:db8:"
SAFE_DOMAINS = [
    "auth-verify.example.org", "update-service.example.net", "portal-login.example.com",
    "secure-billing.example.org", "cdn-assets.example.net", "identity-check.example.com",
    "telemetry-node.example.org", "api-gateway.invalid", "cloud-storage.example.net",
    "mail-sync.example.com", "vpn-connect.example.org", "session-verify.invalid",
    "patch-mirror.example.net", "doc-share.example.com", "support-ticket.invalid"
]

SAFE_URL_PATHS = [
    "/auth/login.php", "/secure/verify-identity", "/dl/update-payload.bin",
    "/invoice/payment_details.html", "/account/password-reset", "/api/v1/sync-session",
    "/remote/session_validator", "/docs/confidential_brief.pdf"
]

CAMPAIGNS = [
    "CAMP-SHADOW-PHISH-01", "CAMP-CRYPTO-LOCKER-DEMO", "CAMP-RANSOM-SIM-ALPHA",
    "CAMP-CRED-HARVEST-2026", "CAMP-WEB-SCAN-BETA", "CAMP-CVE-EXPLOIT-MONITOR",
    "CAMP-SPEAR-FINANCE", "CAMP-API-INSPECTOR-DELTA", "CAMP-INTERNAL-SIM-09"
]

SAMPLE_CVES = [
    "CVE-2026-1001", "CVE-2026-1045", "CVE-2025-4892", "CVE-2025-3129",
    "CVE-2024-21413", "CVE-2024-3400", "CVE-2023-38606", "CVE-2023-46805"
]

def generate_safe_indicator(ind_type, index):
    if ind_type == "IP ADDRESS":
        prefix = random.choice(SAFE_IP_PREFIXES)
        suffix = (index % 250) + 1
        return f"{prefix}{suffix}"
    elif ind_type == "IPV6":
        return f"{SAFE_IPV6_PREFIX}{index:04x}:{index % 999:04x}::1"
    elif ind_type == "DOMAIN":
        base = random.choice(SAFE_DOMAINS)
        sub = f"sub{index % 40}"
        return f"{sub}.{base}"
    elif ind_type == "URL":
        domain = random.choice(SAFE_DOMAINS)
        path = random.choice(SAFE_URL_PATHS)
        return f"https://{domain}{path}?token=demo_{index:04d}"
    elif ind_type == "FILE HASH":
        raw = f"synthetic_benign_defensive_hash_{index}_{random.randint(1000, 999999)}"
        return hashlib.sha256(raw.encode()).hexdigest()
    elif ind_type == "EMAIL/SENDER DOMAIN":
        domain = random.choice(SAFE_DOMAINS)
        users = ["admin-notice", "billing-alert", "support-desk", "security-update", "hr-verify"]
        return f"{random.choice(users)}@{domain}"
    elif ind_type == "CVE ID":
        return random.choice(SAMPLE_CVES)
    else:
        return f"198.51.100.{(index % 250) + 1}"

def generate_threat_dataset(count=2200):
    records = []
    base_time = datetime.now() - timedelta(days=60)
    indicator_types = [
        "IP ADDRESS", "DOMAIN", "URL", "FILE HASH",
        "EMAIL/SENDER DOMAIN", "CVE ID"
    ]

    for i in range(1, count + 1):
        threat_id = f"THR-2026-{i:04d}"
        cat = random.choice(CATEGORIES)
        ind_type = random.choices(
            indicator_types,
            weights=[30, 25, 20, 12, 8, 5],
            k=1
        )[0]
        ind_val = generate_safe_indicator(ind_type, i)
        source = random.choice(SOURCES)
        
        # Determine Severity & Base Risk
        sev = random.choices(SEVERITIES, weights=[10, 25, 35, 20, 10], k=1)[0]
        sev_weights = {"INFORMATIONAL": 15, "LOW": 35, "MEDIUM": 55, "HIGH": 75, "CRITICAL": 95}
        base_sev_score = sev_weights[sev]

        # Reliability weight
        rel_weights = {"A - Highly Reliable": 95, "B - Usually Reliable": 80, "C - Fairly Reliable": 60, "D - Reliability Unknown": 40}
        source_rel_score = rel_weights[source["reliability"]]

        confidence = min(100, max(20, int(source_rel_score * random.uniform(0.8, 1.05))))

        # Recency & Frequency
        days_ago = random.randint(0, 50)
        first_dt = base_time + timedelta(days=days_ago, hours=random.randint(0, 23))
        last_dt = first_dt + timedelta(days=random.randint(0, 8), hours=random.randint(0, 12))
        
        # Observations count
        obs_count = random.randint(1, 45)

        # Calculate composite risk score
        # Risk = 30% Sev + 25% Conf + 15% Recency + 10% Freq + 10% Reliability + 10% Context
        recency_score = max(10, 100 - (days_ago * 2))
        freq_score = min(100, obs_count * 3)
        context_score = 80 if cat in ["RANSOMWARE", "CREDENTIAL THREATS", "VULNERABILITY EXPOSURE"] else 50
        
        risk_score = int(round(
            (base_sev_score * 0.30) +
            (confidence * 0.25) +
            (recency_score * 0.15) +
            (freq_score * 0.10) +
            (source_rel_score * 0.10) +
            (context_score * 0.10)
        ))
        risk_score = min(100, max(5, risk_score))

        status = random.choices(STATUSES, weights=[30, 25, 25, 15, 5], k=1)[0]

        # MITRE ATT&CK Mapping
        tactic, tech_name, tech_id = "", "", ""
        if random.random() > 0.15 and cat in MITRE_MAP:
            t_pair = random.choice(MITRE_MAP[cat])
            tactic = t_pair[0]
            tech_name = t_pair[1]
            tech_id = t_pair[2]

        cve_id = random.choice(SAMPLE_CVES) if cat == "VULNERABILITY EXPOSURE" or random.random() < 0.08 else ""
        campaign_id = random.choice(CAMPAIGNS) if random.random() > 0.3 else ""

        threat_name = f"Synthetic {cat.title()} Indicator {ind_type} #{i}"
        desc = (
            f"Defensive observation: Synthetic {ind_type.lower()} indicator '{ind_val}' "
            f"associated with {cat.lower()} telemetry. Identified via {source['name']}."
        )

        records.append({
            "threat_id": threat_id,
            "timestamp": last_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_name": threat_name,
            "threat_category": cat,
            "indicator_type": ind_type,
            "indicator_value": ind_val,
            "source_name": source["name"],
            "source_reliability": source["reliability"],
            "confidence_score": confidence,
            "severity": sev,
            "risk_score": risk_score,
            "status": status,
            "first_seen": first_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": last_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "observation_count": obs_count,
            "campaign_id": campaign_id,
            "country_or_region_optional": random.choice(COUNTRIES),
            "description": desc,
            "mitre_tactic_optional": tactic,
            "mitre_technique_optional": tech_name,
            "mitre_technique_id_optional": tech_id,
            "cve_id_optional": cve_id
        })

    return records

def generate_vulnerability_dataset():
    products = [
        ("Web Application Server", "Apache HTTP Server / Nginx", "CRITICAL"),
        ("VPN Gateway", "Enterprise SSL VPN Gateway", "HIGH"),
        ("Identity Provider", "Corporate SSO / OAuth Service", "CRITICAL"),
        ("Database Engine", "PostgreSQL / Enterprise SQL", "HIGH"),
        ("Endpoint Agent", "Management & Telemetry Daemon", "MEDIUM"),
        ("Email Gateway", "Secure Mail Filter Gateway", "HIGH"),
        ("Cloud Container Runtime", "Kubernetes Ingress Controller", "CRITICAL"),
        ("Developer Tools", "CI/CD Pipeline Build Agent", "MEDIUM"),
        ("Network Switch", "Core Network Switch OS", "LOW"),
        ("Workstation OS", "Corporate Desktop OS Subsystem", "HIGH")
    ]
    
    records = []
    base_date = datetime.now() - timedelta(days=90)

    for i in range(1, 65):
        cve_num = 1000 + i
        cve_id = f"CVE-2026-{cve_num}"
        prod_cat, prod_name, default_sev = random.choice(products)
        cvss = round(random.uniform(4.0, 9.8), 1)
        
        if cvss >= 9.0:
            sev = "CRITICAL"
        elif cvss >= 7.0:
            sev = "HIGH"
        elif cvss >= 4.0:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        epss = round(random.uniform(0.01, 0.88), 3)
        pub_dt = base_date + timedelta(days=random.randint(1, 80))
        patch_avail = random.choice([True, True, True, False])
        is_kev = cvss >= 8.5 and random.random() > 0.4
        
        # Priority formula: Contextual risk
        # CVSS (40%) + EPSS (30%) + KEV boost (20%) + Patch readiness (10%)
        priority_score = int(round((cvss * 4.0) + (epss * 30.0) + (20 if is_kev else 0) + (10 if not patch_avail else 5)))
        priority_score = min(100, max(10, priority_score))

        desc = f"Synthetic defensive advisory for {prod_name}. Demonstrates defensive patching and contextual risk prioritization."

        records.append({
            "vulnerability_id": f"VULN-{i:03d}",
            "cve_id": cve_id,
            "product_category": prod_cat,
            "product_name": prod_name,
            "severity": sev,
            "cvss_score": cvss,
            "epss_score": epss,
            "known_exploited_demo": "YES" if is_kev else "NO",
            "patch_available": "YES" if patch_avail else "NO",
            "published_date": pub_dt.strftime("%Y-%m-%d"),
            "priority_score": priority_score,
            "description": desc,
            "remediation_guidance": "Apply official vendor security patch or implement network micro-segmentation / ACL controls."
        })

    return records

def save_to_csv(filename, data):
    if not data:
        return
    keys = data[0].keys()
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] Saved {len(data)} records to {filename}")

def main():
    print("[*] Generating synthetic threat intelligence dataset...")
    threats = generate_threat_dataset(count=2200)
    save_to_csv(THREAT_DATASET_FILE, threats)

    print("[*] Generating synthetic vulnerabilities dataset...")
    vulns = generate_vulnerability_dataset()
    save_to_csv(VULN_DATASET_FILE, vulns)
    print("[OK] Synthetic defensive datasets successfully created!")

if __name__ == "__main__":
    main()
