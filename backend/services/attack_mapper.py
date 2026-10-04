"""
MITRE ATT&CK Mapping & Taxonomy Service
Defensive Cybersecurity Education & SOC Analytics Platform

Provides mapping, categorization, and contextual aggregation of adversary
tactics and techniques based on the MITRE ATT&CK Enterprise Framework.
"""

ATTACK_TACTICS_DEFINITION = {
    "Initial Access": {
        "id": "TA0001",
        "description": "Techniques used by adversaries to gain an initial foothold within your network.",
        "defensive_focus": "Email filtering, multi-factor authentication, perimeter vulnerability patching."
    },
    "Execution": {
        "id": "TA0002",
        "description": "Techniques that result in adversary-controlled code running on a local or remote system.",
        "defensive_focus": "Application control, script execution policies, endpoint threat detection."
    },
    "Persistence": {
        "id": "TA0003",
        "description": "Techniques adversaries use to keep access across restarts, changed credentials, and interruptions.",
        "defensive_focus": "Registry auto-run monitoring, scheduled task audits, account privilege review."
    },
    "Privilege Escalation": {
        "id": "TA0004",
        "description": "Techniques that allow an adversary to gain higher-level permissions on a system or network.",
        "defensive_focus": "Patching local privilege elevation CVEs, restricting administrative access."
    },
    "Defense Evasion": {
        "id": "TA0005",
        "description": "Techniques used by adversaries to avoid detection throughout their compromise lifecycle.",
        "defensive_focus": "Behavioral endpoint detection, immutable security event logging, integrity monitoring."
    },
    "Credential Access": {
        "id": "TA0006",
        "description": "Techniques for stealing credentials like account names, passwords, and security tokens.",
        "defensive_focus": "Credential Guard, LSASS memory protection, phishing-resistant MFA."
    },
    "Discovery": {
        "id": "TA0007",
        "description": "Techniques adversaries use to observe system configurations, internal networks, and software.",
        "defensive_focus": "Internal network segmentation, canary tokens, monitoring reconnaissance commands."
    },
    "Collection": {
        "id": "TA0009",
        "description": "Techniques used to gather data of interest prior to exfiltration.",
        "defensive_focus": "Data Loss Prevention (DLP), repository access logs, sensitive file access audits."
    },
    "Command and Control": {
        "id": "TA0011",
        "description": "Techniques used by adversaries to communicate with systems under their control within a victim network.",
        "defensive_focus": "DNS sinkholing, proxy inspection, blocking known C2 indicators, anomaly detection."
    },
    "Exfiltration": {
        "id": "TA0010",
        "description": "Techniques used to steal data out of your enterprise network.",
        "defensive_focus": "Egress filtering, cloud upload restrictions, volume-based anomaly alerts."
    },
    "Impact": {
        "id": "TA0040",
        "description": "Techniques used to disrupt, corrupt, or destroy availability and integrity of systems and data.",
        "defensive_focus": "Immutable offline backups, ransomware recovery plans, disaster recovery readiness."
    }
}

ATTACK_TECHNIQUES = {
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/002/"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1204": {"name": "User Execution", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1204/"},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1078/"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1027/"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1003/"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1046/"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1571/"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1041/"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"}
}

def get_attack_tactic_info(tactic_name: str) -> dict:
    """Return formal MITRE ATT&CK tactic metadata and defensive controls."""
    return ATTACK_TACTICS_DEFINITION.get(tactic_name, {
        "id": "TA-GENERIC",
        "description": "Adversary behavioral phase mapped from threat intelligence observation.",
        "defensive_focus": "Multi-layered defensive telemetry and defense-in-depth controls."
    })

def map_threat_to_attack(category: str, indicator_type: str = "") -> dict:
    """
    Map threat category to probable ATT&CK tactic/technique when context is justified.
    """
    cat_upper = category.upper()
    if "PHISH" in cat_upper:
        return {"tactic": "Initial Access", "technique": "Phishing", "technique_id": "T1566"}
    elif "RANSOM" in cat_upper:
        return {"tactic": "Impact", "technique": "Data Encrypted for Impact", "technique_id": "T1486"}
    elif "CREDENTIAL" in cat_upper:
        return {"tactic": "Credential Access", "technique": "Brute Force", "technique_id": "T1110"}
    elif "MALWARE" in cat_upper:
        return {"tactic": "Execution", "technique": "User Execution", "technique_id": "T1204"}
    elif "VULN" in cat_upper:
        return {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "technique_id": "T1190"}
    elif "NETWORK" in cat_upper:
        return {"tactic": "Discovery", "technique": "Network Service Discovery", "technique_id": "T1046"}
    elif "WEB" in cat_upper:
        return {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "technique_id": "T1190"}
    elif "DATA" in cat_upper:
        return {"tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "technique_id": "T1041"}
    elif "ACCOUNT" in cat_upper:
        return {"tactic": "Persistence", "technique": "Valid Accounts", "technique_id": "T1078"}
    
    return {"tactic": "Unclassified", "technique": "General Suspicious Behavior", "technique_id": ""}
