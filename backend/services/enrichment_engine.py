"""
Threat Enrichment Engine
Defensive Cybersecurity Education & SOC Analytics Platform

Enriches threat indicators with multi-dimensional context from local synthetic datasets,
threat categories, ATT&CK techniques, CVEs, and defensive remediation playbooks.
"""

from .ioc_validator import validate_indicator
from .risk_engine import calculate_threat_risk
from .attack_mapper import map_threat_to_attack, get_attack_tactic_info
from .correlation_engine import find_related_indicators

RECOMMENDED_DEFENSIVE_PLAYBOOKS = {
    "PHISHING": [
        "Search mail gateway logs for inbound messages matching sender domain or embedded URL.",
        "Add indicator domain/URL to web proxy blocklist and DNS sinkhole.",
        "Trigger targeted phishing awareness nudge to recipients who may have received the lure.",
        "Purge matching phishing emails from employee inboxes via Microsoft 365 / Google Workspace admin tools."
    ],
    "MALWARE": [
        "Query EDR telemetry for file hash execution or child process spawning.",
        "Check network egress proxies for outbound connection attempts to associated IPs.",
        "Isolate flagged endpoints to prevent lateral propagation.",
        "Collect memory dumps for offline sandbox analysis."
    ],
    "RANSOMWARE": [
        "Verify integrity of immutable offline backups.",
        "Enforce strict least privilege on SMB network shares.",
        "Audit Active Directory for unauthorized privilege escalation or shadow copy deletions.",
        "Prepare incident response containment protocol and isolate affected network segments."
    ],
    "CREDENTIAL THREATS": [
        "Initiate forced password reset and revoke active session tokens for affected accounts.",
        "Enforce FIDO2/WebAuthn phishing-resistant MFA across external access portals.",
        "Audit authentication logs for anomalous geographic logins or credential stuffing bursts."
    ],
    "WEB THREATS": [
        "Deploy Web Application Firewall (WAF) virtual patching rules for targeted URIs.",
        "Review server access logs for anomalous payload parameters or SQL injection syntax.",
        "Audit public-facing web servers for unpatched dependencies."
    ],
    "NETWORK THREATS": [
        "Update perimeter firewall ACLs to drop ingress/egress on suspicious IPs.",
        "Inspect NetFlow/Zeek logs for port scanning activity or non-standard port communications.",
        "Verify internal network segmentation between DMZ, workstations, and database tiers."
    ],
    "VULNERABILITY EXPOSURE": [
        "Scan asset inventory to identify all instances of affected software packages.",
        "Prioritize patching based on internet exposure and known exploitation evidence.",
        "Apply vendor-recommended workarounds or disable vulnerable sub-features if patch is pending."
    ],
    "SOCIAL ENGINEERING": [
        "Issue an awareness flash advisory highlighting the specific impersonation pretext.",
        "Reinforce dual-authorization requirements for financial transactions and account credential changes.",
        "Remind helpdesk staff to verify employee identities out-of-band before resetting credentials."
    ],
    "DATA EXPOSURE": [
        "Audit cloud storage bucket permissions and enforce private-by-default access policies.",
        "Implement Data Loss Prevention (DLP) rules blocking credit cards and PII egress.",
        "Verify encryption-at-rest is enabled across all production databases and backups."
    ],
    "ACCOUNT SECURITY": [
        "Audit privileged group memberships (Domain Admins, Cloud Global Admins).",
        "Implement conditional access policies restricting logins to corporate-managed devices.",
        "Enable automated alerting on new account creation in sensitive organizational units."
    ]
}

def enrich_indicator(indicator_value: str, all_threats: list[dict], all_vulns: list[dict] = None) -> dict:
    """
    Enrich an indicator strictly using local offline intelligence without external probing.
    """
    val_res = validate_indicator(indicator_value)
    clean_val = val_res.get("normalized_value", indicator_value.strip())
    ind_type = val_res.get("indicator_type", "UNKNOWN")

    # Search in dataset for exact or fuzzy match
    matches = [
        t for t in all_threats
        if t.get("indicator_value", "").lower() == clean_val.lower() or
           (ind_type == "CVE ID" and t.get("cve_id_optional", "").upper() == clean_val.upper())
    ]

    if matches:
        primary = matches[0]
        category = primary.get("threat_category", "PHISHING")
        severity = primary.get("severity", "MEDIUM")
        risk_score = int(primary.get("risk_score", 50))
        confidence_score = int(primary.get("confidence_score", 60))
        source_name = primary.get("source_name", "Internal SOC")
        source_rel = primary.get("source_reliability", "B - Usually Reliable")
        first_seen = primary.get("first_seen", "N/A")
        last_seen = primary.get("last_seen", "N/A")
        status = primary.get("status", "MONITORING")
        desc = primary.get("description", "Identified in defensive threat intelligence telemetry.")
        cve_id = primary.get("cve_id_optional", "")
        campaign_id = primary.get("campaign_id", "")
        known_in_dataset = True
    else:
        # Synthesize baseline enrichment if indicator is syntactically valid but new
        category = "WEB THREATS" if ind_type in ["DOMAIN", "URL"] else "NETWORK THREATS"
        severity = "INFORMATIONAL"
        source_name = "Analyst Query Input"
        source_rel = "D - Reliability Unknown"
        risk_calc = calculate_threat_risk(
            severity="INFORMATIONAL",
            confidence=40,
            days_since_seen=0,
            observation_count=1,
            source_reliability=source_rel,
            category=category
        )
        risk_score = risk_calc["risk_score"]
        confidence_score = 40
        first_seen = "Just Queried"
        last_seen = "Just Queried"
        status = "NEW"
        desc = f"New {ind_type.lower()} indicator queried by analyst. No prior sightings recorded in local threat database."
        cve_id = clean_val if ind_type == "CVE ID" else ""
        campaign_id = ""
        known_in_dataset = False
        primary = {
            "threat_id": "THR-QUERY-TMP",
            "indicator_value": clean_val,
            "indicator_type": ind_type,
            "threat_category": category,
            "campaign_id": ""
        }

    # ATT&CK Mapping
    attack_info = map_threat_to_attack(category, ind_type)
    tactic_details = get_attack_tactic_info(attack_info.get("tactic", ""))

    # Related Indicators via Correlation Engine
    related = find_related_indicators(primary, all_threats) if all_threats else []

    # Defensive Playbooks
    playbook = RECOMMENDED_DEFENSIVE_PLAYBOOKS.get(category, [
        "Investigate logs for evidence of sighting.",
        "Add to defensive watchlist and monitor firewall alerts."
    ])

    return {
        "query": clean_val,
        "is_valid_format": val_res["valid"],
        "indicator_type": ind_type,
        "validation_notes": val_res["validation_notes"],
        "known_in_dataset": known_in_dataset,
        "threat_id": primary.get("threat_id", "N/A"),
        "threat_name": primary.get("threat_name", f"Indicator: {clean_val}"),
        "category": category,
        "severity": severity,
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "status": status,
        "source_name": source_name,
        "source_reliability": source_rel,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "campaign_id": campaign_id,
        "cve_association": cve_id,
        "description": desc,
        "mitre_attack": {
            "tactic": attack_info.get("tactic"),
            "technique": attack_info.get("technique"),
            "technique_id": attack_info.get("technique_id"),
            "tactic_description": tactic_details.get("description"),
            "defensive_focus": tactic_details.get("defensive_focus")
        },
        "related_indicators": related,
        "recommended_actions": playbook,
        "offline_safety_guarantee": "Analyzed entirely as data within local database. No external network connections were made."
    }
