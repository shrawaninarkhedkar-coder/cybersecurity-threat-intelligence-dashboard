"""
Threat Correlation Engine
Defensive Cybersecurity Education & SOC Analytics Platform

Identifies contextual clusters across threat records based on campaigns,
shared infrastructure, indicator types, and temporal proximity.
"""

from collections import defaultdict
from datetime import datetime

def correlate_threat_records(records: list[dict]) -> dict:
    """
    Correlates raw threat intelligence records into logical clusters.
    
    IMPORTANT NOTE:
    Correlation indicates evidential relationships and co-occurrence;
    it does not constitute definitive proof of threat actor attribution.
    """
    campaign_clusters = defaultdict(list)
    category_clusters = defaultdict(list)
    indicator_map = defaultdict(list)

    for item in records:
        tid = item.get("threat_id")
        camp = item.get("campaign_id")
        cat = item.get("threat_category")
        val = item.get("indicator_value")

        if camp:
            campaign_clusters[camp].append(tid)
        if cat:
            category_clusters[cat].append(tid)
        if val:
            indicator_map[val].append(tid)

    # Build cluster summaries
    cluster_list = []
    for camp_name, tids in campaign_clusters.items():
        if len(tids) > 1:
            cluster_list.append({
                "cluster_id": f"CLUS-{camp_name}",
                "name": f"Correlated Campaign: {camp_name}",
                "type": "CAMPAIGN_CORRELATION",
                "record_count": len(tids),
                "threat_ids": tids[:15],
                "summary": f"{len(tids)} synthetic indicators co-occur under campaign tag '{camp_name}'."
            })

    return {
        "total_clusters": len(cluster_list),
        "clusters": cluster_list[:20],
        "top_campaigns": sorted([
            {"campaign": k, "count": len(v)} for k, v in campaign_clusters.items()
        ], key=lambda x: x["count"], reverse=True)[:5]
    }

def find_related_indicators(target_threat: dict, all_records: list[dict]) -> list[dict]:
    """Find indicators closely linked to the target threat by campaign, category, or subnet."""
    target_id = target_threat.get("threat_id")
    target_camp = target_threat.get("campaign_id")
    target_cat = target_threat.get("threat_category")
    target_val = target_threat.get("indicator_value", "")

    related = []
    
    # Subnet extraction for IPs
    target_subnet = ".".join(target_val.split(".")[:3]) if target_threat.get("indicator_type") == "IP ADDRESS" and "." in target_val else ""

    for rec in all_records:
        if rec.get("threat_id") == target_id:
            continue

        is_related = False
        relation_reason = []

        if target_camp and rec.get("campaign_id") == target_camp:
            is_related = True
            relation_reason.append(f"Shared campaign ({target_camp})")

        if target_subnet and rec.get("indicator_type") == "IP ADDRESS" and rec.get("indicator_value", "").startswith(target_subnet):
            is_related = True
            relation_reason.append(f"Same /24 subnet ({target_subnet}.0/24)")

        if rec.get("threat_category") == target_cat and rec.get("severity") in ["HIGH", "CRITICAL"] and len(related) < 5:
            is_related = True
            relation_reason.append(f"Shared high-severity category ({target_cat})")

        if is_related:
            related.append({
                "threat_id": rec.get("threat_id"),
                "threat_name": rec.get("threat_name"),
                "indicator_type": rec.get("indicator_type"),
                "indicator_value": rec.get("indicator_value"),
                "severity": rec.get("severity"),
                "risk_score": rec.get("risk_score"),
                "relation_reason": ", ".join(relation_reason)
            })

        if len(related) >= 8:
            break

    return related
