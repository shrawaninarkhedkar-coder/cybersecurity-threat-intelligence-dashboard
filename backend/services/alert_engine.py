"""
Security Alert & Fatigue Reduction Engine
Defensive Cybersecurity Education & SOC Analytics Platform

Generates actionable alerts for high-risk threats and correlates repeated
events to eliminate alert fatigue for SOC analysts.
"""

from collections import defaultdict
from datetime import datetime

def generate_threat_alerts(threat_records: list[dict], min_risk_threshold: int = 60) -> list[dict]:
    """
    Generate SOC alert queue items from threats exceeding the risk/severity threshold.
    Applies deduplication and grouping to combat alert fatigue.
    """
    raw_alerts = []
    
    for item in threat_records:
        risk = int(item.get("risk_score", 0))
        sev = item.get("severity", "LOW")
        obs_count = int(item.get("observation_count", 1))

        if risk >= min_risk_threshold or sev in ["HIGH", "CRITICAL"]:
            alert_id = f"ALT-{item.get('threat_id', '0000').replace('THR-', '')}"
            raw_alerts.append({
                "alert_id": alert_id,
                "threat_id": item.get("threat_id"),
                "threat_name": item.get("threat_name"),
                "indicator_type": item.get("indicator_type"),
                "indicator_value": item.get("indicator_value"),
                "category": item.get("threat_category"),
                "severity": sev,
                "risk_score": risk,
                "confidence_score": int(item.get("confidence_score", 50)),
                "observation_count": obs_count,
                "timestamp": item.get("timestamp"),
                "status": "NEW" if item.get("status") in ["NEW", "UNDER_REVIEW"] else item.get("status"),
                "description": (
                    f"Elevated risk alert triggered for {item.get('indicator_type')} "
                    f"'{item.get('indicator_value')}' ({sev} - Risk: {risk}/100). "
                    f"Observed {obs_count} time(s)."
                ),
                "recommended_actions": [
                    f"Inspect firewall/proxy logs for hits on {item.get('indicator_value')}",
                    "Check endpoint telemetry for matching process execution or DNS queries",
                    "Add indicator to defensive monitoring / sinkhole if verified"
                ]
            })

    return correlate_and_deduplicate_alerts(raw_alerts)

def correlate_and_deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    """
    Correlates alerts targeting the exact same indicator to prevent alert spamming.
    Aggregates duplicate observations into a single high-context alert.
    """
    indicator_grouped = defaultdict(list)
    for alert in alerts:
        indicator_grouped[alert["indicator_value"]].append(alert)

    deduplicated = []
    for indicator_val, group in indicator_grouped.items():
        if len(group) == 1:
            deduplicated.append(group[0])
        else:
            # Aggregate multiple alerts for the same indicator
            primary = max(group, key=lambda x: x["risk_score"])
            total_observations = sum(a["observation_count"] for a in group)
            aggregated_alert = dict(primary)
            aggregated_alert["observation_count"] = total_observations
            aggregated_alert["description"] = (
                f"[Correlated Alert] Indicator '{indicator_val}' triggered {len(group)} "
                f"separate detection signals across {total_observations} aggregated observations."
            )
            deduplicated.append(aggregated_alert)

    # Sort alerts by risk score descending
    deduplicated.sort(key=lambda x: (x["risk_score"], x["observation_count"]), reverse=True)
    return deduplicated
