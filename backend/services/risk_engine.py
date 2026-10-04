"""
Threat Risk & Confidence Scoring Engine
Defensive Cybersecurity Education & SOC Analytics Platform

Calculates weighted risk scores (0-100) and confidence scores (0-100),
strictly distinguishing potential threat severity from evidentiary confidence.
"""

from datetime import datetime

SEVERITY_WEIGHTS = {
    "INFORMATIONAL": 15,
    "LOW": 35,
    "MEDIUM": 55,
    "HIGH": 75,
    "CRITICAL": 95
}

SOURCE_RELIABILITY_SCORES = {
    "A - Highly Reliable": 95,
    "B - Usually Reliable": 80,
    "C - Fairly Reliable": 60,
    "D - Reliability Unknown": 40
}

HIGH_IMPACT_CATEGORIES = {
    "RANSOMWARE": 90,
    "CREDENTIAL THREATS": 85,
    "VULNERABILITY EXPOSURE": 85,
    "MALWARE": 80,
    "PHISHING": 75,
    "ACCOUNT SECURITY": 70,
    "DATA EXPOSURE": 70,
    "WEB THREATS": 65,
    "NETWORK THREATS": 60,
    "SOCIAL ENGINEERING": 65
}

def classify_risk_level(score: int) -> str:
    """Classify 0-100 risk score into standard SOC tiers."""
    if score <= 20:
        return "INFORMATIONAL"
    elif score <= 40:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"

def calculate_confidence_score(source_reliability: str, observation_count: int = 1, has_correlations: bool = False) -> int:
    """
    Calculate confidence score (0-100) reflecting evidence quality.
    
    Distinction:
    - High Confidence, Low Risk = e.g., Confirmed benign observation or low-impact scanner
    - Low Confidence, High Risk = e.g., Unverified rumor of zero-day exploit
    - High Confidence, High Risk = e.g., Validated ransomware C2 infrastructure verified by multiple internal sensors
    """
    base = SOURCE_RELIABILITY_SCORES.get(source_reliability, 50)
    
    # Boost for repeated sightings / corroborating observations
    repeat_boost = min(15, (observation_count - 1) * 3)
    corr_boost = 10 if has_correlations else 0
    
    total = base + repeat_boost + corr_boost
    return min(100, max(10, total))

def calculate_threat_risk(
    severity: str,
    confidence: int,
    days_since_seen: int = 0,
    observation_count: int = 1,
    source_reliability: str = "B - Usually Reliable",
    category: str = "PHISHING",
    has_correlation: bool = False
) -> dict:
    """
    Calculate composite multi-factor risk score:
    - Severity Weight: 30%
    - Confidence Weight: 25%
    - Recency Weight: 15%
    - Observation Frequency: 10%
    - Source Reliability: 10%
    - Contextual Impact: 10%
    """
    sev_score = SEVERITY_WEIGHTS.get(severity.upper(), 40)
    rel_score = SOURCE_RELIABILITY_SCORES.get(source_reliability, 50)
    
    # Recency decay: fresher indicators represent higher operational urgency
    recency_score = max(10, 100 - (days_since_seen * 2))
    
    # Frequency: higher sightings indicate active campaigns
    freq_score = min(100, observation_count * 5)
    
    # Contextual category baseline
    cat_score = HIGH_IMPACT_CATEGORIES.get(category.upper(), 50)
    if has_correlation:
        cat_score = min(100, cat_score + 15)

    composite_score = int(round(
        (sev_score * 0.30) +
        (confidence * 0.25) +
        (recency_score * 0.15) +
        (freq_score * 0.10) +
        (rel_score * 0.10) +
        (cat_score * 0.10)
    ))
    
    composite_score = min(100, max(5, composite_score))
    risk_level = classify_risk_level(composite_score)

    return {
        "risk_score": composite_score,
        "risk_level": risk_level,
        "confidence_score": confidence,
        "factors": {
            "severity_component": round(sev_score * 0.30, 1),
            "confidence_component": round(confidence * 0.25, 1),
            "recency_component": round(recency_score * 0.15, 1),
            "frequency_component": round(freq_score * 0.10, 1),
            "reliability_component": round(rel_score * 0.10, 1),
            "context_component": round(cat_score * 0.10, 1)
        },
        "interpretation": (
            f"Calculated risk score is {composite_score}/100 ({risk_level}) with {confidence}% evidentiary confidence. "
            "Defensive rule: High risk signals urgency for triage, not automated verdict of system compromise."
        )
    }
