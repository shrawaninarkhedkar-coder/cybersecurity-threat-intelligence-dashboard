"""
Automated Test Suite (35+ Comprehensive Unit & Integration Tests)
Cybersecurity Awareness & Threat Intelligence Dashboard
"""

import json
import os
import pytest
import sqlite3

from backend.services.ioc_validator import (
    validate_indicator, is_valid_ipv4, is_valid_ipv6,
    is_valid_domain, is_valid_url, is_valid_hash, is_valid_cve
)
from backend.services.risk_engine import (
    calculate_threat_risk, calculate_confidence_score, classify_risk_level
)
from backend.services.attack_mapper import (
    map_threat_to_attack, get_attack_tactic_info
)
from backend.services.vulnerability_engine import (
    calculate_vulnerability_priority
)
from backend.services.correlation_engine import (
    correlate_threat_records, find_related_indicators
)
from backend.services.alert_engine import (
    generate_threat_alerts, correlate_and_deduplicate_alerts
)
from backend.services.enrichment_engine import (
    enrich_indicator
)
from backend.services.awareness_engine import (
    evaluate_quiz_submission, generate_learning_recommendations
)
from backend.database import (
    get_db_connection, init_db, seed_database
)
from backend.app import app

TEST_DB_PATH = "data/test_threat_intel.db"

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

# -------------------------------------------------------------
# 1-11: IOC VALIDATION TESTS
# -------------------------------------------------------------
def test_01_valid_ipv4():
    res = validate_indicator("198.51.100.25")
    assert res["valid"] is True
    assert res["indicator_type"] == "IP ADDRESS"
    assert res["normalized_value"] == "198.51.100.25"

def test_02_invalid_ipv4():
    res = validate_indicator("999.51.100.25")
    assert res["valid"] is False
    assert res["indicator_type"] == "INVALID"

def test_03_valid_ipv6():
    res = validate_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert res["valid"] is True
    assert res["indicator_type"] == "IPV6"

def test_04_valid_domain():
    res = validate_indicator("portal-login.example.com")
    assert res["valid"] is True
    assert res["indicator_type"] == "DOMAIN"

def test_05_invalid_domain():
    res = validate_indicator("invalid..domain..")
    assert res["valid"] is False

def test_06_valid_url():
    res = validate_indicator("https://auth-verify.example.org/login.php?token=demo")
    assert res["valid"] is True
    assert res["indicator_type"] == "URL"

def test_07_valid_md5_hash():
    val = "098f6bcd4621d373cade4e832627b4f6"
    res = validate_indicator(val)
    assert res["valid"] is True
    assert res["indicator_type"] == "FILE HASH"
    assert "MD5" in res["validation_notes"]

def test_08_valid_sha1_hash():
    val = "a9993e364706816aba3e25717850c26c9cd0d89d"
    res = validate_indicator(val)
    assert res["valid"] is True
    assert res["indicator_type"] == "FILE HASH"
    assert "SHA-1" in res["validation_notes"]

def test_09_valid_sha256_hash():
    val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = validate_indicator(val)
    assert res["valid"] is True
    assert res["indicator_type"] == "FILE HASH"
    assert "SHA-256" in res["validation_notes"]

def test_10_valid_cve():
    res = validate_indicator("CVE-2026-1001")
    assert res["valid"] is True
    assert res["indicator_type"] == "CVE ID"

def test_11_invalid_cve():
    res = validate_indicator("CVE-INVALID-99")
    assert res["valid"] is False

# -------------------------------------------------------------
# 12-15: RISK, CONFIDENCE & RELIABILITY SCORING
# -------------------------------------------------------------
def test_12_threat_risk_calculation():
    calc = calculate_threat_risk(
        severity="CRITICAL",
        confidence=90,
        days_since_seen=1,
        observation_count=10,
        source_reliability="A - Highly Reliable",
        category="RANSOMWARE"
    )
    assert calc["risk_score"] >= 80
    assert calc["risk_level"] == "CRITICAL"
    assert "severity_component" in calc["factors"]

def test_13_confidence_scoring_distinction():
    conf_high = calculate_confidence_score("A - Highly Reliable", observation_count=5, has_correlations=True)
    conf_low = calculate_confidence_score("D - Reliability Unknown", observation_count=1, has_correlations=False)
    assert conf_high > conf_low
    assert conf_high <= 100
    assert conf_low >= 10

def test_14_risk_classification_tiers():
    assert classify_risk_level(15) == "INFORMATIONAL"
    assert classify_risk_level(35) == "LOW"
    assert classify_risk_level(55) == "MEDIUM"
    assert classify_risk_level(75) == "HIGH"
    assert classify_risk_level(95) == "CRITICAL"

def test_15_source_reliability_mapping():
    conf_a = calculate_confidence_score("A - Highly Reliable")
    conf_b = calculate_confidence_score("B - Usually Reliable")
    conf_c = calculate_confidence_score("C - Fairly Reliable")
    assert conf_a > conf_b > conf_c

# -------------------------------------------------------------
# 16-19: ENRICHMENT, SEARCH & CORRELATION
# -------------------------------------------------------------
def test_16_local_ioc_enrichment():
    sample_records = [{
        "threat_id": "THR-TEST-001",
        "threat_name": "Test Phish",
        "threat_category": "PHISHING",
        "indicator_type": "DOMAIN",
        "indicator_value": "portal-login.example.com",
        "severity": "HIGH",
        "risk_score": 78,
        "confidence_score": 85,
        "source_name": "Internal SOC",
        "source_reliability": "A - Highly Reliable",
        "first_seen": "2026-01-01 10:00:00",
        "last_seen": "2026-01-05 12:00:00",
        "status": "MONITORING",
        "campaign_id": "CAMP-01"
    }]
    res = enrich_indicator("portal-login.example.com", sample_records)
    assert res["is_valid_format"] is True
    assert res["known_in_dataset"] is True
    assert res["risk_score"] == 78
    assert res["category"] == "PHISHING"
    assert len(res["recommended_actions"]) > 0

def test_17_unknown_indicator_enrichment():
    res = enrich_indicator("203.0.113.99", [])
    assert res["is_valid_format"] is True
    assert res["known_in_dataset"] is False
    assert res["status"] == "NEW"

def test_18_threat_correlation_clustering():
    records = [
        {"threat_id": "T1", "campaign_id": "CAMP-A", "threat_category": "PHISHING", "indicator_value": "192.0.2.1"},
        {"threat_id": "T2", "campaign_id": "CAMP-A", "threat_category": "PHISHING", "indicator_value": "192.0.2.2"},
        {"threat_id": "T3", "campaign_id": "CAMP-B", "threat_category": "MALWARE", "indicator_value": "192.0.2.3"}
    ]
    clusters = correlate_threat_records(records)
    assert clusters["total_clusters"] == 1
    assert clusters["clusters"][0]["cluster_id"] == "CLUS-CAMP-A"

def test_19_related_indicators_lookup():
    target = {"threat_id": "T1", "campaign_id": "CAMP-A", "threat_category": "PHISHING", "indicator_type": "IP ADDRESS", "indicator_value": "192.0.2.10"}
    all_recs = [
        {"threat_id": "T1", "campaign_id": "CAMP-A", "threat_category": "PHISHING", "indicator_type": "IP ADDRESS", "indicator_value": "192.0.2.10", "severity": "HIGH", "risk_score": 75},
        {"threat_id": "T2", "campaign_id": "CAMP-A", "threat_category": "PHISHING", "indicator_type": "DOMAIN", "indicator_value": "sub1.example.org", "severity": "HIGH", "risk_score": 80},
        {"threat_id": "T3", "campaign_id": "OTHER", "threat_category": "PHISHING", "indicator_type": "IP ADDRESS", "indicator_value": "192.0.2.15", "severity": "HIGH", "risk_score": 70}
    ]
    related = find_related_indicators(target, all_recs)
    assert len(related) >= 2

# -------------------------------------------------------------
# 20-22: ALERT ENGINE & FATIGUE REDUCTION
# -------------------------------------------------------------
def test_20_alert_generation():
    threats = [
        {"threat_id": "T-01", "threat_name": "Ransom Alert", "indicator_type": "IP ADDRESS", "indicator_value": "198.51.100.1", "threat_category": "RANSOMWARE", "severity": "CRITICAL", "risk_score": 90, "confidence_score": 80, "observation_count": 2, "status": "NEW", "timestamp": "2026-01-01"},
        {"threat_id": "T-02", "threat_name": "Low Info", "indicator_type": "DOMAIN", "indicator_value": "safe.example.com", "threat_category": "WEB THREATS", "severity": "LOW", "risk_score": 25, "confidence_score": 50, "observation_count": 1, "status": "CLOSED", "timestamp": "2026-01-01"}
    ]
    alerts = generate_threat_alerts(threats, min_risk_threshold=60)
    assert len(alerts) == 1
    assert alerts[0]["threat_id"] == "T-01"

def test_21_alert_fatigue_deduplication():
    raw_alerts = [
        {"alert_id": "A1", "threat_id": "T1", "threat_name": "Spam IP", "indicator_type": "IP ADDRESS", "indicator_value": "198.51.100.5", "category": "NETWORK", "severity": "HIGH", "risk_score": 70, "confidence_score": 80, "observation_count": 10, "status": "NEW", "timestamp": "2026-01-01", "description": "hit"},
        {"alert_id": "A2", "threat_id": "T2", "threat_name": "Spam IP", "indicator_type": "IP ADDRESS", "indicator_value": "198.51.100.5", "category": "NETWORK", "severity": "HIGH", "risk_score": 75, "confidence_score": 85, "observation_count": 15, "status": "NEW", "timestamp": "2026-01-01", "description": "hit"}
    ]
    dedup = correlate_and_deduplicate_alerts(raw_alerts)
    assert len(dedup) == 1
    assert dedup[0]["observation_count"] == 25

def test_22_alert_status_transition(client):
    res = client.put("/api/alerts/ALT-0001/status", json={"status": "INVESTIGATING", "threat_id": "THR-2026-0001", "author": "Analyst", "note": "Triaging"})
    assert res.status_code in [200, 400]

# -------------------------------------------------------------
# 23-25: ATT&CK, VULNERABILITIES & ANALYST NOTES
# -------------------------------------------------------------
def test_23_attack_mapping():
    phish_map = map_threat_to_attack("PHISHING")
    assert phish_map["tactic"] == "Initial Access"
    assert phish_map["technique_id"] == "T1566"

    ransom_map = map_threat_to_attack("RANSOMWARE")
    assert ransom_map["tactic"] == "Impact"
    assert ransom_map["technique_id"] == "T1486"

def test_24_attack_tactic_metadata():
    tac = get_attack_tactic_info("Initial Access")
    assert tac["id"] == "TA0001"
    assert "Email filtering" in tac["defensive_focus"]

def test_25_vulnerability_prioritization():
    # Contextual priority: internet facing critical asset with KEV
    high_prio = calculate_vulnerability_priority(
        cvss_score=7.5,
        epss_score=0.4,
        is_internet_facing=True,
        is_critical_asset=True,
        known_exploited=True
    )
    # Low priority: isolated test system
    low_prio = calculate_vulnerability_priority(
        cvss_score=7.5,
        epss_score=0.1,
        is_internet_facing=False,
        is_critical_asset=False,
        known_exploited=False
    )
    assert high_prio["priority_score"] > low_prio["priority_score"]
    assert "CRITICAL" in high_prio["priority_tier"] or "HIGH" in high_prio["priority_tier"]

# -------------------------------------------------------------
# 26-32: AWARENESS QUIZ & RECOMMENDATIONS
# -------------------------------------------------------------
def test_26_quiz_scoring_evaluation():
    bank = [
        {"id": "Q1", "category": "PHISHING", "question": "Q1", "correct_index": 2},
        {"id": "Q2", "category": "PASSWORDS", "question": "Q2", "correct_index": 1}
    ]
    user_answers = {"Q1": 2, "Q2": 1}
    res = evaluate_quiz_submission(user_answers, bank)
    assert res["overall_score"] == 100
    assert res["tier"].startswith("Strong")

def test_27_quiz_weak_category_recommendations():
    category_scores = {
        "PHISHING": {"correct": 1, "total": 4, "percentage": 25},
        "PASSWORDS": {"correct": 4, "total": 4, "percentage": 100}
    }
    recs = generate_learning_recommendations(category_scores)
    assert len(recs) >= 1
    assert recs[0]["category"] == "PHISHING"
    assert recs[0]["priority"] == "URGENT"

def test_28_analyst_notes_api(client):
    res = client.post("/api/threats/THR-2026-0001/notes", json={
        "note": "Automated verification note from unit test.",
        "author": "Test Runner"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"

# -------------------------------------------------------------
# 29-35: API ENDPOINTS, FILTERING & DATABASE
# -------------------------------------------------------------
def test_29_api_dashboard_stats(client):
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    d = res.get_json()["data"]
    assert d["total_threats"] >= 2000
    assert d["vulnerabilities_tracked"] >= 50

def test_30_api_threat_filtering_severity(client):
    res = client.get("/api/threats?severity=CRITICAL&limit=5")
    assert res.status_code == 200
    data = res.get_json()
    for row in data["data"]:
        assert row["severity"] == "CRITICAL"

def test_31_api_threat_filtering_category(client):
    res = client.get("/api/threats?category=RANSOMWARE&limit=5")
    assert res.status_code == 200
    data = res.get_json()
    for row in data["data"]:
        assert row["category"] == "RANSOMWARE"

def test_32_api_ioc_search(client):
    res = client.get("/api/indicators/search?q=198.51.100.25")
    assert res.status_code == 200
    data = res.get_json()["data"]
    assert data["is_valid_format"] is True

def test_33_api_vulnerabilities_list(client):
    res = client.get("/api/vulnerabilities")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] > 0

def test_34_api_awareness_modules(client):
    res = client.get("/api/awareness/modules")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] >= 15

def test_35_api_executive_summary(client):
    res = client.get("/api/executive/summary")
    assert res.status_code == 200
    data = res.get_json()["data"]
    assert "threat_posture_summary" in data
    assert len(data["executive_recommendations"]) > 0

def test_36_empty_indicator_validation_edge_case():
    res = validate_indicator("")
    assert res["valid"] is False
    assert res["indicator_type"] == "UNKNOWN"

def test_37_database_persistence():
    conn = get_db_connection()
    cur = conn.cursor()
    count = cur.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    conn.close()
    assert count >= 2000
