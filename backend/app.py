"""
Cybersecurity Awareness & Threat Intelligence Dashboard
Flask REST API & Static Web Server

Defensive Cybersecurity Education & SOC Analytics Platform
"""

import json
import os
import sqlite3
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from backend.database import get_db_connection, DB_PATH, MODULES_JSON_PATH, QUIZ_JSON_PATH, seed_database
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk, calculate_confidence_score, classify_risk_level
from backend.services.enrichment_engine import enrich_indicator
from backend.services.correlation_engine import correlate_threat_records, find_related_indicators
from backend.services.alert_engine import generate_threat_alerts
from backend.services.attack_mapper import map_threat_to_attack, get_attack_tactic_info, ATTACK_TACTICS_DEFINITION
from backend.services.vulnerability_engine import calculate_vulnerability_priority
from backend.services.awareness_engine import evaluate_quiz_submission

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# Ensure database exists
if not os.path.exists(DB_PATH):
    seed_database(DB_PATH)

def load_json_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

# -------------------------------------------------------------
# FRONTEND STATIC ROUTES
# -------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

# -------------------------------------------------------------
# DASHBOARD METRICS & TRENDS
# -------------------------------------------------------------
@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    conn = get_db_connection()
    cur = conn.cursor()

    total_threats = cur.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    critical_threats = cur.execute("SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL'").fetchone()[0]
    high_threats = cur.execute("SELECT COUNT(*) FROM threats WHERE severity = 'HIGH'").fetchone()[0]
    active_indicators = cur.execute("SELECT COUNT(DISTINCT indicator_value) FROM threats WHERE status != 'CLOSED' AND status != 'FALSE_POSITIVE'").fetchone()[0]
    open_alerts = cur.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'INVESTIGATING')").fetchone()[0]
    avg_confidence = cur.execute("SELECT AVG(confidence_score) FROM threats").fetchone()[0] or 0
    avg_risk = cur.execute("SELECT AVG(risk_score) FROM threats").fetchone()[0] or 0
    vulns_tracked = cur.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

    # Awareness stats
    quiz_attempts = cur.execute("SELECT COUNT(*) FROM quiz_results").fetchone()[0]
    avg_awareness = cur.execute("SELECT AVG(overall_score) FROM quiz_results").fetchone()[0] or 78.5

    conn.close()

    return jsonify({
        "status": "success",
        "data": {
            "total_threats": total_threats,
            "critical_threats": critical_threats,
            "high_threats": high_threats,
            "active_indicators": active_indicators,
            "open_alerts": open_alerts,
            "avg_confidence": round(avg_confidence, 1),
            "avg_risk": round(avg_risk, 1),
            "vulnerabilities_tracked": vulns_tracked,
            "quiz_attempts": quiz_attempts,
            "avg_awareness_score": round(avg_awareness, 1)
        }
    })

@app.route("/api/dashboard/trends", methods=["GET"])
def get_dashboard_trends():
    conn = get_db_connection()
    cur = conn.cursor()

    # Severity distribution
    sev_data = cur.execute("""
        SELECT severity, COUNT(*) as count
        FROM threats
        GROUP BY severity
        ORDER BY count DESC
    """).fetchall()

    # Category distribution
    cat_data = cur.execute("""
        SELECT category, COUNT(*) as count
        FROM threats
        GROUP BY category
        ORDER BY count DESC
    """).fetchall()

    # Indicator type distribution
    ind_data = cur.execute("""
        SELECT indicator_type, COUNT(*) as count
        FROM threats
        GROUP BY indicator_type
        ORDER BY count DESC
    """).fetchall()

    # MITRE Tactic distribution
    tactic_data = cur.execute("""
        SELECT mitre_tactic, COUNT(*) as count
        FROM threats
        WHERE mitre_tactic != '' AND mitre_tactic IS NOT NULL
        GROUP BY mitre_tactic
        ORDER BY count DESC
        LIMIT 8
    """).fetchall()

    # Status distribution
    status_data = cur.execute("""
        SELECT status, COUNT(*) as count
        FROM threats
        GROUP BY status
        ORDER BY count DESC
    """).fetchall()

    # Vulnerabilities by severity
    vuln_sev = cur.execute("""
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY severity
        ORDER BY count DESC
    """).fetchall()

    # Risk Score ranges
    risk_ranges = {
        "0-20 (Info)": cur.execute("SELECT COUNT(*) FROM threats WHERE risk_score BETWEEN 0 AND 20").fetchone()[0],
        "21-40 (Low)": cur.execute("SELECT COUNT(*) FROM threats WHERE risk_score BETWEEN 21 AND 40").fetchone()[0],
        "41-60 (Med)": cur.execute("SELECT COUNT(*) FROM threats WHERE risk_score BETWEEN 41 AND 60").fetchone()[0],
        "61-80 (High)": cur.execute("SELECT COUNT(*) FROM threats WHERE risk_score BETWEEN 61 AND 80").fetchone()[0],
        "81-100 (Crit)": cur.execute("SELECT COUNT(*) FROM threats WHERE risk_score BETWEEN 81 AND 100").fetchone()[0]
    }

    conn.close()

    return jsonify({
        "status": "success",
        "data": {
            "severity_distribution": [dict(r) for r in sev_data],
            "category_distribution": [dict(r) for r in cat_data],
            "indicator_distribution": [dict(r) for r in ind_data],
            "mitre_tactics": [dict(r) for r in tactic_data],
            "status_distribution": [dict(r) for r in status_data],
            "vulnerability_severity": [dict(r) for r in vuln_sev],
            "risk_distribution": risk_ranges
        }
    })

# -------------------------------------------------------------
# THREATS API (LIST, FILTER, SORT, CREATE, UPDATE)
# -------------------------------------------------------------
@app.route("/api/threats", methods=["GET"])
def get_threats():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 25))
    offset = (page - 1) * limit

    category = request.args.get("category")
    severity = request.args.get("severity")
    indicator_type = request.args.get("indicator_type")
    status = request.args.get("status")
    search_query = request.args.get("q", "").strip()
    sort_by = request.args.get("sort", "newest")

    query = "SELECT * FROM threats WHERE 1=1"
    params = []

    if category:
        query += " AND category = ?"
        params.append(category)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if indicator_type:
        query += " AND indicator_type = ?"
        params.append(indicator_type)
    if status:
        query += " AND status = ?"
        params.append(status)
    if search_query:
        query += " AND (threat_id LIKE ? OR threat_name LIKE ? OR indicator_value LIKE ? OR description LIKE ?)"
        term = f"%{search_query}%"
        params.extend([term, term, term, term])

    # Count total filtered records
    count_query = query.replace("SELECT *", "SELECT COUNT(*)")
    conn = get_db_connection()
    cur = conn.cursor()
    total_count = cur.execute(count_query, params).fetchone()[0]

    # Sorting options
    sort_map = {
        "newest": "last_seen DESC",
        "highest_risk": "risk_score DESC",
        "highest_confidence": "confidence_score DESC",
        "most_observed": "observation_count DESC"
    }
    order_clause = sort_map.get(sort_by, "last_seen DESC")
    query += f" ORDER BY {order_clause} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = cur.execute(query, params).fetchall()
    conn.close()

    return jsonify({
        "status": "success",
        "pagination": {
            "page": page,
            "limit": limit,
            "total_records": total_count,
            "total_pages": (total_count + limit - 1) // limit
        },
        "data": [dict(r) for r in rows]
    })

@app.route("/api/threats/<threat_id>", methods=["GET"])
def get_threat_detail(threat_id):
    conn = get_db_connection()
    cur = conn.cursor()

    row = cur.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": f"Threat {threat_id} not found."}), 404

    threat_dict = dict(row)
    all_threats = [dict(r) for r in cur.execute("SELECT threat_id, threat_name, category as threat_category, indicator_type, indicator_value, severity, risk_score, campaign_id FROM threats LIMIT 500").fetchall()]
    notes = [dict(r) for r in cur.execute("SELECT * FROM analyst_notes WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,)).fetchall()]
    conn.close()

    # Local threat enrichment
    enriched = enrich_indicator(threat_dict["indicator_value"], all_threats)
    enriched["db_record"] = threat_dict
    enriched["analyst_notes"] = notes

    return jsonify({"status": "success", "data": enriched})

@app.route("/api/threats", methods=["POST"])
def create_threat():
    data = request.get_json() or {}
    indicator_val = data.get("indicator_value", "").strip()
    category = data.get("category", "PHISHING")
    source_name = data.get("source_name", "Internal SOC")
    source_reliability = data.get("source_reliability", "B - Usually Reliable")

    # Format validation
    val_res = validate_indicator(indicator_val)
    if not val_res["valid"]:
        return jsonify({
            "status": "error",
            "message": "Invalid indicator format.",
            "details": val_res
        }), 400

    ind_type = val_res["indicator_type"]
    norm_val = val_res["normalized_value"]

    # Calculate Confidence and Risk
    confidence = calculate_confidence_score(source_reliability, observation_count=1)
    risk_calc = calculate_threat_risk(
        severity=data.get("severity", "MEDIUM"),
        confidence=confidence,
        days_since_seen=0,
        observation_count=1,
        source_reliability=source_reliability,
        category=category
    )

    risk_score = risk_calc["risk_score"]
    sev = risk_calc["risk_level"]
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # MITRE ATT&CK Mapping
    attack_info = map_threat_to_attack(category, ind_type)

    conn = get_db_connection()
    cur = conn.cursor()
    
    # Generate ID
    last_id_row = cur.execute("SELECT threat_id FROM threats ORDER BY ROWID DESC LIMIT 1").fetchone()
    next_num = 2201
    if last_id_row:
        try:
            next_num = int(last_id_row[0].replace("THR-2026-", "")) + 1
        except Exception:
            next_num = 2201
    threat_id = f"THR-2026-{next_num:04d}"

    threat_name = data.get("threat_name", f"Observed {category.title()} Indicator {norm_val}")
    desc = data.get("description", f"Analyst-submitted observation for {norm_val} ({ind_type}).")

    cur.execute("""
    INSERT INTO threats (
        threat_id, threat_name, category, indicator_type, indicator_value,
        source_name, source_reliability, confidence_score, severity, risk_score,
        status, first_seen, last_seen, observation_count, campaign_id,
        country, description, mitre_tactic, mitre_technique, mitre_technique_id, cve_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        threat_id, threat_name, category, ind_type, norm_val,
        source_name, source_reliability, confidence, sev, risk_score,
        "NEW", now_str, now_str, 1, data.get("campaign_id", ""),
        data.get("country", "Global / Multi-Region"), desc,
        attack_info["tactic"], attack_info["technique"], attack_info["technique_id"],
        data.get("cve_id", "")
    ))

    # Add to indicators table
    cur.execute("""
    INSERT INTO indicators (threat_id, indicator_type, indicator_value, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?)
    """, (threat_id, ind_type, norm_val, now_str, now_str))

    # If risk is elevated, create alert
    if risk_score >= 60:
        alt_id = f"ALT-{threat_id.replace('THR-', '')}"
        cur.execute("""
        INSERT INTO alerts (alert_id, threat_id, threat_name, indicator_type, indicator_value, category, severity, risk_score, confidence_score, observation_count, status, created_at, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alt_id, threat_id, threat_name, ind_type, norm_val, category,
            sev, risk_score, confidence, 1, "NEW", now_str,
            f"Automated alert: High risk {ind_type} submitted."
        ))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": f"Threat record {threat_id} created successfully.",
        "threat_id": threat_id,
        "risk_score": risk_score,
        "severity": sev,
        "confidence_score": confidence
    }), 201

@app.route("/api/threats/<threat_id>", methods=["PUT"])
def update_threat(threat_id):
    data = request.get_json() or {}
    conn = get_db_connection()
    cur = conn.cursor()

    row = cur.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Threat not found."}), 404

    new_status = data.get("status", row["status"])
    new_desc = data.get("description", row["description"])
    
    cur.execute("""
    UPDATE threats
    SET status = ?, description = ?
    WHERE threat_id = ?
    """, (new_status, new_desc, threat_id))

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": f"Threat {threat_id} updated."})

# -------------------------------------------------------------
# IOC SEARCH & VALIDATION
# -------------------------------------------------------------
@app.route("/api/indicators/search", methods=["GET"])
def search_indicator():
    raw_query = request.args.get("q", "").strip()
    if not raw_query:
        return jsonify({"status": "error", "message": "Query parameter 'q' is required."}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    all_threats = [dict(r) for r in cur.execute("""
        SELECT threat_id, threat_name, category as threat_category, indicator_type,
               indicator_value, severity, risk_score, confidence_score, source_name,
               source_reliability, first_seen, last_seen, status, description,
               campaign_id, cve_id as cve_id_optional
        FROM threats
    """).fetchall()]

    all_vulns = [dict(r) for r in cur.execute("SELECT * FROM vulnerabilities").fetchall()]
    conn.close()

    enrichment_result = enrich_indicator(raw_query, all_threats, all_vulns)
    return jsonify({"status": "success", "data": enrichment_result})

# -------------------------------------------------------------
# ALERTS API & ANALYST WORKFLOW
# -------------------------------------------------------------
@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY risk_score DESC, observation_count DESC LIMIT 100"

    conn = get_db_connection()
    cur = conn.cursor()
    rows = cur.execute(query, params).fetchall()
    conn.close()

    return jsonify({"status": "success", "count": len(rows), "data": [dict(r) for r in rows]})

@app.route("/api/alerts/<alert_id>/status", methods=["PUT"])
def update_alert_status(alert_id):
    data = request.get_json() or {}
    new_status = data.get("status", "").upper()

    valid_statuses = ["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"]
    if new_status not in valid_statuses:
        return jsonify({"status": "error", "message": f"Invalid status. Choose from: {', '.join(valid_statuses)}"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
    
    # Also optionally add an analyst log note if provided
    note = data.get("note")
    threat_id = data.get("threat_id")
    if note and threat_id:
        cur.execute("INSERT INTO analyst_notes (threat_id, author, note_text) VALUES (?, ?, ?)",
                    (threat_id, data.get("author", "SOC Analyst"), f"[Status -> {new_status}] {note}"))

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": f"Alert {alert_id} status updated to {new_status}."})

@app.route("/api/threats/<threat_id>/notes", methods=["GET", "POST"])
def handle_analyst_notes(threat_id):
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        data = request.get_json() or {}
        note_text = data.get("note", "").strip()
        author = data.get("author", "SOC Analyst").strip()

        if not note_text:
            conn.close()
            return jsonify({"status": "error", "message": "Note text is required."}), 400

        cur.execute("INSERT INTO analyst_notes (threat_id, author, note_text) VALUES (?, ?, ?)",
                    (threat_id, author, note_text))
        conn.commit()

    notes = cur.execute("SELECT * FROM analyst_notes WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,)).fetchall()
    conn.close()

    return jsonify({"status": "success", "data": [dict(r) for r in notes]})

# -------------------------------------------------------------
# VULNERABILITY MANAGEMENT & PRIORITIZATION
# -------------------------------------------------------------
@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    conn = get_db_connection()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM vulnerabilities ORDER BY priority_score DESC").fetchall()
    conn.close()
    return jsonify({"status": "success", "count": len(rows), "data": [dict(r) for r in rows]})

@app.route("/api/vulnerabilities/prioritize", methods=["POST"])
def prioritize_vulnerability():
    data = request.get_json() or {}
    try:
        cvss = float(data.get("cvss_score", 7.5))
        epss = float(data.get("epss_score", 0.2))
        is_internet_facing = bool(data.get("is_internet_facing", False))
        is_critical_asset = bool(data.get("is_critical_asset", False))
        known_exploited = bool(data.get("known_exploited", False))
        patch_available = bool(data.get("patch_available", True))

        result = calculate_vulnerability_priority(
            cvss_score=cvss,
            epss_score=epss,
            is_internet_facing=is_internet_facing,
            is_critical_asset=is_critical_asset,
            known_exploited=known_exploited,
            patch_available=patch_available
        )
        return jsonify({"status": "success", "data": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# -------------------------------------------------------------
# CYBERSECURITY AWARENESS CENTER & QUIZ
# -------------------------------------------------------------
@app.route("/api/awareness/modules", methods=["GET"])
def get_awareness_modules():
    modules = load_json_file(MODULES_JSON_PATH)
    category = request.args.get("category")
    if category:
        modules = [m for m in modules if m.get("category") == category.upper()]
    return jsonify({"status": "success", "count": len(modules), "data": modules})

@app.route("/api/awareness/modules/<module_id>", methods=["GET"])
def get_awareness_module_detail(module_id):
    modules = load_json_file(MODULES_JSON_PATH)
    mod = next((m for m in modules if m.get("id") == module_id), None)
    if not mod:
        return jsonify({"status": "error", "message": f"Module {module_id} not found."}), 404
    return jsonify({"status": "success", "data": mod})

@app.route("/api/quiz", methods=["GET"])
def get_quiz_questions():
    questions = load_json_file(QUIZ_JSON_PATH)
    # Sanitize questions: omit correct_index and explanation from initial display
    sanitized = []
    for q in questions:
        sanitized.append({
            "id": q["id"],
            "category": q["category"],
            "question": q["question"],
            "options": q["options"]
        })
    return jsonify({"status": "success", "count": len(sanitized), "data": sanitized})

@app.route("/api/quiz/submit", methods=["POST"])
def submit_quiz():
    data = request.get_json() or {}
    user_answers = data.get("answers", {})
    user_name = data.get("user_name", "Anonymous Defender").strip()

    questions = load_json_file(QUIZ_JSON_PATH)
    eval_result = evaluate_quiz_submission(user_answers, questions)

    # Persist score to DB
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO quiz_results (user_name, overall_score, tier, category_breakdown)
    VALUES (?, ?, ?, ?)
    """, (
        user_name,
        eval_result["overall_score"],
        eval_result["tier"],
        json.dumps(eval_result["category_scores"])
    ))
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "data": eval_result})

# -------------------------------------------------------------
# EXECUTIVE CYBERSECURITY SUMMARY
# -------------------------------------------------------------
@app.route("/api/executive/summary", methods=["GET"])
def get_executive_summary():
    conn = get_db_connection()
    cur = conn.cursor()

    total_threats = cur.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    crit_count = cur.execute("SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL'").fetchone()[0]
    high_count = cur.execute("SELECT COUNT(*) FROM threats WHERE severity = 'HIGH'").fetchone()[0]
    
    top_cats = cur.execute("""
        SELECT category, COUNT(*) as count
        FROM threats
        GROUP BY category
        ORDER BY count DESC
        LIMIT 3
    """).fetchall()

    top_vulns = cur.execute("""
        SELECT product_category, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY product_category
        ORDER BY count DESC
        LIMIT 3
    """).fetchall()

    avg_awareness = cur.execute("SELECT AVG(overall_score) FROM quiz_results").fetchone()[0] or 76.0

    conn.close()

    return jsonify({
        "status": "success",
        "data": {
            "threat_posture_summary": "Moderate Defensive Posture. Active monitoring enabled across 10 threat categories.",
            "critical_and_high_threats": crit_count + high_count,
            "top_threat_vectors": [dict(r) for r in top_cats],
            "top_vulnerable_systems": [dict(r) for r in top_vulns],
            "organization_awareness_health": {
                "average_score": round(avg_awareness, 1),
                "rating": "Good Awareness" if avg_awareness >= 60 else "Requires Nudging"
            },
            "executive_recommendations": [
                "Prioritize rapid patching for critical public-facing web servers and SSO identity gateways.",
                "Reinforce email gateway anti-phishing filters and schedule employee phishing simulation drills.",
                "Enforce FIDO2 phishing-resistant hardware MFA for all administrative and remote access tiers.",
                "Review immutable offline backup integrity as a primary defensive hedge against ransomware."
            ]
        }
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
