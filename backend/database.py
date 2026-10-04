"""
Database Management & SQLite Persistence Layer
Defensive Cybersecurity Education & SOC Analytics Platform

Handles initialization, schema creation, synthetic data seeding, and query operations.
"""

import csv
import json
import os
import sqlite3
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
AWARENESS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "awareness")
DB_PATH = os.path.join(DATA_DIR, "threat_intelligence.db")
CSV_DATASET_PATH = os.path.join(DATA_DIR, "threat_intelligence_dataset.csv")
CSV_VULN_PATH = os.path.join(DATA_DIR, "vulnerabilities.csv")
MODULES_JSON_PATH = os.path.join(AWARENESS_DIR, "modules.json")
QUIZ_JSON_PATH = os.path.join(AWARENESS_DIR, "quiz_questions.json")

def get_db_connection(db_path=DB_PATH):
    """Establish connection to SQLite database with dictionary-like row access."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=DB_PATH):
    """Create all required relational tables and indexes."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    # 1. Threats Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        threat_id TEXT PRIMARY KEY,
        threat_name TEXT NOT NULL,
        category TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        source_name TEXT,
        source_reliability TEXT,
        confidence_score INTEGER,
        severity TEXT,
        risk_score INTEGER,
        status TEXT,
        first_seen TEXT,
        last_seen TEXT,
        observation_count INTEGER DEFAULT 1,
        campaign_id TEXT,
        country TEXT,
        description TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        mitre_technique_id TEXT,
        cve_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. Indicators Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        indicator_type TEXT,
        indicator_value TEXT,
        first_seen TEXT,
        last_seen TEXT,
        FOREIGN KEY (threat_id) REFERENCES threats (threat_id)
    )
    """)

    # 3. Vulnerabilities Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        vulnerability_id TEXT PRIMARY KEY,
        cve_id TEXT NOT NULL,
        product_category TEXT,
        product_name TEXT,
        severity TEXT,
        cvss_score REAL,
        epss_score REAL,
        known_exploited TEXT,
        patch_available TEXT,
        published_date TEXT,
        priority_score INTEGER,
        description TEXT,
        remediation_guidance TEXT
    )
    """)

    # 4. Alerts Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        threat_id TEXT,
        threat_name TEXT,
        indicator_type TEXT,
        indicator_value TEXT,
        category TEXT,
        severity TEXT,
        risk_score INTEGER,
        confidence_score INTEGER,
        observation_count INTEGER,
        status TEXT DEFAULT 'NEW',
        created_at TEXT,
        description TEXT,
        FOREIGN KEY (threat_id) REFERENCES threats (threat_id)
    )
    """)

    # 5. Analyst Notes Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analyst_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        author TEXT DEFAULT 'SOC Analyst',
        note_text TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (threat_id) REFERENCES threats (threat_id)
    )
    """)

    # 6. Quiz Results Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS quiz_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT DEFAULT 'Anonymous Defender',
        overall_score INTEGER,
        tier TEXT,
        category_breakdown TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create Performance Indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threats(indicator_value)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_category ON threats(category)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_risk ON threats(risk_score)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")

    conn.commit()
    conn.close()
    print("[+] Database schema initialized successfully.")

def seed_database(db_path=DB_PATH):
    """Seed SQLite database from CSV datasets and populate initial alerts."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    # Check if threats table already populated
    threat_count = cur.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    if threat_count == 0 and os.path.exists(CSV_DATASET_PATH):
        print("[*] Seeding threat intelligence records from CSV...")
        with open(CSV_DATASET_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            threat_rows = []
            indicator_rows = []
            for r in reader:
                threat_rows.append((
                    r["threat_id"], r["threat_name"], r["threat_category"],
                    r["indicator_type"], r["indicator_value"], r["source_name"],
                    r["source_reliability"], int(r["confidence_score"]), r["severity"],
                    int(r["risk_score"]), r["status"], r["first_seen"], r["last_seen"],
                    int(r.get("observation_count", 1)), r.get("campaign_id", ""),
                    r.get("country_or_region_optional", ""), r["description"],
                    r.get("mitre_tactic_optional", ""), r.get("mitre_technique_optional", ""),
                    r.get("mitre_technique_id_optional", ""), r.get("cve_id_optional", "")
                ))
                indicator_rows.append((
                    r["threat_id"], r["indicator_type"], r["indicator_value"],
                    r["first_seen"], r["last_seen"]
                ))

            cur.executemany("""
            INSERT OR REPLACE INTO threats (
                threat_id, threat_name, category, indicator_type, indicator_value,
                source_name, source_reliability, confidence_score, severity,
                risk_score, status, first_seen, last_seen, observation_count,
                campaign_id, country, description, mitre_tactic, mitre_technique,
                mitre_technique_id, cve_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, threat_rows)

            cur.executemany("""
            INSERT INTO indicators (
                threat_id, indicator_type, indicator_value, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?)
            """, indicator_rows)

        print(f"[+] Loaded {len(threat_rows)} threat records into SQLite.")

    # Seed Vulnerabilities
    vuln_count = cur.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    if vuln_count == 0 and os.path.exists(CSV_VULN_PATH):
        print("[*] Seeding vulnerabilities from CSV...")
        with open(CSV_VULN_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            vuln_rows = []
            for r in reader:
                vuln_rows.append((
                    r["vulnerability_id"], r["cve_id"], r["product_category"],
                    r["product_name"], r["severity"], float(r["cvss_score"]),
                    float(r["epss_score"]), r["known_exploited_demo"], r["patch_available"],
                    r["published_date"], int(r["priority_score"]), r["description"],
                    r["remediation_guidance"]
                ))
            cur.executemany("""
            INSERT OR REPLACE INTO vulnerabilities (
                vulnerability_id, cve_id, product_category, product_name, severity,
                cvss_score, epss_score, known_exploited, patch_available, published_date,
                priority_score, description, remediation_guidance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, vuln_rows)
        print(f"[+] Loaded {len(vuln_rows)} vulnerability records into SQLite.")

    # Seed Initial Alerts
    alert_count = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if alert_count == 0:
        print("[*] Generating baseline SOC alerts from high-risk threats...")
        high_threats = cur.execute("""
        SELECT threat_id, threat_name, indicator_type, indicator_value, category,
               severity, risk_score, confidence_score, observation_count, last_seen, description
        FROM threats
        WHERE risk_score >= 65 OR severity IN ('HIGH', 'CRITICAL')
        LIMIT 60
        """).fetchall()

        alert_rows = []
        for t in high_threats:
            alt_id = f"ALT-{t['threat_id'].replace('THR-', '')}"
            desc = f"Elevated alert: {t['indicator_type']} '{t['indicator_value']}' observed ({t['severity']} - Risk: {t['risk_score']}/100)."
            alert_rows.append((
                alt_id, t["threat_id"], t["threat_name"], t["indicator_type"],
                t["indicator_value"], t["category"], t["severity"], t["risk_score"],
                t["confidence_score"], t["observation_count"], "NEW", t["last_seen"], desc
            ))

        cur.executemany("""
        INSERT OR REPLACE INTO alerts (
            alert_id, threat_id, threat_name, indicator_type, indicator_value,
            category, severity, risk_score, confidence_score, observation_count,
            status, created_at, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, alert_rows)
        print(f"[+] Generated {len(alert_rows)} baseline alerts.")

    # Seed initial sample analyst notes
    note_count = cur.execute("SELECT COUNT(*) FROM analyst_notes").fetchone()[0]
    if note_count == 0:
        sample_notes = [
            ("THR-2026-0001", "Tier 1 SOC Analyst", "Initial triage complete. Corroborated with external telemetry."),
            ("THR-2026-0005", "Senior CTI Analyst", "Campaign cluster linked to automated credential harvesting."),
            ("THR-2026-0012", "Incident Responder", "Host isolated, memory artifact preserved, firewall rule applied.")
        ]
        cur.executemany("""
        INSERT INTO analyst_notes (threat_id, author, note_text) VALUES (?, ?, ?)
        """, sample_notes)

    conn.commit()
    conn.close()
    print("[+] Database seeding complete!")

if __name__ == "__main__":
    seed_database()
