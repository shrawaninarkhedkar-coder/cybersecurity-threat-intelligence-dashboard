"""
Awareness Scoring & Personalized Recommendation Engine
Defensive Cybersecurity Education & SOC Analytics Platform

Evaluates quiz submissions, calculates category-level awareness scores,
identifies knowledge gaps, and recommends targeted educational modules.
"""

from collections import defaultdict

CATEGORY_MODULE_MAP = {
    "PHISHING": {"module_id": "AWR-01", "module_title": "Phishing Awareness & Email Defense"},
    "PASSWORDS": {"module_id": "AWR-02", "module_title": "Password Security & Passphrase Hygiene"},
    "MFA": {"module_id": "AWR-03", "module_title": "Multi-Factor Authentication (MFA) & Phishing Resistance"},
    "SOCIAL ENGINEERING": {"module_id": "AWR-04", "module_title": "Social Engineering & Vishing/Smishing Defense"},
    "SAFE BROWSING": {"module_id": "AWR-05", "module_title": "Safe Web Browsing & Malicious Downloads"},
    "SECURE WI-FI": {"module_id": "AWR-06", "module_title": "Secure Wi-Fi & Public Network Protection"},
    "SOFTWARE UPDATES": {"module_id": "AWR-07", "module_title": "Software Patching & Vulnerability Hygiene"},
    "RANSOMWARE": {"module_id": "AWR-08", "module_title": "Ransomware Awareness & Defensive Measures"},
    "REMOVABLE MEDIA": {"module_id": "AWR-09", "module_title": "Removable Media & USB Security"},
    "DATA EXPOSURE": {"module_id": "AWR-10", "module_title": "Data Privacy & Information Classification"},
    "MOBILE SECURITY": {"module_id": "AWR-11", "module_title": "Mobile Device Security & App Permissions"},
    "REMOTE WORK": {"module_id": "AWR-12", "module_title": "Remote Work & Home Network Defense"},
    "ACCOUNT SECURITY": {"module_id": "AWR-13", "module_title": "Cloud Account Security & API Token Hygiene"},
    "INCIDENT REPORTING": {"module_id": "AWR-14", "module_title": "Incident Reporting & Timely Escalation"},
    "AI SCAMS": {"module_id": "AWR-15", "module_title": "AI-Enabled Scams & Deepfake Defense"}
}

def evaluate_quiz_submission(user_answers: dict, question_bank: list[dict]) -> dict:
    """
    Evaluate user quiz responses.
    
    user_answers: dict of {question_id: selected_option_index}
    question_bank: list of question dicts
    """
    total_questions = len(question_bank)
    if total_questions == 0:
        return {
            "overall_score": 0,
            "tier": "Needs Improvement",
            "category_scores": {},
            "recommendations": []
        }

    correct_count = 0
    category_totals = defaultdict(int)
    category_correct = defaultdict(int)
    question_evaluations = []

    q_lookup = {q["id"]: q for q in question_bank}

    for q in question_bank:
        qid = q["id"]
        cat = q.get("category", "GENERAL")
        category_totals[cat] += 1
        
        user_choice = user_answers.get(qid)
        is_correct = (user_choice == q["correct_index"])
        
        if is_correct:
            correct_count += 1
            category_correct[cat] += 1

        question_evaluations.append({
            "question_id": qid,
            "category": cat,
            "question": q["question"],
            "user_choice": user_choice,
            "correct_choice": q["correct_index"],
            "is_correct": is_correct,
            "explanation": q.get("explanation", "")
        })

    overall_score = int(round((correct_count / total_questions) * 100))

    # Determine Tier
    if overall_score >= 81:
        tier = "Strong Awareness (Cyber Champion)"
        summary_msg = "Outstanding cybersecurity vigilance! You demonstrate strong defensive habits."
    elif overall_score >= 61:
        tier = "Good Awareness (Proficient Defender)"
        summary_msg = "Good foundational knowledge with minor gaps in specialized defensive areas."
    elif overall_score >= 41:
        tier = "Basic Awareness (Developing Defender)"
        summary_msg = "Basic understanding present. Recommended to review target awareness modules."
    else:
        tier = "Needs Improvement (High Vulnerability Risk)"
        summary_msg = "Immediate review of essential security practices recommended to prevent incidents."

    # Compute category percentages
    category_breakdown = {}
    for cat, total in category_totals.items():
        corr = category_correct.get(cat, 0)
        pct = int(round((corr / total) * 100))
        category_breakdown[cat] = {
            "correct": corr,
            "total": total,
            "percentage": pct
        }

    # Generate Personalized Recommendations
    recommendations = generate_learning_recommendations(category_breakdown)

    return {
        "overall_score": overall_score,
        "correct_answers": correct_count,
        "total_questions": total_questions,
        "tier": tier,
        "summary": summary_msg,
        "category_scores": category_breakdown,
        "recommendations": recommendations,
        "detailed_results": question_evaluations
    }

def generate_learning_recommendations(category_scores: dict) -> list[dict]:
    """
    Generate targeted learning recommendations for categories scoring below 75%.
    """
    recommendations = []
    
    # Sort categories by lowest score first
    sorted_cats = sorted(category_scores.items(), key=lambda x: x[1]["percentage"])

    for cat, data in sorted_cats:
        pct = data["percentage"]
        if pct < 75:
            mod_info = CATEGORY_MODULE_MAP.get(cat, {
                "module_id": "AWR-01",
                "module_title": f"{cat.title()} Awareness Training"
            })
            
            priority = "URGENT" if pct < 50 else "RECOMMENDED"
            recommendations.append({
                "category": cat,
                "score_percentage": pct,
                "priority": priority,
                "module_id": mod_info["module_id"],
                "module_title": mod_info["module_title"],
                "reason": f"Scored {pct}% in {cat.title()}. Complete the module to reinforce defensive habits."
            })

    if not recommendations:
        recommendations.append({
            "category": "ADVANCED DEFENSE",
            "score_percentage": 100,
            "priority": "OPTIONAL",
            "module_id": "AWR-15",
            "module_title": "AI-Enabled Scams & Deepfake Defense",
            "reason": "All core areas scored high! Explore emerging AI threat awareness."
        })

    return recommendations
