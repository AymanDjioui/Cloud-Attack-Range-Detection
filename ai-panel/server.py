# AI Insights Dashboard - Real-time SOC Panel with Security Assistant
#!/usr/bin/env python3
"""
AI Insights Web Panel — Phase 5
================================
Flask API that serves AI analysis results from PostgreSQL
to the frontend dashboard.
"""

from flask import Flask, jsonify, send_from_directory, request
import psycopg2
import psycopg2.extras
import os
import json
import requests

app = Flask(__name__, static_folder="public", static_url_path="")

DB_URL = os.getenv("DATABASE_URL", "postgresql://admin:admin_password@db:5432/insights_db")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def get_db():
    return psycopg2.connect(DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


@app.route("/")
def index():
    return send_from_directory("public", "index.html")


@app.route("/api/insights")
def get_insights():
    """Get all AI insights, newest first. Supports time filtering."""
    hours = request.args.get("hours", None)
    conn = get_db()
    cur = conn.cursor()

    if hours:
        cur.execute("""
            SELECT id, alert_id, timestamp, rule_id, rule_level,
                   rule_description, source_ip, agent_name, severity,
                   ai_summary, ai_analysis, ai_remediation, threat_hunting, ai_ioc, mitre_tactics
            FROM ai_insights
            WHERE timestamp >= NOW() - INTERVAL '%s hours'
            ORDER BY timestamp DESC
            LIMIT 100
        """, (int(hours),))
    else:
        cur.execute("""
            SELECT id, alert_id, timestamp, rule_id, rule_level,
                   rule_description, source_ip, agent_name, severity,
                   ai_summary, ai_analysis, ai_remediation, threat_hunting, ai_ioc, mitre_tactics
            FROM ai_insights
            ORDER BY timestamp DESC
            LIMIT 100
        """)
    rows = cur.fetchall()
    cur.close()
    conn.close()

    insights = []
    for row in rows:
        r = dict(row)
        r["timestamp"] = r["timestamp"].isoformat() if r["timestamp"] else None
        insights.append(r)

    return jsonify({"success": True, "insights": insights, "total": len(insights)})


@app.route("/api/insights/stats")
def get_stats():
    """Get summary statistics."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as total FROM ai_insights")
    total = cur.fetchone()["total"]

    cur.execute("SELECT severity, COUNT(*) as count FROM ai_insights GROUP BY severity ORDER BY count DESC")
    by_severity = cur.fetchall()

    cur.execute("SELECT rule_id, rule_description, COUNT(*) as count FROM ai_insights GROUP BY rule_id, rule_description ORDER BY count DESC LIMIT 10")
    top_rules = cur.fetchall()

    cur.execute("SELECT source_ip, COUNT(*) as count FROM ai_insights GROUP BY source_ip ORDER BY count DESC LIMIT 10")
    top_ips = cur.fetchall()

    # MITRE tactics distribution
    cur.execute("SELECT mitre_tactics FROM ai_insights WHERE mitre_tactics IS NOT NULL")
    mitre_rows = cur.fetchall()
    mitre_counts = {}
    for row in mitre_rows:
        tactics = row["mitre_tactics"]
        if isinstance(tactics, str):
            tactics = json.loads(tactics)
        if isinstance(tactics, list):
            for t in tactics:
                mitre_counts[t] = mitre_counts.get(t, 0) + 1
    mitre_dist = [{"tactic": k, "count": v} for k, v in sorted(mitre_counts.items(), key=lambda x: -x[1])]

    # Alert trend by hour (last 24h)
    cur.execute("""
        SELECT date_trunc('hour', timestamp) as hour, COUNT(*) as count
        FROM ai_insights
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour ASC
    """)
    trend_rows = cur.fetchall()
    alert_trend = [{"hour": r["hour"].isoformat() if r["hour"] else None, "count": r["count"]} for r in trend_rows]

    cur.close()
    conn.close()

    return jsonify({
        "success": True,
        "stats": {
            "total_insights": total,
            "by_severity": [dict(r) for r in by_severity],
            "top_rules": [dict(r) for r in top_rules],
            "top_source_ips": [dict(r) for r in top_ips],
            "mitre_distribution": mitre_dist,
            "alert_trend_24h": alert_trend
        }
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "ai-insights-panel"})


@app.route("/api/chat", methods=["POST"])
def chat():
    """Chat Assistant — uses OpenRouter (free models) or falls back to Gemini."""
    data = request.json
    user_msg = data.get("message", "")
    context = data.get("context", "")

    openrouter_key = os.getenv("OPENROUTER_API_KEY", "")
    gemini_key = GEMINI_API_KEY

    print(f"[CHAT] OpenRouter key set: {bool(openrouter_key)}, Gemini key set: {bool(gemini_key)}")

    if not openrouter_key and not gemini_key:
        return jsonify({
            "success": False,
            "reply": "AI Assistant offline. No API keys found. Set OPENROUTER_API_KEY or GEMINI_API_KEY in .env file."
        })

    system_prompt = (
        "You are a Senior SOC Analyst AI Assistant embedded in a Wazuh-based Cloud Security Range dashboard. "
        "Help security analysts understand alerts, suggest remediation, and answer security questions. "
        "Keep answers concise, professional, and actionable. Use bullet points where helpful."
    )

    # ── Try OpenRouter (rotate through free models) ──
    FREE_MODELS = [
        "google/gemma-4-31b-it:free",
        "deepseek/deepseek-r1:free",
        "meta-llama/llama-3.1-8b-instruct:free",
        "google/gemma-2-9b-it:free",
    ]

    if openrouter_key:
        for model in FREE_MODELS:
            try:
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Dashboard Context:\n{context}\n\nAnalyst Question: {user_msg}"}
                    ],
                    "max_tokens": 800,
                    "temperature": 0.4
                }
                print(f"[CHAT] Trying {model}...")
                r = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {openrouter_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "http://192.168.100.10:3000",
                        "X-Title": "SOC AI Assistant"
                    },
                    json=payload,
                    timeout=30
                )
                if r.status_code == 429:
                    print(f"[CHAT] {model} rate-limited, trying next...")
                    continue
                if r.status_code != 200:
                    print(f"[CHAT] {model} error {r.status_code}: {r.text[:200]}")
                    continue
                resp = r.json()
                text = resp["choices"][0]["message"]["content"]
                print(f"[CHAT] Success with {model}")
                return jsonify({"success": True, "reply": text.strip()})
            except Exception as e:
                print(f"[CHAT] {model} failed: {e}")
                continue

        # All free models failed, try Gemini
        if not gemini_key:
            return jsonify({"success": False, "reply": "All free AI models are busy. Please wait 30 seconds and try again."})

    # ── Fallback to Gemini ──
    prompt = f"{system_prompt}\n\nDashboard Context:\n{context}\n\nAnalyst Question: {user_msg}"
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.4, "maxOutputTokens": 800}
        }
        r = requests.post(url, json=payload, timeout=20)
        r.raise_for_status()
        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        return jsonify({"success": True, "reply": text.strip()})
    except Exception as e:
        err = str(e).replace(gemini_key, "***") if gemini_key else str(e)
        print(f"[CHAT] Gemini Error: {err}")
        return jsonify({"success": False, "reply": "AI service temporarily unavailable. Try again shortly."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
