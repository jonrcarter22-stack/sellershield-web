"""
SellerShield Web App
--------------------
Flask server that runs compliance audits and serves results via a web UI.

Free tier:  score, grade, platform breakdown, issue names only
Paid tier:  full fix details + PDF download (linked to Gumroad)
"""

import os
import sys
import uuid
import json
import threading
from pathlib import Path
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, abort

# Add engine directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))

from audit_engine import AuditEngine
from report_generator import generate_pdf

app = Flask(__name__)

# ── In-memory audit cache (results live for 2 hours) ────────────────────────
# Keyed by audit_id → {result, pdf_path, expires_at}
_cache = {}
_cache_lock = threading.Lock()

REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Gumroad product link — update this once your Gumroad listing is live
GUMROAD_URL = "https://carterverse838.gumroad.com/l/pcarai"

PLATFORM_LABELS = {
    "google":  "Google Merchant Center",
    "amazon":  "Amazon Seller Central",
    "tiktok":  "TikTok Shop",
    "meta":    "Meta Commerce",
    "walmart": "Walmart Marketplace",
}


def _clean_cache():
    """Remove expired entries from cache."""
    now = datetime.utcnow()
    with _cache_lock:
        expired = [k for k, v in _cache.items() if v["expires_at"] < now]
        for k in expired:
            # Clean up PDF file too
            try:
                Path(_cache[k]["pdf_path"]).unlink(missing_ok=True)
            except Exception:
                pass
            del _cache[k]


def _result_to_dict(result, audit_id: str) -> dict:
    """Serialize AuditResult to a JSON-safe dict for the frontend."""
    platforms = []
    for ps in result.platform_scores:
        findings = []
        for f in ps.findings:
            findings.append({
                "severity":  f.severity,
                "category":  f.category,
                "message":   f.message,
                "fix":       f.fix,
                "evidence":  f.evidence,
                "rule_id":   f.rule_id,
            })
        platforms.append({
            "name":     ps.name,
            "platform": ps.platform,
            "score":    ps.score,
            "grade":    ps.grade,
            "passed":   ps.passed,
            "failed":   ps.failed,
            "findings": findings,
        })

    # Deduplicate all_findings by rule_id for the summary list
    seen, unique_findings = set(), []
    for f in result.all_findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            unique_findings.append({
                "severity": f.severity,
                "message":  f.message,
                "fix":      f.fix,
                "rule_id":  f.rule_id,
            })

    return {
        "audit_id":        audit_id,
        "url":             result.url,
        "timestamp":       result.timestamp[:19].replace("T", " "),
        "overall_score":   result.overall_score,
        "overall_grade":   result.overall_grade,
        "ssl_ok":          result.ssl_ok,
        "pages_found":     result.pages_found,
        "pages_missing":   result.pages_missing,
        "platforms":       platforms,
        "all_findings":    unique_findings,
        "suspension_count": len(result.suspension_warnings),
        "crawl_error":     result.crawl_error,
        "gumroad_url":     GUMROAD_URL,
    }


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", gumroad_url=GUMROAD_URL)


@app.route("/audit", methods=["POST"])
def run_audit():
    """Run an audit. Returns JSON with free-tier results."""
    _clean_cache()

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    platforms_raw = (data.get("platforms") or "google,amazon,tiktok,meta,walmart").strip()

    if not url:
        return jsonify({"error": "Please enter a store URL."}), 400

    if not url.startswith("http"):
        url = "https://" + url

    platforms = [p.strip() for p in platforms_raw.split(",") if p.strip()]
    valid = {"google", "amazon", "tiktok", "meta", "walmart"}
    platforms = [p for p in platforms if p in valid] or list(valid)

    try:
        engine = AuditEngine(timeout=12)
        result = engine.audit(url, platforms)
    except Exception as e:
        return jsonify({"error": f"Audit failed: {str(e)}"}), 500

    audit_id = str(uuid.uuid4())[:8]

    # Generate PDF in background and cache
    pdf_path = str(REPORTS_DIR / f"sellershield_{audit_id}.pdf")
    try:
        generate_pdf(result, pdf_path)
    except Exception:
        pdf_path = None

    with _cache_lock:
        _cache[audit_id] = {
            "result":     result,
            "result_dict": _result_to_dict(result, audit_id),
            "pdf_path":   pdf_path,
            "expires_at": datetime.utcnow() + timedelta(hours=2),
        }

    return jsonify(_cache[audit_id]["result_dict"])


@app.route("/report/<audit_id>/pdf")
def download_pdf(audit_id):
    """Serve the PDF report. In production, gate this behind Gumroad verification."""
    _clean_cache()
    with _cache_lock:
        entry = _cache.get(audit_id)
    if not entry:
        abort(404)
    pdf_path = entry.get("pdf_path")
    if not pdf_path or not Path(pdf_path).exists():
        abort(404)

    filename = f"SellerShield_Report_{entry['result'].url.replace('https://', '').replace('/', '_')}.pdf"
    return send_file(pdf_path, as_attachment=True, download_name=filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
