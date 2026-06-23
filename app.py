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


CONTACT_EMAIL = "jonrcarter22@gmail.com"

_PAGE_STYLE = """
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #0B1120; color: #CBD5E1; min-height: 100vh; }
  nav { display: flex; align-items: center; justify-content: space-between;
        padding: 18px 48px; border-bottom: 1px solid rgba(255,255,255,.08); }
  .logo { font-size: 1.4rem; font-weight: 800; color: #fff; text-decoration: none; }
  .logo span { color: #22C55E; }
  nav a { color: #CBD5E1; text-decoration: none; font-size: .9rem; }
  nav a:hover { color: #fff; }
  .page { max-width: 720px; margin: 0 auto; padding: 56px 24px 80px; }
  h1 { font-size: 2rem; font-weight: 800; color: #fff; margin-bottom: 8px; }
  .meta { color: #64748B; font-size: .85rem; margin-bottom: 40px; }
  h2 { font-size: 1.1rem; font-weight: 700; color: #fff; margin: 32px 0 10px; }
  p { color: #CBD5E1; line-height: 1.7; margin-bottom: 12px; }
  ul { color: #CBD5E1; line-height: 1.8; padding-left: 20px; margin-bottom: 12px; }
  a { color: #22C55E; }
  footer { text-align: center; padding: 32px 24px;
           border-top: 1px solid rgba(255,255,255,.06);
           color: #64748B; font-size: .82rem; }
  footer a { color: #64748B; }
</style>
"""

def _nav():
    return f'<nav><a class="logo" href="/">Seller<span>Shield</span></a><a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></nav>'

def _footer():
    return f'<footer><p>SellerShield &nbsp;·&nbsp; <a href="/privacy">Privacy Policy</a> &nbsp;·&nbsp; <a href="/terms">Terms of Service</a> &nbsp;·&nbsp; <a href="/about">About</a></p><p style="margin-top:8px;">Results are informational only. Always verify against official platform documentation.</p></footer>'


@app.route("/privacy")
def privacy():
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Policy — SellerShield</title>{_PAGE_STYLE}</head>
<body>{_nav()}
<div class="page">
  <h1>Privacy Policy</h1>
  <p class="meta">Last updated: June 2025</p>

  <p>SellerShield ("we", "us", or "our") operates this compliance audit tool. This page explains what information we collect when you use our service and how we handle it.</p>

  <h2>Information We Collect</h2>
  <p>When you run a free audit, we collect:</p>
  <ul>
    <li>The store URL you submit for scanning</li>
    <li>Publicly accessible content from that URL (page text, links, SSL status)</li>
    <li>Your selected marketplace platforms</li>
  </ul>
  <p>We do <strong>not</strong> collect your name, email address, or any personal identifiers unless you contact us directly.</p>

  <h2>How We Use Your Data</h2>
  <p>Your store URL and audit results are held in temporary server memory for up to 2 hours to allow report generation, then permanently deleted. We do not log, store, or analyze URLs beyond this window.</p>

  <h2>Payment Information</h2>
  <p>PDF report purchases are processed entirely by Gumroad. We never receive or store your payment card details. Gumroad's privacy policy governs payment data.</p>

  <h2>Third-Party Services</h2>
  <ul>
    <li><strong>Railway</strong> — cloud hosting provider. Server logs may include IP addresses per Railway's standard infrastructure practices.</li>
    <li><strong>Gumroad</strong> — payment processor for PDF reports.</li>
  </ul>
  <p>We do not sell, rent, or share your data with any other third parties.</p>

  <h2>Cookies</h2>
  <p>This site does not use tracking cookies, analytics cookies, or advertising cookies. No cookie consent is required.</p>

  <h2>Your Rights</h2>
  <p>Because we do not retain personally identifiable information beyond the 2-hour audit cache, there is generally no personal data to retrieve or delete. If you have questions, contact us.</p>

  <h2>Contact</h2>
  <p>For privacy questions: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>
</div>
{_footer()}</body></html>"""


@app.route("/terms")
def terms():
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terms of Service — SellerShield</title>{_PAGE_STYLE}</head>
<body>{_nav()}
<div class="page">
  <h1>Terms of Service</h1>
  <p class="meta">Last updated: June 2025</p>

  <p>By using SellerShield you agree to these terms. Please read them carefully.</p>

  <h2>1. Informational Use Only</h2>
  <p>SellerShield audit results are provided for informational purposes only. They do not constitute legal, compliance, or business advice. Marketplace policies change frequently — always verify findings against each platform's official documentation before taking action.</p>

  <h2>2. No Guarantee of Accuracy</h2>
  <p>We make reasonable efforts to keep our rule database current, but we cannot guarantee that all findings are accurate, complete, or up to date. SellerShield is not liable for any account suspensions, penalties, or losses that arise from relying on our results.</p>

  <h2>3. Acceptable Use</h2>
  <p>You agree not to:</p>
  <ul>
    <li>Use SellerShield to scan URLs you do not own or have permission to audit</li>
    <li>Attempt to scrape, reverse-engineer, or abuse the scanning service</li>
    <li>Submit malicious, illegal, or harmful URLs</li>
  </ul>
  <p>We reserve the right to block access for misuse without notice.</p>

  <h2>4. PDF Reports and Refunds</h2>
  <p>PDF reports are digital goods delivered immediately upon purchase. Because the full report content is revealed at the moment of download, all sales are final. If you experience a technical issue with your download, contact us and we will resolve it promptly.</p>

  <h2>5. Limitation of Liability</h2>
  <p>To the fullest extent permitted by law, SellerShield's total liability for any claim arising from use of this service is limited to the amount you paid for your report (if any). We are not liable for indirect, incidental, or consequential damages.</p>

  <h2>6. Changes to These Terms</h2>
  <p>We may update these terms periodically. Continued use of the service after changes are posted constitutes acceptance of the revised terms.</p>

  <h2>7. Contact</h2>
  <p>Questions about these terms: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>
</div>
{_footer()}</body></html>"""


@app.route("/about")
def about():
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>About — SellerShield</title>{_PAGE_STYLE}</head>
<body>{_nav()}
<div class="page">
  <h1>About SellerShield</h1>

  <p>SellerShield is a free marketplace compliance audit tool for e-commerce store owners. We scan your store against the real published rules used by Amazon, Google, Meta, TikTok Shop, and Walmart — and show you exactly what could get your account flagged or suspended.</p>

  <h2>How It Works</h2>
  <p>Enter your store URL and we'll crawl your public-facing pages, check for SSL, required policy pages, prohibited content patterns, and structured data requirements. You get a compliance score, platform-by-platform breakdown, and your top issues — free.</p>
  <p>Want the full picture? The paid PDF report ($49) includes step-by-step fix instructions for every finding, written for non-technical store owners.</p>

  <h2>Who Built This</h2>
  <p>SellerShield was built by a team of e-commerce operators who got tired of discovering compliance problems the hard way — after getting flagged. We built the tool we wished existed.</p>

  <h2>Contact Us</h2>
  <p>Have a question, found a bug, or want to partner with us?</p>
  <p>Email: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>

  <p style="margin-top: 40px;"><a href="/" style="color: #22C55E; font-weight: 700;">← Run a Free Audit</a></p>
</div>
{_footer()}</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
