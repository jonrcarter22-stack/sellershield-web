"""
SellerShield Web App
--------------------
Flask server that runs compliance audits, serves results via a web UI,
and acts as a Shopify embedded app with OAuth + billing.

Free tier: score, grade, platform breakdown, issue names only
Paid tier: full fix details + PDF download (linked to Gumroad)
"""

import os
import sys
import uuid
import json
import hmac as hmac_lib
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, abort, redirect as flask_redirect
import requests as http_req

# Add engine directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))

from audit_engine import AuditEngine
from report_generator import generate_pdf

app = Flask(__name__)

# In-memory audit cache (results live for 2 hours)
_cache = {}
_cache_lock = threading.Lock()

REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

GUMROAD_URL = "https://carterverse838.gumroad.com/l/pcarai"

PLATFORM_LABELS = {
    "google": "Google Merchant Center",
    "amazon": "Amazon Seller Central",
    "tiktok": "TikTok Shop",
    "meta": "Meta Commerce",
    "walmart": "Walmart Marketplace",
}

# Shopify App Config
SHOPIFY_API_KEY    = os.environ.get("SHOPIFY_API_KEY", "")
SHOPIFY_API_SECRET = os.environ.get("SHOPIFY_API_SECRET", "")
APP_URL            = os.environ.get("APP_URL", "https://getsellershield.app")
SHOPIFY_BILLING_TEST = os.environ.get("SHOPIFY_BILLING_TEST", "true").lower() == "true"
SHOPIFY_SCOPES = (
    "read_products,write_products,read_orders,"
    "read_customers,read_script_tags,write_script_tags"
)

_shop_tokens: dict = {}

CONTACT_EMAIL = "jonrcarter22@gmail.com"

def _verify_shopify_hmac(params: dict) -> bool:
    params = dict(params)
    hmac_value = params.pop("hmac", "")
    sorted_params = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    expected = hmac_lib.new(
        SHOPIFY_API_SECRET.encode(), sorted_params.encode(), hashlib.sha256
    ).hexdigest()
    return hmac_lib.compare_digest(expected, hmac_value)

def _clean_cache():
    now = datetime.utcnow()
    with _cache_lock:
        expired = [k for k, v in _cache.items() if v["expires_at"] < now]
        for k in expired:
            try:
                Path(_cache[k]["pdf_path"]).unlink(missing_ok=True)
            except Exception:
                pass
            del _cache[k]

def _result_to_dict(result, audit_id: str) -> dict:
    platforms = []
    for ps in result.platform_scores:
        findings = []
        for f in ps.findings:
            findings.append({
                "severity": f.severity, "category": f.category,
                "message": f.message, "fix": f.fix,
                "evidence": f.evidence, "rule_id": f.rule_id,
            })
        platforms.append({
            "name": ps.name, "platform": ps.platform,
            "score": ps.score, "grade": ps.grade,
            "passed": ps.passed, "failed": ps.failed, "findings": findings,
        })
    seen, unique_findings = set(), []
    for f in result.all_findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            unique_findings.append({
                "severity": f.severity, "message": f.message,
                "fix": f.fix, "rule_id": f.rule_id,
            })
    return {
        "audit_id": audit_id, "url": result.url,
        "timestamp": result.timestamp[:19].replace("T", " "),
        "overall_score": result.overall_score, "overall_grade": result.overall_grade,
        "ssl_ok": result.ssl_ok, "pages_found": result.pages_found,
        "pages_missing": result.pages_missing, "platforms": platforms,
        "all_findings": unique_findings,
        "suspension_count": len(result.suspension_warnings),
        "crawl_error": result.crawl_error, "gumroad_url": GUMROAD_URL,
    }

# Web Audit Routes

@app.route("/")
def index():
    shop = request.args.get("shop", "")
    if shop:
        return flask_redirect(f"/shopify/dashboard?shop={shop}")
    return render_template("index.html", gumroad_url=GUMROAD_URL)

@app.route("/audit", methods=["POST"])
def run_audit():
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
    pdf_path = str(REPORTS_DIR / f"sellershield_{audit_id}.pdf")
    try:
        generate_pdf(result, pdf_path)
    except Exception:
        pdf_path = None
    with _cache_lock:
        _cache[audit_id] = {
            "result": result, "result_dict": _result_to_dict(result, audit_id),
            "pdf_path": pdf_path, "expires_at": datetime.utcnow() + timedelta(hours=2),
        }
    return jsonify(_cache[audit_id]["result_dict"])

@app.route("/report/<audit_id>/pdf")
def download_pdf(audit_id):
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

# Shopify OAuth Routes

@app.route("/shopify/install")
def shopify_install():
    shop = request.args.get("shop", "").strip()
    if not shop:
        return "Missing shop parameter", 400
    auth_url = (
        f"https://{shop}/admin/oauth/authorize"
        f"?client_id={SHOPIFY_API_KEY}"
        f"&scope={SHOPIFY_SCOPES}"
        f"&redirect_uri={APP_URL}/auth/callback"
    )
    return flask_redirect(auth_url)

@app.route("/auth/callback")
def shopify_callback():
    shop = request.args.get("shop", "")
    code = request.args.get("code", "")
    if not shop or not code:
        return "Invalid OAuth callback", 400
    if not _verify_shopify_hmac(request.args.to_dict()):
        return "HMAC validation failed", 403
    token_resp = http_req.post(
        f"https://{shop}/admin/oauth/access_token",
        json={"client_id": SHOPIFY_API_KEY, "client_secret": SHOPIFY_API_SECRET, "code": code},
        timeout=10,
    )
    if token_resp.status_code != 200:
        return f"Token exchange failed: {token_resp.text}", 500
    access_token = token_resp.json().get("access_token", "")
    _shop_tokens[shop] = access_token
    if not SHOPIFY_BILLING_TEST:
        charge_resp = http_req.post(
            f"https://{shop}/admin/api/2024-01/recurring_application_charges.json",
            headers={"X-Shopify-Access-Token": access_token},
            json={"recurring_application_charge": {
                "name": "SellerShield Monthly", "price": 29.99,
                "return_url": f"{APP_URL}/billing/callback?shop={shop}",
                "test": False, "trial_days": 7,
            }},
            timeout=10,
        )
        if charge_resp.status_code == 201:
            confirmation_url = charge_resp.json().get(
                "recurring_application_charge", {}
            ).get("confirmation_url", "")
            if confirmation_url:
                return flask_redirect(confirmation_url)
    # Redirect directly to dashboard to avoid OAuth loop
    return flask_redirect(f"{APP_URL}/shopify/dashboard?shop={shop}")

@app.route("/billing/callback")
def billing_callback():
    shop = request.args.get("shop", "")
    charge_id = request.args.get("charge_id", "")
    token = _shop_tokens.get(shop, "")
    if not token:
        return flask_redirect(f"/shopify/install?shop={shop}")
    http_req.post(
        f"https://{shop}/admin/api/2024-01/recurring_application_charges/{charge_id}/activate.json",
        headers={"X-Shopify-Access-Token": token},
        json={"recurring_application_charge": {"id": charge_id}},
        timeout=10,
    )
    return flask_redirect(f"{APP_URL}/shopify/dashboard?shop={shop}")

@app.route("/shopify/dashboard")
def shopify_dashboard():
    shop = request.args.get("shop", "").strip()
    if not shop:
        return "Missing shop parameter", 400
    token = _shop_tokens.get(shop, "")
    if not token:
        # No token after server restart - re-run OAuth seamlessly
        return flask_redirect(f"/shopify/install?shop={shop}")
    return render_template(
        "shopify_dashboard.html", shop=shop, app_url=APP_URL, authenticated=True
    )

# Static Pages

_PAGE_STYLE = """
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif;
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
    return f'<footer><p>SellerShield &nbsp; <a href="/privacy">Privacy Policy</a> &nbsp; <a href="/terms">Terms of Service</a> &nbsp; <a href="/about">About</a></p><p style="margin-top:8px;">Results are informational only. Always verify against official platform documentation.</p></footer>'

@app.route("/privacy")
def privacy():
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Policy - SellerShield</title>{_PAGE_STYLE}</head>
<body>{_nav()}
<div class="page">
<h1>Privacy Policy</h1>
<p class="meta">Last updated: June 2025</p>
<p>SellerShield ("we", "us", or "our") operates this compliance audit tool.</p>
<h2>Information We Collect</h2>
<ul>
<li>The store URL you submit for scanning</li>
<li>Publicly accessible content from that URL</li>
<li>Your selected marketplace platforms</li>
</ul>
<p>We do not collect personal identifiers unless you contact us directly.</p>
<h2>How We Use Your Data</h2>
<p>Audit results are held in temporary server memory for up to 2 hours, then permanently deleted.</p>
<h2>Third-Party Services</h2>
<ul>
<li>Railway - cloud hosting provider.</li>
<li>Gumroad - payment processor for PDF reports.</li>
<li>Shopify - marketplace platform for the SellerShield app.</li>
</ul>
<h2>Contact</h2>
<p>For privacy questions: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>
</div>
{_footer()}</body></html>"""

@app.route("/terms")
def terms():
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terms of Service - SellerShield</title>{_PAGE_STYLE}</head>
<body>{_nav()}
<div class="page">
<h1>Terms of Service</h1>
<p class="meta">Last updated: June 2025</p>
<p>By using SellerShield you agree to these terms.</p>
<h2>1. Informational Use Only</h2>
<p>SellerShield audit results are for informational purposes only and do not constitute legal or compliance advice.</p>
<h2>2. No Guarantee of Accuracy</h2>
<p>We cannot guarantee that all findings are accurate, complete, or up to date.</p>
<h2>3. Acceptable Use</h2>
<p>Do not scan URLs you do not own, abuse the scanning service, or submit malicious URLs.</p>
<h2>4. PDF Reports and Refunds</h2>
<p>PDF reports are digital goods. All sales are final.</p>
<h2>5. Limitation of Liability</h2>
<p>SellerShield total liability is limited to the amount you paid (if any).</p>
<h2>6. Contact</h2>
<p>Questions: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>
</div>
{_footer()}</body></html>"""

@app.route("/about")
def about():
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>About - SellerShield</title>{_PAGE_STYLE}</head>
<body>{_nav()}
<div class="page">
<h1>About SellerShield</h1>
<p>SellerShield is a free marketplace compliance audit tool for e-commerce store owners.</p>
<h2>Contact Us</h2>
<p>Email: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>
<p style="margin-top: 40px;"><a href="/" style="color: #22C55E; font-weight: 700;">Run a Free Audit</a></p>
</div>
{_footer()}</body></html>"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
