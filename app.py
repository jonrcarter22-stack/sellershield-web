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
from flask import Flask, render_template, request, jsonify, send_file, abort, redirect as flask_redirect, make_response
import requests as http_req
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None

# Add engine directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))

from audit_engine import AuditEngine
from report_generator import generate_pdf

app = Flask(__name__)
_init_db()

# ── In-memory audit cache (results live for 2 hours) ──────────────────────
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

# ── Shopify App Config ─────────────────────────────────────────────────────
SHOPIFY_API_KEY    = os.environ.get("SHOPIFY_API_KEY", "")
SHOPIFY_API_SECRET = os.environ.get("SHOPIFY_API_SECRET", "")
APP_URL            = os.environ.get("APP_URL", "https://getsellershield.app")
SHOPIFY_BILLING_TEST = os.environ.get("SHOPIFY_BILLING_TEST", "true").lower() == "true"
DATABASE_URL       = os.environ.get("DATABASE_URL", "")
SHOPIFY_SCOPES = (
    "read_products,write_products,read_orders,"
    "read_customers,read_script_tags,write_script_tags"
)

# In-memory fallback (used when no DATABASE_URL is set)
_shop_tokens: dict = {}

CONTACT_EMAIL = "jonrcarter22@gmail.com"


# ── Database helpers ───────────────────────────────────────────────────────

def _db_conn():
    return psycopg2.connect(DATABASE_URL)


def _init_db():
    """Create shop_installs table if it doesn't exist."""
    if not DATABASE_URL or not psycopg2:
        return
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS shop_installs (
                        shop TEXT PRIMARY KEY,
                        access_token TEXT NOT NULL,
                        charge_id BIGINT,
                        charge_status TEXT DEFAULT 'none',
                        installed_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
            conn.commit()
    except Exception as e:
        print(f"[DB] init error: {e}")


def _db_save_token(shop: str, token: str):
    if not DATABASE_URL or not psycopg2:
        _shop_tokens[shop] = token
        return
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO shop_installs (shop, access_token, charge_status, updated_at)
                    VALUES (%s, %s, 'none', NOW())
                    ON CONFLICT (shop) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        charge_status = 'none',
                        updated_at = NOW()
                """, (shop, token))
            conn.commit()
    except Exception as e:
        print(f"[DB] save_token error: {e}")
        _shop_tokens[shop] = token


def _db_get_install(shop: str):
    """Returns (access_token, charge_id, charge_status) or None."""
    if not DATABASE_URL or not psycopg2:
        token = _shop_tokens.get(shop, "")
        # In dev/test mode with no DB, treat any token as active
        return (token, None, "active") if token else None
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT access_token, charge_id, charge_status FROM shop_installs WHERE shop = %s",
                    (shop,)
                )
                return cur.fetchone()
    except Exception as e:
        print(f"[DB] get_install error: {e}")
        return None


def _db_save_charge(shop: str, charge_id, status: str):
    if not DATABASE_URL or not psycopg2:
        return
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE shop_installs
                    SET charge_id = %s, charge_status = %s, updated_at = NOW()
                    WHERE shop = %s
                """, (charge_id, status, shop))
            conn.commit()
    except Exception as e:
        print(f"[DB] save_charge error: {e}")


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


# ── Web Audit Routes ───────────────────────────────────────────────────────

@app.route("/")
def index():
    shop = request.args.get("shop", "")
    host = request.args.get("host", "")
    if shop:
        # Entry point from Shopify admin — forward to embedded dashboard
        return flask_redirect(f"/shopify/dashboard?shop={shop}&host={host}")
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


# ── Shopify OAuth Routes ───────────────────────────────────────────────────

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
    _db_save_token(shop, access_token)
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
    store_name = shop.replace(".myshopify.com", "")
    return flask_redirect(f"https://admin.shopify.com/store/{store_name}/apps/sellershield")


@app.route("/billing/callback")
def billing_callback():
    shop = request.args.get("shop", "")
    charge_id = request.args.get("charge_id", "")
    install = _db_get_install(shop)
    if not install:
        return flask_redirect(f"/shopify/install?shop={shop}")
    token = install[0]
    # Check current charge status from Shopify before activating
    status_resp = http_req.get(
        f"https://{shop}/admin/api/2024-01/recurring_application_charges/{charge_id}.json",
        headers={"X-Shopify-Access-Token": token},
        timeout=10,
    )
    charge_status = "declined"
    if status_resp.status_code == 200:
        charge_status = status_resp.json().get("recurring_application_charge", {}).get("status", "declined")
    if charge_status == "accepted":
        activate_resp = http_req.post(
            f"https://{shop}/admin/api/2024-01/recurring_application_charges/{charge_id}/activate.json",
            headers={"X-Shopify-Access-Token": token},
            json={"recurring_application_charge": {"id": charge_id}},
            timeout=10,
        )
        if activate_resp.status_code == 200:
            charge_status = "active"
    _db_save_charge(shop, charge_id, charge_status)
    store_name = shop.replace(".myshopify.com", "")
    return flask_redirect(f"https://admin.shopify.com/store/{store_name}/apps/sellershield")


@app.route("/shopify/dashboard")
def shopify_dashboard():
    shop = request.args.get("shop", "").strip()
    if not shop:
        return "Missing shop parameter", 400
    host = request.args.get("host", "")
    install = _db_get_install(shop)
    token = install[0] if install else ""
    if not token:
        # No token — use App Bridge to escape the Shopify iframe and trigger OAuth
        install_url = f"{APP_URL}/shopify/install?shop={shop}"
        default_host = f"admin.shopify.com/store/{shop.replace('.myshopify.com', '')}"
        computed_host = host or f"{{btoa_placeholder}}"
        html = f"""<!DOCTYPE html>
<html><head>
<script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       display: flex; align-items: center; justify-content: center;
       min-height: 100vh; background: #f6f6f7; }}
.card {{ background: #fff; border-radius: 12px; padding: 48px 40px;
         text-align: center; max-width: 380px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }}
h2 {{ font-size: 1.25rem; font-weight: 700; color: #1a1a1a; margin-bottom: 10px; }}
p {{ color: #6b7280; font-size: .9rem; margin-bottom: 28px; line-height: 1.5; }}
.btn {{ display: inline-block; padding: 12px 28px; background: #008060;
        color: #fff; border: none; border-radius: 6px; font-size: 15px;
        font-weight: 600; cursor: pointer; text-decoration: none; }}
.btn:hover {{ background: #006a4d; }}
</style>
<script>
(function() {{
    var installUrl = "{install_url}";
    var host = "{host}" || btoa("{default_host}");
    var apiKey = "{SHOPIFY_API_KEY}";

    // Called on button click — user gesture allows top-level navigation
    window.__connectSellerShield = function() {{
        // Method 1: top-level nav (requires user gesture — guaranteed on click)
        try {{ window.top.location.href = installUrl; return; }} catch(e1) {{}}

        // Method 2: App Bridge redirect
        try {{
            var AppBridge = window["app-bridge"];
            if (AppBridge && AppBridge.actions && AppBridge.actions.Redirect) {{
                var createApp = AppBridge.default || AppBridge.createApp;
                var app = createApp({{ apiKey: apiKey, host: host }});
                var rb = AppBridge.actions.Redirect.create(app);
                rb.dispatch(AppBridge.actions.Redirect.Action.REMOTE, installUrl);
                return;
            }}
        }} catch(e2) {{}}

        // Method 3: navigate iframe (Shopify may intercept to top-level)
        window.location.href = installUrl;
    }};

    // Also attempt auto-redirect on load (works if called with user activation context)
    window.addEventListener('load', function() {{
        try {{ window.top.location.href = installUrl; }} catch(e) {{}}
    }});
}})();
</script>
</head>
<body>
<div class="card">
  <h2>Connect SellerShield</h2>
  <p>Click below to authenticate your store and get started with compliance auditing.</p>
  <button class="btn" onclick="window.__connectSellerShield()">Connect SellerShield</button>
</div>
</body></html>"""
        resp = make_response(html)
        resp.headers["Content-Security-Policy"] = (
            "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
        )
        return resp

    # ── Billing gate (skipped in test mode) ───────────────────────────────
    if not SHOPIFY_BILLING_TEST:
        charge_status = install[2] if install else "none"
        if charge_status != "active":
            resubscribe_url = f"{APP_URL}/shopify/install?shop={shop}"
            paywall_html = f"""<!DOCTYPE html>
<html><head>
<script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       display: flex; align-items: center; justify-content: center;
       min-height: 100vh; background: #f6f6f7; }}
.card {{ background: #fff; border-radius: 12px; padding: 48px 40px;
         text-align: center; max-width: 420px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }}
h2 {{ font-size: 1.25rem; font-weight: 700; color: #1a1a1a; margin-bottom: 10px; }}
p {{ color: #6b7280; font-size: .9rem; margin-bottom: 28px; line-height: 1.5; }}
.price {{ font-size: 2rem; font-weight: 800; color: #1a1a1a; margin: 16px 0 4px; }}
.trial {{ color: #008060; font-weight: 600; font-size: .9rem; margin-bottom: 28px; }}
.btn {{ display: inline-block; padding: 12px 28px; background: #008060;
        color: #fff; border: none; border-radius: 6px; font-size: 15px;
        font-weight: 600; cursor: pointer; text-decoration: none; }}
.btn:hover {{ background: #006a4d; }}
</style>
<script>
(function() {{
    var url = "{resubscribe_url}";
    window.__subscribe = function() {{
        try {{ window.top.location.href = url; return; }} catch(e) {{}}
        window.location.href = url;
    }};
}})();
</script>
</head>
<body>
<div class="card">
  <h2>Subscription Required</h2>
  <p>Your SellerShield subscription is not active. Subscribe below to run compliance audits and protect your store.</p>
  <div class="price">$29.99<span style="font-size:1rem;font-weight:400;color:#6b7280">/mo</span></div>
  <div class="trial">7-day free trial included</div>
  <button class="btn" onclick="window.__subscribe()">Start Free Trial</button>
</div>
</body></html>"""
            resp = make_response(paywall_html)
            resp.headers["Content-Security-Policy"] = (
                "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
            )
            return resp

    resp = make_response(render_template(
        "shopify_dashboard.html",
        shop=shop,
        host=host,
        app_url=APP_URL,
        api_key=SHOPIFY_API_KEY,
        authenticated=True,
    ))
    resp.headers["Content-Security-Policy"] = (
        "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
    )
    return resp


# ── Static Pages ───────────────────────────────────────────────────────────

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
<p>SellerShield ("we", "us", or "our") operates this compliance audit tool.</p>
<h2>Information We Collect</h2>
<ul>
<li>The store URL you submit for scanning</li>
<li>Publicly accessible content from that URL</li>
<li>Your selected marketplace platforms</li>
</ul>
<p>We do <strong>not</strong> collect personal identifiers unless you contact us directly.</p>
<h2>How We Use Your Data</h2>
<p>Audit results are held in temporary server memory for up to 2 hours, then permanently deleted.</p>
<h2>Third-Party Services</h2>
<ul>
<li><strong>Railway</strong> — cloud hosting provider.</li>
<li><strong>Gumroad</strong> — payment processor for PDF reports.</li>
<li><strong>Shopify</strong> — marketplace platform for the SellerShield app.</li>
</ul>
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
<p>SellerShield's total liability is limited to the amount you paid (if any).</p>
<h2>6. Contact</h2>
<p>Questions: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>
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
<p>SellerShield is a free marketplace compliance audit tool for e-commerce store owners.</p>
<h2>Contact Us</h2>
<p>Email: <a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a></p>
<p style="margin-top: 40px;"><a href="/" style="color: #22C55E; font-weight: 700;">&#8592; Run a Free Audit</a></p>
</div>
{_footer()}</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
