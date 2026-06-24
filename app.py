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
from functools import wraps
from pathlib import Path
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, abort, redirect as flask_redirect, make_response
import requests as http_req
try:
    import psycopg2
    import psycopg2.extras
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    RealDictCursor = None

# Add engine directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))

from audit_engine import AuditEngine
from report_generator import generate_pdf
try:
    from compliance_scanner import ComplianceScanner
except ImportError:
    ComplianceScanner = None

app = Flask(__name__)

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
    "read_customers,read_script_tags,write_script_tags,"
    "write_pages,read_shipping,write_metafields"
)

# In-memory fallback (used when no DATABASE_URL is set)
_shop_tokens: dict = {}

CONTACT_EMAIL  = "jonrcarter22@gmail.com"
ALERT_EMAIL    = os.environ.get("ALERT_FROM_EMAIL", CONTACT_EMAIL)
SMTP_HOST      = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER      = os.environ.get("SMTP_USER", "")
SMTP_PASS      = os.environ.get("SMTP_PASS", "")

# Shopify billing price map (plan_key → monthly price USD)
_PLAN_PRICES = {
    "free":    0.00,
    "starter": 29.00,
    "growth":  69.00,
    "pro":     99.00,
}


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


# ── Plan Configuration ─────────────────────────────────────────────────────

PLAN_LIMITS = {
    "free": {
        "name": "Free", "price_cents": 0,
        "channels": ["google"], "auto_fix": False, "one_click_fix": False,
        "frequency": "manual", "max_scans_month": 1, "appeal_guidance": False,
    },
    "starter": {
        "name": "Starter", "price_cents": 2900,
        "channels": ["google"], "auto_fix": True, "one_click_fix": False,
        "frequency": "weekly", "max_scans_month": 4, "appeal_guidance": False,
    },
    "growth": {
        "name": "Growth", "price_cents": 6900,
        "channels": ["google", "amazon", "meta"], "auto_fix": True,
        "one_click_fix": True, "frequency": "daily", "max_scans_month": 30,
        "appeal_guidance": False,
    },
    "pro": {
        "name": "Pro", "price_cents": 9900,
        "channels": ["google", "amazon", "meta"], "auto_fix": True,
        "one_click_fix": True, "frequency": "realtime", "max_scans_month": 999,
        "appeal_guidance": True,
    },
}

SHOPIFY_BILLING_PLANS = {
    "starter": {"name": "SellerShield Starter", "price": 29.00, "trial_days": 7},
    "growth":  {"name": "SellerShield Growth",  "price": 69.00, "trial_days": 7},
    "pro":     {"name": "SellerShield Pro",      "price": 99.00, "trial_days": 7},
}


# ── Extended DB Schema ─────────────────────────────────────────────────────

def _init_extended_schema():
    """Create scans, violations, fixes, and shop_plans tables."""
    if not DATABASE_URL or not psycopg2:
        return
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS shop_plans (
                        shop TEXT PRIMARY KEY,
                        plan_name TEXT DEFAULT 'free',
                        charge_id BIGINT,
                        trial_ends_at TIMESTAMPTZ,
                        updated_at TIMESTAMPTZ DEFAULT NOW()
                    );

                    CREATE TABLE IF NOT EXISTS scans (
                        id SERIAL PRIMARY KEY,
                        shop TEXT NOT NULL,
                        status TEXT DEFAULT 'running',
                        overall_score INTEGER,
                        google_score INTEGER,
                        amazon_score INTEGER,
                        meta_score INTEGER,
                        violation_count INTEGER DEFAULT 0,
                        started_at TIMESTAMPTZ DEFAULT NOW(),
                        completed_at TIMESTAMPTZ,
                        error TEXT
                    );
                    CREATE INDEX IF NOT EXISTS scans_shop_idx ON scans(shop);

                    CREATE TABLE IF NOT EXISTS violations (
                        id SERIAL PRIMARY KEY,
                        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                        shop TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        fix_type TEXT NOT NULL DEFAULT 'flagged',
                        fix_details JSONB DEFAULT '{}',
                        status TEXT DEFAULT 'open',
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        resolved_at TIMESTAMPTZ
                    );
                    CREATE INDEX IF NOT EXISTS violations_shop_idx ON violations(shop);

                    CREATE TABLE IF NOT EXISTS fixes (
                        id SERIAL PRIMARY KEY,
                        shop TEXT NOT NULL,
                        violation_id INTEGER REFERENCES violations(id),
                        fix_type TEXT NOT NULL,
                        details JSONB DEFAULT '{}',
                        status TEXT DEFAULT 'applied',
                        applied_at TIMESTAMPTZ DEFAULT NOW(),
                        reverted_at TIMESTAMPTZ,
                        revert_data JSONB DEFAULT '{}'
                    );
                    CREATE INDEX IF NOT EXISTS fixes_shop_idx ON fixes(shop);
                """)
            conn.commit()
    except Exception as e:
        print(f"[DB] extended schema error: {e}")


# ── Extended DB helpers ────────────────────────────────────────────────────

def _db_get_plan(shop: str) -> dict:
    """Returns the plan limits dict for a shop. Defaults to free."""
    plan_name = "free"
    if DATABASE_URL and psycopg2:
        try:
            with _db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT plan_name FROM shop_plans WHERE shop = %s", (shop,)
                    )
                    row = cur.fetchone()
                    if row:
                        plan_name = row[0]
        except Exception as e:
            print(f"[DB] get_plan error: {e}")
    # Also check billing status from shop_installs
    install = _db_get_install(shop)
    if install and install[2] != "active" and not SHOPIFY_BILLING_TEST:
        plan_name = "free"
    return {**PLAN_LIMITS.get(plan_name, PLAN_LIMITS["free"]), "plan_name": plan_name}


def _db_set_plan(shop: str, plan_name: str, charge_id=None):
    if not DATABASE_URL or not psycopg2:
        return
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO shop_plans (shop, plan_name, charge_id, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (shop) DO UPDATE SET
                        plan_name = EXCLUDED.plan_name,
                        charge_id = COALESCE(EXCLUDED.charge_id, shop_plans.charge_id),
                        updated_at = NOW()
                """, (shop, plan_name, charge_id))
            conn.commit()
    except Exception as e:
        print(f"[DB] set_plan error: {e}")


def _db_create_scan(shop: str) -> int:
    if not DATABASE_URL or not psycopg2:
        return -1
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO scans (shop) VALUES (%s) RETURNING id", (shop,)
                )
                scan_id = cur.fetchone()[0]
            conn.commit()
            return scan_id
    except Exception as e:
        print(f"[DB] create_scan error: {e}")
        return -1


def _db_complete_scan(scan_id: int, scores: dict, violation_count: int):
    if not DATABASE_URL or not psycopg2 or scan_id < 0:
        return
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE scans SET
                        status = 'complete',
                        overall_score = %s,
                        google_score = %s,
                        amazon_score = %s,
                        meta_score = %s,
                        violation_count = %s,
                        completed_at = NOW()
                    WHERE id = %s
                """, (
                    scores.get("overall"), scores.get("google"),
                    scores.get("amazon"), scores.get("meta"),
                    violation_count, scan_id
                ))
            conn.commit()
    except Exception as e:
        print(f"[DB] complete_scan error: {e}")


def _db_fail_scan(scan_id: int, error: str):
    if not DATABASE_URL or not psycopg2 or scan_id < 0:
        return
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE scans SET status='failed', error=%s, completed_at=NOW() WHERE id=%s",
                    (error[:500], scan_id)
                )
            conn.commit()
    except Exception as e:
        print(f"[DB] fail_scan error: {e}")


def _db_save_violation(scan_id: int, shop: str, channel: str, rule_id: str,
                       severity: str, title: str, description: str,
                       fix_type: str, fix_details: dict) -> int:
    if not DATABASE_URL or not psycopg2:
        return -1
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO violations
                        (scan_id, shop, channel, rule_id, severity, title,
                         description, fix_type, fix_details)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                """, (scan_id, shop, channel, rule_id, severity, title,
                      description, fix_type, json.dumps(fix_details)))
                vid = cur.fetchone()[0]
            conn.commit()
            return vid
    except Exception as e:
        print(f"[DB] save_violation error: {e}")
        return -1


def _db_get_violations(shop: str, channel: str = None, status: str = "open") -> list:
    if not DATABASE_URL or not psycopg2:
        return []
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if channel:
                    cur.execute("""
                        SELECT v.*, s.started_at as scan_time
                        FROM violations v JOIN scans s ON v.scan_id = s.id
                        WHERE v.shop=%s AND v.channel=%s AND v.status=%s
                        ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, v.id DESC
                    """, (shop, channel, status))
                else:
                    cur.execute("""
                        SELECT v.*, s.started_at as scan_time
                        FROM violations v JOIN scans s ON v.scan_id = s.id
                        WHERE v.shop=%s AND v.status=%s
                        ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, v.id DESC
                    """, (shop, status))
                rows = cur.fetchall()
                return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] get_violations error: {e}")
        return []


def _db_get_latest_scan(shop: str) -> dict:
    if not DATABASE_URL or not psycopg2:
        return {}
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM scans WHERE shop=%s
                    ORDER BY started_at DESC LIMIT 1
                """, (shop,))
                row = cur.fetchone()
                return dict(row) if row else {}
    except Exception as e:
        print(f"[DB] get_latest_scan error: {e}")
        return {}


def _db_save_fix(shop: str, violation_id: int, fix_type: str,
                 details: dict, revert_data: dict) -> int:
    if not DATABASE_URL or not psycopg2:
        return -1
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO fixes (shop, violation_id, fix_type, details, revert_data, status, applied_at)
                    VALUES (%s,%s,%s,%s,%s,'applied',NOW())
                    RETURNING id
                """, (shop, violation_id, fix_type, json.dumps(details), json.dumps(revert_data)))
                fix_id = cur.fetchone()[0]
                # Mark violation resolved
                cur.execute(
                    "UPDATE violations SET status='resolved', resolved_at=NOW() WHERE id=%s",
                    (violation_id,)
                )
            conn.commit()
            return fix_id
    except Exception as e:
        print(f"[DB] save_fix error: {e}")
        return -1


def _db_revert_fix(fix_id: int) -> dict:
    if not DATABASE_URL or not psycopg2:
        return {}
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM fixes WHERE id=%s", (fix_id,))
                fix = cur.fetchone()
                if not fix or fix["status"] != "applied":
                    return {}
                revert_data = fix["revert_data"] or {}
                cur.execute(
                    "UPDATE fixes SET status='reverted', reverted_at=NOW() WHERE id=%s",
                    (fix_id,)
                )
                cur.execute(
                    "UPDATE violations SET status='open', resolved_at=NULL WHERE id=%s",
                    (fix["violation_id"],)
                )
            conn.commit()
            return dict(fix)
    except Exception as e:
        print(f"[DB] revert_fix error: {e}")
        return {}


def _db_get_fix_history(shop: str, limit: int = 50) -> list:
    if not DATABASE_URL or not psycopg2:
        return []
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT f.*, v.title as violation_title, v.channel, v.severity
                    FROM fixes f
                    LEFT JOIN violations v ON f.violation_id = v.id
                    WHERE f.shop=%s
                    ORDER BY f.applied_at DESC
                    LIMIT %s
                """, (shop, limit))
                return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        print(f"[DB] get_fix_history error: {e}")
        return []


# ── API Auth Decorator ─────────────────────────────────────────────────────

def require_api_auth(f):
    """Verify the requesting shop has a valid install."""
    @wraps(f)
    def decorated(*args, **kwargs):
        shop = (
            request.headers.get("X-Shopify-Shop-Domain")
            or request.args.get("shop", "")
            or (request.get_json(silent=True) or {}).get("shop", "")
        )
        if not shop:
            return jsonify({"error": "Missing shop domain"}), 401
        install = _db_get_install(shop)
        if not install or not install[0]:
            return jsonify({"error": "Shop not authenticated"}), 401
        request.shop = shop
        request.shop_token = install[0]
        request.plan = _db_get_plan(shop)
        return f(*args, **kwargs)
    return decorated


# ── Scan Engine (maps audit results → DB violations) ──────────────────────

_PLATFORM_TO_CHANNEL = {
    "google": "google", "amazon": "amazon",
    "meta": "meta", "tiktok": "meta", "walmart": "amazon",
}

_FIX_TYPE_MAP = {
    # rule_id prefixes → fix_type
    "POL-": "auto",   # Policy pages → fully automatic
    "CON-": "auto",   # Contact info → fully automatic
    "PRD-": "one_click",  # Product feed → one-click with preview
    "GTN-": "guided", # GTIN issues → guided
    "APP-": "flagged", # App conflicts → flagged only
    "REP-": "flagged", # Reputation → flagged only
}

def _resolve_fix_type(rule_id: str) -> str:
    for prefix, fix_type in _FIX_TYPE_MAP.items():
        if rule_id.startswith(prefix):
            return fix_type
    return "flagged"


def _run_scan_for_shop(shop: str, url: str, scan_id: int, plan: dict):
    """Run compliance scan and store results. Called in a background thread."""
    try:
        channels = plan.get("channels", ["google"])
        install  = _db_get_install(shop)
        token    = install[0] if install else None

        violations = []

        # ── Phase 3: Channel-specific compliance scanner (Shopify API-based) ──
        if token and ComplianceScanner:
            scanner = ComplianceScanner(shop, token)
            violations = scanner.run(channels=channels)

        # ── Fallback: URL-based AuditEngine (20s hard timeout) ──────────────
        if url:
            _audit_result = [None]
            def _run_audit():
                try:
                    engine = AuditEngine(timeout=10)
                    _audit_result[0] = engine.audit(url, channels)
                except Exception as e:
                    print(f"[scan] AuditEngine error: {e}")
            _audit_thread = threading.Thread(target=_run_audit, daemon=True)
            _audit_thread.start()
            _audit_thread.join(timeout=20)  # Hard cap at 20 seconds
            if _audit_result[0] is not None:
                result = _audit_result[0]
                seen_rules = {v["rule_id"] for v in violations}
                for f in result.all_findings:
                    if f.rule_id not in seen_rules:
                        seen_rules.add(f.rule_id)
                        ch = _PLATFORM_TO_CHANNEL.get(
                            next((ps.platform for ps in result.platform_scores
                                  if any(ff.rule_id == f.rule_id for ff in ps.findings)), "google"),
                            "google"
                        )
                        violations.append({
                            "rule_id":     f.rule_id,
                            "channel":     ch,
                            "severity":    f.severity.lower(),
                            "title":       f.message,
                            "description": f.fix or "",
                            "fix_type":    _resolve_fix_type(f.rule_id),
                            "fix_details": {"fix_text": f.fix or ""},
                        })
            else:
                print("[scan] AuditEngine timed out — using ComplianceScanner results only")

        # ── Compute per-channel scores ────────────────────────────────────────
        channel_counts = {}
        for v in violations:
            ch = v.get("channel", "google")
            channel_counts.setdefault(ch, {"critical": 0, "high": 0, "medium": 0, "low": 0})
            sev = v.get("severity", "low")
            if sev in channel_counts[ch]:
                channel_counts[ch][sev] += 1

        def _score_from_counts(counts):
            deductions = counts.get("critical", 0) * 20 + counts.get("high", 0) * 10 + \
                         counts.get("medium", 0) * 5  + counts.get("low", 0) * 2
            return max(0, 100 - deductions)

        scores = {"overall": None, "google": None, "amazon": None, "meta": None}
        for ch, counts in channel_counts.items():
            if ch in scores:
                scores[ch] = _score_from_counts(counts)
        active_scores = [s for s in [scores["google"], scores["amazon"], scores["meta"]] if s is not None]
        scores["overall"] = int(sum(active_scores) / len(active_scores)) if active_scores else 100

        # ── Save violations to DB ─────────────────────────────────────────────
        vcount = 0
        for v in violations:
            _db_save_violation(
                scan_id=scan_id, shop=shop,
                channel=v.get("channel", "google"),
                rule_id=v["rule_id"],
                severity=v.get("severity", "medium"),
                title=v.get("title", v["rule_id"]),
                description=v.get("description", ""),
                fix_type=v.get("fix_type", "guided"),
                fix_details=v.get("fix_details", {}),
            )
            vcount += 1

        _db_complete_scan(scan_id, scores, vcount)
    except Exception as e:
        print(f"[scan] _run_scan_for_shop error: {e}")
        _db_fail_scan(scan_id, str(e))


# ── Shopify Admin API helpers ─────────────────────────────────────────────

def _shopify_api(shop: str, token: str, method: str, path: str, body=None):
    """Make a call to the Shopify Admin API."""
    url = f"https://{shop}/admin/api/2024-01/{path}"
    headers = {"X-Shopify-Access-Token": token, "Content-Type": "application/json"}
    resp = getattr(http_req, method)(url, headers=headers, json=body, timeout=15)
    return resp


def _get_shop_info(shop: str, token: str) -> dict:
    resp = _shopify_api(shop, token, "get", "shop.json")
    if resp.status_code == 200:
        return resp.json().get("shop", {})
    return {}


def _get_shop_pages(shop: str, token: str) -> list:
    resp = _shopify_api(shop, token, "get", "pages.json?limit=250")
    if resp.status_code == 200:
        return resp.json().get("pages", [])
    return []


def _create_shop_page(shop: str, token: str, title: str, body_html: str) -> dict:
    resp = _shopify_api(shop, token, "post", "pages.json",
                        body={"page": {"title": title, "body_html": body_html, "published": True}})
    if resp.status_code == 201:
        return resp.json().get("page", {})
    return {}


def _update_shop_page(shop: str, token: str, page_id: int, body_html: str) -> dict:
    resp = _shopify_api(shop, token, "put", f"pages/{page_id}.json",
                        body={"page": {"id": page_id, "body_html": body_html}})
    if resp.status_code == 200:
        return resp.json().get("page", {})
    return {}


# ── Policy Page Auto-Fix ───────────────────────────────────────────────────

_POLICY_TEMPLATES = {
    "privacy": {
        "title": "Privacy Policy",
        "handle": "privacy-policy",
        "body": lambda info: f"""<h2>Privacy Policy</h2>
<p>Last updated: {datetime.utcnow().strftime('%B %d, %Y')}</p>
<p>{info.get('name', 'Our store')} ("we", "us", or "our") is committed to protecting your privacy.</p>
<h3>Information We Collect</h3>
<p>We collect information you provide when placing orders, including your name, email, shipping address, and payment information.</p>
<h3>How We Use Your Information</h3>
<p>We use your information to process orders, send order confirmations, and provide customer support.</p>
<h3>Data Sharing</h3>
<p>We do not sell your personal information. We share data only with service providers needed to fulfill your orders.</p>
<h3>Your Rights</h3>
<p>You may request access to, correction of, or deletion of your personal data by contacting us at {info.get('email', 'support@' + info.get('domain', 'ourstore.com'))}.</p>
<h3>Contact</h3>
<p>Email: {info.get('email', '')}<br>Phone: {info.get('phone', '')}<br>Address: {info.get('address1', '')}, {info.get('city', '')}</p>""",
    },
    "refund": {
        "title": "Refund Policy",
        "handle": "refund-policy",
        "body": lambda info: f"""<h2>Refund Policy</h2>
<p>We offer a 30-day return policy. Items must be unused and in original packaging.</p>
<h3>How to Return</h3>
<p>Contact us at {info.get('email', '')} within 30 days of delivery to initiate a return.</p>
<h3>Refund Process</h3>
<p>Once we receive and inspect your return, we will notify you of the refund approval. Approved refunds are processed within 5-10 business days.</p>
<h3>Exchanges</h3>
<p>We replace items that are defective or damaged. Contact us to arrange an exchange.</p>""",
    },
    "shipping": {
        "title": "Shipping Policy",
        "handle": "shipping-policy",
        "body": lambda info: f"""<h2>Shipping Policy</h2>
<p>We ship to all addresses within the United States. International shipping is available for select countries.</p>
<h3>Processing Time</h3>
<p>Orders are processed within 1-3 business days.</p>
<h3>Shipping Times</h3>
<p>Standard shipping: 5-7 business days<br>Expedited shipping: 2-3 business days</p>
<h3>Tracking</h3>
<p>A tracking number will be emailed to you once your order ships. Contact us at {info.get('email', '')} with any shipping questions.</p>""",
    },
    "terms": {
        "title": "Terms of Service",
        "handle": "terms-of-service",
        "body": lambda info: f"""<h2>Terms of Service</h2>
<p>By using {info.get('name', 'our store')} you agree to these terms.</p>
<h3>Products</h3>
<p>We reserve the right to refuse service or limit quantities at our discretion.</p>
<h3>Accuracy of Information</h3>
<p>We strive for accuracy in product descriptions and pricing. Errors will be corrected when discovered.</p>
<h3>Limitation of Liability</h3>
<p>Our liability is limited to the amount paid for the product in question.</p>
<h3>Contact</h3>
<p>{info.get('name', '')}<br>{info.get('email', '')}</p>""",
    },
}

_POLICY_RULE_MAP = {
    # rule_id → policy template key (auto-creatable pages)
    "POL-001": "privacy", "POL-002": "refund",
    "POL-003": "shipping", "POL-004": "terms",
    # Amazon / Meta policy rules map to same templates
    "AMZ-005": "refund",
    "MET-005": "privacy",
}

# Deep-link templates for guided fixes (Shopify Admin URLs)
_GUIDED_DEEP_LINKS = {
    "PRD-001": lambda shop: f"https://{shop}/admin/products",
    "PRD-002": lambda shop: f"https://{shop}/admin/products",
    "PRD-003": lambda shop: f"https://{shop}/admin/products",
    "PRD-004": lambda shop: f"https://{shop}/admin/products",
    "PRD-005": lambda shop: f"https://{shop}/admin/products",
    "AMZ-001": lambda shop: f"https://{shop}/admin/products",
    "AMZ-002": lambda shop: f"https://{shop}/admin/products",
    "AMZ-003": lambda shop: f"https://{shop}/admin/products",
    "AMZ-004": lambda shop: f"https://{shop}/admin/products",
    "MET-001": lambda shop: f"https://{shop}/admin/products",
    "MET-002": lambda shop: f"https://facebook.com/policies/commerce/",
    "MET-003": lambda shop: f"https://{shop}/admin/products",
    "MET-004": lambda shop: f"https://{shop}/admin/products",
    "CON-001": lambda shop: f"https://{shop}/admin/settings/general",
    "CON-002": lambda shop: f"https://{shop}/admin/settings/general",
}

# One-click fix handlers: rule_id → function(shop, token, violation) → dict
def _one_click_add_description(shop: str, token: str, v: dict) -> dict:
    """Add a placeholder description to products that are missing one."""
    fix_details = v.get("fix_details") or {}
    affected    = fix_details.get("affected_titles", [])
    if not affected:
        return {"success": False, "error": "No affected products identified"}

    # Fetch products and update those with thin descriptions
    updated, errors = 0, []
    try:
        resp = _shopify_api(shop, token, "get", "products.json?limit=250&status=active")
        if resp.status_code != 200:
            return {"success": False, "error": "Could not fetch products"}
        products = resp.json().get("products", [])
        for p in products:
            import re
            plain = re.sub(r"<[^>]+>", " ", p.get("body_html", "") or "").strip()
            if len(plain.split()) < 20 and p["title"] in affected:
                # Build a minimal description from available product data
                vendor = p.get("vendor", "")
                ptype  = p.get("product_type", "")
                tags   = p.get("tags", "")
                stub   = (
                    f"<p>{p['title']} by {vendor}. " if vendor else f"<p>{p['title']}. "
                ) + (
                    f"Category: {ptype}. " if ptype else ""
                ) + (
                    f"Tags: {tags}.</p>" if tags else "</p>"
                ) + (
                    "<p>Please contact us for more details about this product.</p>"
                )
                old_body = p.get("body_html", "")
                upd = _shopify_api(shop, token, "put", f"products/{p['id']}.json",
                                   body={"product": {"id": p["id"], "body_html": stub}})
                if upd.status_code == 200:
                    updated += 1
                    _db_save_fix(shop, v["id"], "one_click",
                                 {"product_id": p["id"], "action": "added_description"},
                                 {"product_id": p["id"], "old_body": old_body})
                else:
                    errors.append(p["title"])
    except Exception as e:
        return {"success": False, "error": str(e)}

    if updated:
        return {"success": True, "updated": updated,
                "message": f"Added placeholder descriptions to {updated} product(s). Edit them in Shopify Admin for best results."}
    return {"success": False, "error": f"No products updated. Errors: {errors[:3]}"}


def _auto_fix_policy_page(shop: str, token: str, violation_id: int, rule_id: str) -> dict:
    """Generate and create/update a missing policy page via Shopify API."""
    policy_key = _POLICY_RULE_MAP.get(rule_id)
    if not policy_key or policy_key not in _POLICY_TEMPLATES:
        return {"success": False, "error": "Unknown policy rule"}

    tmpl = _POLICY_TEMPLATES[policy_key]
    shop_info = _get_shop_info(shop, token)
    body_html = tmpl["body"](shop_info)

    # Check if page already exists
    pages = _get_shop_pages(shop, token)
    existing = next((p for p in pages if p.get("handle") == tmpl["handle"]), None)

    if existing:
        revert_data = {"page_id": existing["id"], "old_body": existing.get("body_html", "")}
        updated = _update_shop_page(shop, token, existing["id"], body_html)
        if updated:
            _db_save_fix(shop, violation_id, "auto",
                         {"policy": policy_key, "page_id": existing["id"], "action": "updated"},
                         revert_data)
            return {"success": True, "action": "updated", "page_id": existing["id"],
                    "title": tmpl["title"]}
    else:
        created = _create_shop_page(shop, token, tmpl["title"], body_html)
        if created:
            _db_save_fix(shop, violation_id, "auto",
                         {"policy": policy_key, "page_id": created["id"], "action": "created"},
                         {"page_id": created["id"], "created": True})
            return {"success": True, "action": "created", "page_id": created.get("id"),
                    "title": tmpl["title"]}

    return {"success": False, "error": "Shopify API error"}


# ── API Routes ─────────────────────────────────────────────────────────────

@app.route("/api/dashboard")
@require_api_auth
def api_dashboard():
    shop = request.shop
    plan = request.plan
    scan = _db_get_latest_scan(shop)
    violations = _db_get_violations(shop)

    critical = sum(1 for v in violations if v["severity"] == "critical")
    warnings = sum(1 for v in violations if v["severity"] == "warning")
    infos    = sum(1 for v in violations if v["severity"] == "info")

    # Compute next scan time based on plan
    next_scan = None
    if scan.get("completed_at"):
        freq = plan.get("frequency", "manual")
        if freq == "weekly":
            next_scan = (scan["completed_at"] + timedelta(days=7)).isoformat()
        elif freq == "daily":
            next_scan = (scan["completed_at"] + timedelta(days=1)).isoformat()
        elif freq == "realtime":
            next_scan = "Continuous"

    return jsonify({
        "shop": shop,
        "plan": plan,
        "scan": {
            "id": scan.get("id"),
            "status": scan.get("status"),
            "overall_score": scan.get("overall_score"),
            "google_score": scan.get("google_score"),
            "amazon_score": scan.get("amazon_score"),
            "meta_score": scan.get("meta_score"),
            "violation_count": scan.get("violation_count", 0),
            "last_scanned": scan.get("completed_at", {}).isoformat() if scan.get("completed_at") else None,
            "next_scan": next_scan,
        },
        "summary": {"critical": critical, "warning": warnings, "info": infos},
        "channels_available": plan.get("channels", ["google"]),
        "all_channels": ["google", "amazon", "meta"],
    })


@app.route("/api/scan", methods=["POST"])
@require_api_auth
def api_trigger_scan():
    shop = request.shop
    token = request.shop_token
    plan = request.plan
    data = request.get_json(silent=True) or {}
    store_url = data.get("url", "").strip()

    if not store_url:
        # Try to get URL from Shopify
        shop_info = _get_shop_info(shop, token)
        store_url = f"https://{shop_info.get('domain', shop)}"

    scan_id = _db_create_scan(shop)
    # Run in background thread so we can respond immediately
    t = threading.Thread(
        target=_run_scan_for_shop,
        args=(shop, store_url, scan_id, plan),
        daemon=True
    )
    t.start()

    return jsonify({"scan_id": scan_id, "status": "running", "shop": shop})


@app.route("/api/scan/<int:scan_id>/status")
@require_api_auth
def api_scan_status(scan_id):
    if not DATABASE_URL or not psycopg2:
        return jsonify({"status": "unknown"})
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM scans WHERE id=%s AND shop=%s",
                            (scan_id, request.shop))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "Not found"}), 404
                return jsonify(dict(row))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/violations")
@require_api_auth
def api_violations():
    shop = request.shop
    plan = request.plan
    channel = request.args.get("channel")
    status = request.args.get("status", "open")

    violations = _db_get_violations(shop, channel=channel, status=status)

    # Gate: hide full details for channels not on plan
    allowed_channels = set(plan.get("channels", ["google"]))
    result = []
    for v in violations:
        v_out = dict(v)
        if v["channel"] not in allowed_channels:
            v_out["_locked"] = True
            v_out["description"] = None
            v_out["fix_details"] = {}
        # Gate fix buttons based on plan
        if not plan.get("auto_fix") and v["fix_type"] == "auto":
            v_out["fix_type"] = "locked"
        if not plan.get("one_click_fix") and v["fix_type"] == "one_click":
            v_out["fix_type"] = "locked"
        # Serialize datetime fields
        for k in ("created_at", "resolved_at", "scan_time"):
            if v_out.get(k) and hasattr(v_out[k], "isoformat"):
                v_out[k] = v_out[k].isoformat()
        result.append(v_out)

    return jsonify({"violations": result, "total": len(result)})


@app.route("/api/fix/<int:violation_id>", methods=["POST"])
@require_api_auth
def api_apply_fix(violation_id):
    shop = request.shop
    token = request.shop_token
    plan = request.plan

    # Fetch violation
    if not DATABASE_URL or not psycopg2:
        return jsonify({"error": "Database required"}), 503
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM violations WHERE id=%s AND shop=%s", (violation_id, shop)
                )
                v = cur.fetchone()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if not v:
        return jsonify({"error": "Violation not found"}), 404
    if v["status"] == "resolved":
        return jsonify({"error": "Already resolved"}), 400

    v = dict(v)
    fix_type = v["fix_type"]

    # Check plan gating
    if fix_type == "auto" and not plan.get("auto_fix"):
        return jsonify({"error": "Upgrade to Starter or higher to use auto-fix", "upgrade": True}), 403
    if fix_type == "one_click" and not plan.get("one_click_fix"):
        return jsonify({"error": "Upgrade to Growth or higher for one-click fixes", "upgrade": True}), 403

    rule_id     = v["rule_id"]
    fix_details = v.get("fix_details") or {}

    # ── Auto fix ──────────────────────────────────────────────────────────
    if fix_type == "auto":
        if rule_id in _POLICY_RULE_MAP:
            result = _auto_fix_policy_page(shop, token, violation_id, rule_id)
            return jsonify(result)
        return jsonify({"error": f"No auto-fix handler for {rule_id}"}), 400

    # ── One-click fix ─────────────────────────────────────────────────────
    elif fix_type == "one_click":
        _one_click_handlers = {
            "PRD-001": _one_click_add_description,
        }
        handler = _one_click_handlers.get(rule_id)
        if handler:
            result = handler(shop, token, v)
            return jsonify(result)
        # Fallback: treat as guided
        deep_link = _GUIDED_DEEP_LINKS.get(rule_id, lambda s: f"https://{s}/admin")(shop)
        return jsonify({
            "success": False,
            "pending": True,
            "instructions": fix_details.get("instructions", "Follow the steps in Shopify Admin."),
            "deep_link": deep_link,
            "rule_id": rule_id,
        })

    # ── Guided fix ────────────────────────────────────────────────────────
    elif fix_type == "guided":
        deep_link = _GUIDED_DEEP_LINKS.get(rule_id, lambda s: f"https://{s}/admin")(shop)
        store_name = shop.replace(".myshopify.com", "")
        # Build embedded admin deep link (works inside Shopify iframe)
        embedded_link = f"https://admin.shopify.com/store/{store_name}" + \
                        deep_link.split("/admin")[-1] if "/admin" in deep_link else deep_link
        return jsonify({
            "success": False,
            "pending": True,
            "instructions": fix_details.get("instructions", "Manual action required."),
            "deep_link": embedded_link,
            "rule_id": rule_id,
            "affected": fix_details.get("affected_titles", []),
        })

    # ── Flagged (manual review only) ──────────────────────────────────────
    elif fix_type == "flagged":
        policy_url = fix_details.get("policy_url", "")
        return jsonify({
            "success": False,
            "pending": True,
            "instructions": fix_details.get("instructions", "This issue requires manual review."),
            "policy_url": policy_url,
            "rule_id": rule_id,
            "requires_manual_review": True,
        })

    return jsonify({"error": "Fix type not supported", "fix_type": fix_type}), 400


@app.route("/api/fix/<int:fix_id>/revert", methods=["POST"])
@require_api_auth
def api_revert_fix(fix_id):
    shop = request.shop
    token = request.shop_token

    fix = _db_revert_fix(fix_id)
    if not fix:
        return jsonify({"error": "Fix not found or already reverted"}), 404

    revert_data = fix.get("revert_data") or {}

    # Handle policy page revert
    if fix.get("fix_type") == "auto":
        page_id = revert_data.get("page_id")
        if page_id and revert_data.get("created"):
            # Delete the page we created
            _shopify_api(shop, token, "delete", f"pages/{page_id}.json")
        elif page_id and revert_data.get("old_body") is not None:
            # Restore original content
            _update_shop_page(shop, token, page_id, revert_data["old_body"])

    return jsonify({"success": True, "fix_id": fix_id})


@app.route("/api/history")
@require_api_auth
def api_fix_history():
    shop = request.shop
    history = _db_get_fix_history(shop)
    for item in history:
        for k in ("applied_at", "reverted_at"):
            if item.get(k) and hasattr(item[k], "isoformat"):
                item[k] = item[k].isoformat()
    return jsonify({"history": history})


@app.route("/api/plan")
@require_api_auth
def api_plan():
    return jsonify({"plan": request.plan, "all_plans": PLAN_LIMITS})


@app.route("/api/plan/upgrade", methods=["POST"])
@require_api_auth
def api_plan_upgrade():
    """Initiate a Shopify billing charge for a plan upgrade."""
    shop  = request.shop
    token = request.shop_token
    data  = request.get_json(silent=True) or {}
    new_plan_key = data.get("plan", "").lower()

    if new_plan_key not in PLAN_LIMITS:
        return jsonify({"error": f"Unknown plan: {new_plan_key}"}), 400

    price = _PLAN_PRICES.get(new_plan_key, 0)

    # Free plan — just update the DB, no charge
    if price == 0:
        _db_set_plan(shop, new_plan_key)
        return jsonify({"success": True, "plan": new_plan_key})

    plan_info = PLAN_LIMITS[new_plan_key]
    charge_body = {
        "recurring_application_charge": {
            "name":       f"SellerShield {plan_info['name']}",
            "price":      price,
            "return_url": f"{APP_URL}/billing/callback?shop={shop}&plan={new_plan_key}",
            "test":       SHOPIFY_BILLING_TEST,
            "trial_days": 7,
        }
    }
    resp = http_req.post(
        f"https://{shop}/admin/api/2024-01/recurring_application_charges.json",
        headers={"X-Shopify-Access-Token": token},
        json=charge_body, timeout=10,
    )
    if resp.status_code == 201:
        confirmation_url = resp.json().get(
            "recurring_application_charge", {}
        ).get("confirmation_url", "")
        return jsonify({"confirmation_url": confirmation_url})

    return jsonify({"error": f"Billing API error: {resp.text[:200]}"}), 500


@app.route("/shopify/plans")
def shopify_plans():
    shop = request.args.get("shop", "").strip()
    host = request.args.get("host", "")
    if not shop:
        return "Missing shop parameter", 400
    install = _db_get_install(shop)
    current_plan = _db_get_plan(shop)
    resp = make_response(render_template(
        "shopify_plans.html",
        shop=shop, host=host, app_url=APP_URL,
        api_key=SHOPIFY_API_KEY,
        current_plan_key=current_plan.get("key", "free"),
        contact_email=CONTACT_EMAIL,
    ))
    resp.headers["Content-Security-Policy"] = (
        "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
    )
    return resp


# ── Email alert helpers ────────────────────────────────────────────────────

def _send_alert_email(to_email: str, subject: str, body_html: str):
    """Send an HTML email via SMTP. Silently no-ops if SMTP not configured."""
    if not SMTP_USER or not SMTP_PASS:
        print(f"[email] SMTP not configured; skipping alert to {to_email}")
        return
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"SellerShield <{ALERT_EMAIL}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(body_html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(ALERT_EMAIL, [to_email], msg.as_string())
        print(f"[email] Alert sent to {to_email}: {subject}")
    except Exception as e:
        print(f"[email] Send error: {e}")


def _build_alert_email(shop: str, violations: list, score: int) -> str:
    rows = ""
    for v in violations[:10]:
        sev   = v.get("severity", "")
        color = {"critical": "#d72c0d", "high": "#e08600"}.get(sev, "#6d7175")
        rows += (
            f'<tr><td style="padding:8px 12px;border-bottom:1px solid #eee">'
            f'<span style="color:{color};font-weight:700">{sev.upper()}</span></td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #eee">'
            f'{v.get("title","")}</td></tr>'
        )
    store_name = shop.replace(".myshopify.com", "")
    dashboard_url = f"{APP_URL}/shopify/dashboard?shop={shop}"
    return f"""
<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto">
  <div style="background:#008060;padding:24px 32px;border-radius:8px 8px 0 0">
    <h1 style="color:#fff;margin:0;font-size:20px">SellerShield Compliance Alert</h1>
    <p style="color:rgba(255,255,255,.8);margin:4px 0 0;font-size:14px">{shop}</p>
  </div>
  <div style="background:#fff;padding:24px 32px;border:1px solid #e1e3e5;border-top:none">
    <p style="font-size:15px">Your latest compliance scan found <strong>{len(violations)} violation(s)</strong>
    with an overall score of <strong>{score}/100</strong>.</p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0">
      <thead><tr>
        <th style="text-align:left;padding:8px 12px;background:#f6f6f7;font-size:12px">SEVERITY</th>
        <th style="text-align:left;padding:8px 12px;background:#f6f6f7;font-size:12px">ISSUE</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    {'<p style="color:#6d7175;font-size:13px">+ ' + str(len(violations)-10) + ' more violations…</p>' if len(violations) > 10 else ''}
    <a href="{dashboard_url}" style="display:inline-block;background:#008060;color:#fff;padding:12px 24px;
       border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;margin-top:8px">
      View &amp; Fix Violations →
    </a>
  </div>
  <p style="text-align:center;color:#6d7175;font-size:12px;padding:16px">
    You're receiving this because your SellerShield plan includes email alerts.<br>
    <a href="{APP_URL}/shopify/plans?shop={shop}" style="color:#6d7175">Manage plan</a>
  </p>
</div>"""


# ── Scheduled scan engine ──────────────────────────────────────────────────

def _scheduler_loop():
    """Background thread: auto-scan shops based on their plan frequency."""
    import time as _time
    print("[scheduler] Started")
    while True:
        try:
            _run_scheduled_scans()
        except Exception as e:
            print(f"[scheduler] Error: {e}")
        _time.sleep(3600)  # Check every hour


def _run_scheduled_scans():
    if not DATABASE_URL or not psycopg2:
        return
    try:
        with _db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Find shops due for a scheduled scan
                cur.execute("""
                    SELECT sp.shop, sp.plan_key,
                           s.completed_at as last_scan,
                           i.token
                    FROM shop_plans sp
                    JOIN installs i ON sp.shop = i.shop
                    LEFT JOIN LATERAL (
                        SELECT completed_at FROM scans
                        WHERE shop = sp.shop AND status = 'done'
                        ORDER BY completed_at DESC LIMIT 1
                    ) s ON true
                    WHERE sp.plan_key != 'free'
                """)
                rows = cur.fetchall()
    except Exception as e:
        print(f"[scheduler] DB error: {e}")
        return

    from datetime import timezone
    now = datetime.now(timezone.utc)

    freq_hours = {"starter": 168, "growth": 24, "pro": 1}  # weekly, daily, hourly

    for row in rows:
        shop     = row["shop"]
        plan_key = row["plan_key"]
        token    = row["token"]
        last     = row["last_scan"]
        hours    = freq_hours.get(plan_key, 168)

        if last:
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            elapsed = (now - last).total_seconds() / 3600
            if elapsed < hours:
                continue  # Not due yet

        print(f"[scheduler] Triggering scan for {shop} (plan={plan_key})")
        try:
            plan  = PLAN_LIMITS.get(plan_key, PLAN_LIMITS["free"])
            info  = _get_shop_info(shop, token)
            url   = f"https://{info.get('domain', shop)}"
            scan_id = _db_create_scan(shop)
            t = threading.Thread(
                target=_run_scan_for_shop,
                args=(shop, url, scan_id, plan),
                daemon=True
            )
            t.start()
            t.join(timeout=120)  # Wait up to 2 min for scan

            # Send email alert if violations found
            if plan.get("channels"):
                shop_email = info.get("email", "")
                if shop_email:
                    violations = _db_get_violations(shop, status="open")
                    if violations:
                        scan = _db_get_latest_scan(shop)
                        score = scan.get("overall_score", 0) or 0
                        subject = f"SellerShield: {len(violations)} compliance issue(s) found in your store"
                        html = _build_alert_email(shop, violations, score)
                        _send_alert_email(shop_email, subject, html)
        except Exception as e:
            print(f"[scheduler] Scan error for {shop}: {e}")


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


# ── Startup ────────────────────────────────────────────────────────────────
_init_db()
_init_extended_schema()

# Start background scheduler (auto-scans based on plan frequency)
_scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
_scheduler_thread.start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
