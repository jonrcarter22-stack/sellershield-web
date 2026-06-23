"""
audit_engine.py — SellerShield Core Audit Engine

Given a store URL, crawls the site and checks it against:
  1. Platform compliance rules (rules_db.RULES)
  2. Known suspension patterns (rules_db.SUSPENSION_PATTERNS)

Returns a structured AuditResult with per-platform scores and findings.
"""

import re
import ssl
import time
import socket
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

try:
    import requests
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[WARN] requests/beautifulsoup4 not installed — crawling disabled")

from rules_db import RULES, SUSPENSION_PATTERNS

SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
PLATFORM_NAMES  = {
    "google":  "Google Merchant Center",
    "amazon":  "Amazon Seller Central",
    "tiktok":  "TikTok Shop",
    "meta":    "Meta Commerce",
    "walmart": "Walmart Marketplace",
    "all":     "All Platforms",
}

CRAWL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SellerShield-AuditBot/1.0; +https://sellershield.com/bot)",
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Common page slugs to discover
PAGE_PROBES = [
    "privacy", "privacy-policy", "privacy_policy",
    "return", "returns", "refund", "refund-policy", "return-policy",
    "contact", "contact-us", "about", "about-us",
    "terms", "terms-of-service", "terms-and-conditions", "tos",
    "shipping", "shipping-policy", "delivery",
]


@dataclass
class Finding:
    rule_id:   str
    platform:  str
    category:  str
    severity:  str
    message:   str
    fix:       str
    source:    str = "rule"   # "rule" or "pattern"
    evidence:  str = ""       # snippet of matching content


@dataclass
class PlatformScore:
    platform:    str
    name:        str
    score:       int          # 0–100
    grade:       str          # Great / Good / Medium / Low / Critical
    findings:    list[Finding] = field(default_factory=list)
    passed:      int = 0
    failed:      int = 0


@dataclass
class AuditResult:
    url:              str
    timestamp:        str
    overall_score:    int
    overall_grade:    str
    ssl_ok:           bool
    pages_found:      list[str]
    pages_missing:    list[str]
    platform_scores:  list[PlatformScore]
    all_findings:     list[Finding]
    suspension_warnings: list[dict]
    crawl_error:      str = ""


def _grade(score: int) -> str:
    if score >= 90: return "Great"
    if score >= 75: return "Good"
    if score >= 55: return "Medium"
    if score >= 30: return "Low"
    return "Critical"


def _excerpt(text: str, pattern: str, window: int = 80) -> str:
    """Return a short excerpt around the first match of pattern."""
    try:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            start = max(0, m.start() - window // 2)
            end   = min(len(text), m.end() + window // 2)
            return "..." + text[start:end].strip() + "..."
    except re.error:
        pass
    return ""


class AuditEngine:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = None
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update(CRAWL_HEADERS)

    # ── Network helpers ────────────────────────────────────────────────────

    def _fetch(self, url: str) -> tuple[int, str]:
        """Returns (status_code, html). 0 = network error."""
        if not self.session:
            return 0, ""
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return r.status_code, r.text
        except requests.exceptions.SSLError:
            return -1, ""
        except Exception:
            return 0, ""

    def _check_ssl(self, hostname: str) -> bool:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname):
                return True
        except Exception:
            return False

    def _measure_load_time(self, url: str) -> float:
        if not self.session:
            return 0.0
        try:
            t0 = time.time()
            self.session.get(url, timeout=15)
            return time.time() - t0
        except Exception:
            return 0.0

    # ── Page discovery ─────────────────────────────────────────────────────

    def _discover_pages(self, base_url: str, homepage_html: str) -> tuple[list[str], list[str]]:
        """
        Find which required pages exist.
        Returns (found_slugs, missing_slugs).
        """
        found, missing = [], []
        soup = BeautifulSoup(homepage_html, "html.parser") if homepage_html else None

        # Collect all hrefs from homepage
        site_links = set()
        if soup:
            for a in soup.find_all("a", href=True):
                href = a["href"].lower()
                site_links.add(href)

        for slug in PAGE_PROBES:
            # Check if any homepage link contains this slug
            if any(slug in link for link in site_links):
                found.append(slug)
                continue
            # Try fetching directly
            probe_url = urllib.parse.urljoin(base_url, slug)
            status, _ = self._fetch(probe_url)
            if status == 200:
                found.append(slug)
            elif slug not in found:
                missing.append(slug)

        # Deduplicate — if "privacy" found, don't also report "privacy-policy" missing
        # NOTE: "about" is its own key, separate from "contact", so META-003 and UNI-004
        # can independently detect each page type.
        key_pages = {
            "privacy":  ["privacy", "privacy-policy", "privacy_policy"],
            "return":   ["return", "returns", "refund", "refund-policy", "return-policy"],
            "contact":  ["contact", "contact-us"],
            "about":    ["about", "about-us"],
            "terms":    ["terms", "terms-of-service", "terms-and-conditions", "tos"],
            "shipping": ["shipping", "shipping-policy", "delivery"],
        }
        found_keys, missing_keys = [], []
        for key, variants in key_pages.items():
            if any(v in found for v in variants):
                found_keys.append(key)
            else:
                missing_keys.append(key)

        return found_keys, missing_keys

    # ── Content helpers ───────────────────────────────────────────────────

    def _all_text(self, html: str) -> str:
        """Strip HTML tags and return clean text."""
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(" ", strip=True)

    def _has_structured_data(self, html: str) -> bool:
        return bool(re.search(r'"@type"\s*:\s*"Product"', html, re.IGNORECASE) or
                    "schema.org/Product" in html)

    # ── Rule checkers ─────────────────────────────────────────────────────

    def _run_rule(self, rule: dict, context: dict) -> Optional[Finding]:
        """
        Evaluate a single rule against the crawled context.
        Returns a Finding if violated, None if passed.
        """
        check   = rule.get("check")
        pattern = rule.get("pattern", "")
        text    = context.get("full_text", "")
        html    = context.get("html", "")

        if check == "ssl":
            if not context.get("ssl_ok", True):
                return Finding(rule["id"], rule["platform"], rule["category"],
                               rule["severity"], rule["message"], rule["fix"],
                               evidence="SSL certificate missing or invalid")
            return None

        if check == "page_missing":
            # pattern may be "return|refund" — split on | and check if ANY variant
            # appears as a substring in the found pages list
            variants = [v.strip() for v in pattern.split("|")]
            pages_found = context.get("pages_found", [])
            if not any(variant in page for variant in variants for page in pages_found):
                return Finding(rule["id"], rule["platform"], rule["category"],
                               rule["severity"], rule["message"], rule["fix"])
            return None

        if check == "content_missing":
            if not re.search(pattern, text, re.IGNORECASE):
                return Finding(rule["id"], rule["platform"], rule["category"],
                               rule["severity"], rule["message"], rule["fix"])
            return None

        if check == "content_contains":
            if re.search(pattern, text, re.IGNORECASE):
                excerpt = _excerpt(text, pattern)
                return Finding(rule["id"], rule["platform"], rule["category"],
                               rule["severity"], rule["message"], rule["fix"],
                               evidence=excerpt)
            return None

        if check == "page_load":
            if context.get("load_time", 0) > 3.0:
                return Finding(rule["id"], rule["platform"], rule["category"],
                               rule["severity"], rule["message"], rule["fix"],
                               evidence=f"Load time: {context['load_time']:.1f}s")
            return None

        if check == "structured_data":
            if not self._has_structured_data(html):
                return Finding(rule["id"], rule["platform"], rule["category"],
                               rule["severity"], rule["message"], rule["fix"])
            return None

        return None

    def _check_suspension_patterns(self, context: dict, active_platforms: list) -> list[dict]:
        """Match known suspension patterns against site content.
        Only returns patterns relevant to the platforms being audited."""
        warnings = []
        text = context.get("full_text", "")
        for sp in SUSPENSION_PATTERNS:
            # Skip patterns for platforms not selected in this audit
            if sp["platform"] not in active_platforms:
                continue
            if sp.get("check_pattern"):
                if re.search(sp["check_pattern"], text, re.IGNORECASE):
                    warnings.append({
                        "id":        sp["id"],
                        "platform":  sp["platform"],
                        "title":     sp["title"],
                        "frequency": sp["frequency"],
                        "warning":   sp["warning"],
                        "examples":  sp.get("reddit_examples", []),
                    })
        return warnings

    # ── Platform scorer ───────────────────────────────────────────────────

    def _score_platform(self, platform: str, findings: list[Finding], total_rules: int) -> PlatformScore:
        """Calculate a 0-100 score for a platform based on findings."""
        deductions = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
        score = max(0, min(100, 100 - deductions))
        failed = len(findings)
        passed = max(0, total_rules - failed)
        return PlatformScore(
            platform=platform,
            name=PLATFORM_NAMES.get(platform, platform.title()),
            score=score,
            grade=_grade(score),
            findings=sorted(findings, key=lambda f: SEVERITY_WEIGHT.get(f.severity, 0), reverse=True),
            passed=passed,
            failed=failed,
        )

    # ── Main entry point ──────────────────────────────────────────────────

    def audit(self, url: str, platforms: Optional[List[str]] = None) -> AuditResult:
        """
        Run a full compliance audit on `url`.

        Args:
            url:       The store URL to audit (e.g. "https://mystore.com")
            platforms: List of platforms to check. None = all.

        Returns:
            AuditResult with scores and findings.
        """
        if not url.startswith("http"):
            url = "https://" + url

        parsed    = urllib.parse.urlparse(url)
        hostname  = parsed.netloc
        timestamp = datetime.now().isoformat()

        print(f"\n🔍 SellerShield Audit Starting")
        print(f"   URL: {url}")
        print(f"   Time: {timestamp}\n")

        # 1. SSL check
        print("  [1/5] Checking SSL...")
        ssl_ok = self._check_ssl(hostname)
        print(f"        SSL: {'✓ Valid' if ssl_ok else '✗ Missing/Invalid'}")

        # 2. Fetch homepage
        print("  [2/5] Fetching homepage...")
        t0 = time.time()
        status, html = self._fetch(url)
        load_time = time.time() - t0
        crawl_error = ""
        if status == 0:
            crawl_error = "Could not reach the website. Audit based on rules only."
            html = ""
            print(f"        ✗ Could not fetch ({status})")
        else:
            print(f"        ✓ Fetched ({status}, {len(html):,} chars, {load_time:.1f}s)")

        full_text = self._all_text(html) if html else ""

        # 3. Discover pages
        print("  [3/5] Discovering required pages...")
        if html:
            pages_found, pages_missing = self._discover_pages(url, html)
        else:
            pages_found, pages_missing = [], list(PAGE_PROBES[:5])
        print(f"        Found: {pages_found}")
        print(f"        Missing: {pages_missing}")

        # 4. Run rules
        print("  [4/5] Running compliance rules...")
        context = {
            "ssl_ok":      ssl_ok,
            "html":        html,
            "full_text":   full_text,
            "pages_found": pages_found,
            "load_time":   load_time,
        }

        active_platforms = platforms or ["google", "amazon", "tiktok", "meta", "walmart"]
        platform_findings: dict[str, list[Finding]] = {p: [] for p in active_platforms}
        platform_rule_counts: dict[str, int] = {p: 0 for p in active_platforms}

        for rule in RULES:
            rp = rule["platform"]
            targets = active_platforms if rp == "all" else ([rp] if rp in active_platforms else [])
            for p in targets:
                platform_rule_counts[p] = platform_rule_counts.get(p, 0) + 1
                finding = self._run_rule(rule, context)
                if finding:
                    # For universal rules, attach a copy to each platform
                    import copy
                    f = copy.copy(finding)
                    f.platform = p
                    platform_findings[p].append(f)

        # 5. Suspension pattern matching
        print("  [5/5] Checking suspension patterns...")
        suspension_warnings = self._check_suspension_patterns(context, active_platforms)
        print(f"        {len(suspension_warnings)} pattern matches found\n")

        # 6. Build platform scores
        platform_scores = []
        all_findings    = []
        for p in active_platforms:
            ps = self._score_platform(p, platform_findings[p], platform_rule_counts.get(p, 10))
            platform_scores.append(ps)
            all_findings.extend(ps.findings)

        # 7. Overall score = weighted average
        if platform_scores:
            overall_score = round(sum(ps.score for ps in platform_scores) / len(platform_scores))
        else:
            overall_score = 100

        return AuditResult(
            url=url,
            timestamp=timestamp,
            overall_score=overall_score,
            overall_grade=_grade(overall_score),
            ssl_ok=ssl_ok,
            pages_found=pages_found,
            pages_missing=pages_missing,
            platform_scores=sorted(platform_scores, key=lambda ps: ps.score),
            all_findings=sorted(all_findings, key=lambda f: SEVERITY_WEIGHT.get(f.severity, 0), reverse=True),
            suspension_warnings=suspension_warnings,
            crawl_error=crawl_error,
        )
