"""
policy_fetcher.py — Live Policy Updater

Fetches the latest policy text from each platform's public help pages
and extracts new keywords/rules to augment the rules_db.

Run this periodically (e.g., weekly cron) to keep your rules current.
Requires internet access — designed for production server deployment.
"""

import re
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List

try:
    import requests
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Policy page URLs ────────────────────────────────────────────────────────

POLICY_SOURCES = {
    "google": [
        ("Shopping ads policies overview",        "https://support.google.com/merchants/answer/6150127"),
        ("Prohibited content",                     "https://support.google.com/merchants/answer/7000891"),
        ("Prohibited practices",                   "https://support.google.com/merchants/answer/6150126"),
        ("Restricted content",                     "https://support.google.com/merchants/answer/9049197"),
        ("Website requirements",                   "https://support.google.com/merchants/answer/4752885"),
        ("Misrepresentation policy",               "https://support.google.com/merchants/answer/6150127"),
    ],
    "amazon": [
        ("Seller code of conduct",                 "https://sellercentral.amazon.com/help/hub/reference/G1801"),
        ("Prohibited seller activities",           "https://sellercentral.amazon.com/help/hub/reference/G200386250"),
        ("Product listing policies",               "https://sellercentral.amazon.com/help/hub/reference/G200390640"),
        ("Review policies",                        "https://sellercentral.amazon.com/help/hub/reference/G202138500"),
        ("Performance notification policies",      "https://sellercentral.amazon.com/help/hub/reference/G200285190"),
    ],
    "tiktok": [
        ("TikTok Shop prohibited products",        "https://seller-us.tiktok.com/university/essay?knowledge_id=10000731"),
        ("TikTok Shop seller standards",           "https://seller-us.tiktok.com/university/essay?knowledge_id=10001527"),
        ("Creator marketplace policies",           "https://www.tiktok.com/legal/page/global/bc-policy/en"),
    ],
    "meta": [
        ("Facebook Commerce Policy",               "https://www.facebook.com/policies/commerce"),
        ("Instagram Shopping policies",            "https://help.instagram.com/1627591227572763"),
        ("Prohibited content Commerce",            "https://www.facebook.com/policies/commerce/prohibited_content"),
    ],
    "walmart": [
        ("Walmart Marketplace seller standards",   "https://sellerhelp.walmart.com/s/guide?article=000009355"),
        ("Prohibited products list",               "https://sellerhelp.walmart.com/s/guide?article=000007892"),
        ("Content policy",                         "https://sellerhelp.walmart.com/s/guide?article=000008893"),
    ],
}

# ── Reddit sources for suspension pattern mining ─────────────────────────────

REDDIT_SOURCES = {
    "google": [
        "https://www.reddit.com/r/GoogleMerchantCenter/search.json?q=suspended+account&sort=top&t=year&limit=25",
        "https://www.reddit.com/r/SEO/search.json?q=google+merchant+center+suspended&sort=top&t=year&limit=10",
    ],
    "amazon": [
        "https://www.reddit.com/r/FulfillmentByAmazon/search.json?q=suspended+account&sort=top&t=year&limit=25",
        "https://www.reddit.com/r/AmazonSeller/search.json?q=account+suspended&sort=top&t=year&limit=25",
        "https://www.reddit.com/r/amazonseller/search.json?q=suspension+policy+violation&sort=top&t=year&limit=15",
    ],
    "tiktok": [
        "https://www.reddit.com/r/Tiktokhelp/search.json?q=tiktok+shop+suspended&sort=top&t=year&limit=20",
        "https://www.reddit.com/r/TikTok/search.json?q=shop+account+banned+seller&sort=top&t=year&limit=10",
    ],
    "meta": [
        "https://www.reddit.com/r/FacebookAds/search.json?q=account+disabled+suspended&sort=top&t=year&limit=25",
        "https://www.reddit.com/r/Instagram/search.json?q=shop+disabled+suspended+commerce&sort=top&t=year&limit=10",
    ],
    "walmart": [
        "https://www.reddit.com/r/walmart/search.json?q=seller+suspended+marketplace&sort=top&t=year&limit=15",
        "https://www.reddit.com/r/ecommerce/search.json?q=walmart+marketplace+suspended&sort=top&t=year&limit=10",
    ],
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SellerShield-PolicyBot/1.0; +https://sellershield.com/bot)",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


class PolicyFetcher:
    def __init__(self, cache_dir="policy_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.session = requests.Session() if HAS_REQUESTS else None
        if self.session:
            self.session.headers.update(HEADERS)

    def _cache_path(self, url: str) -> Path:
        key = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{key}.json"

    def _load_cache(self, url: str, max_age_hours=24):
        p = self._cache_path(url)
        if p.exists():
            data = json.loads(p.read_text())
            age = (datetime.now().timestamp() - data["ts"]) / 3600
            if age < max_age_hours:
                return data["content"]
        return None

    def _save_cache(self, url: str, content: str):
        p = self._cache_path(url)
        p.write_text(json.dumps({"ts": datetime.now().timestamp(), "content": content}))

    def fetch_page(self, url: str, retries=2) -> Optional[str]:
        cached = self._load_cache(url)
        if cached:
            return cached
        if not HAS_REQUESTS or not self.session:
            return None
        for attempt in range(retries + 1):
            try:
                resp = self.session.get(url, timeout=12)
                if resp.status_code == 200:
                    self._save_cache(url, resp.text)
                    return resp.text
                elif resp.status_code == 429:
                    time.sleep(10 * (attempt + 1))
            except Exception as e:
                if attempt == retries:
                    print(f"  [fetch] Failed {url}: {e}")
                time.sleep(2)
        return None

    def extract_policy_keywords(self, html: str, platform: str) -> List[str]:
        """Pull key prohibited/required terms from policy HTML."""
        soup = BeautifulSoup(html, "html.parser")
        keywords = []
        for tag in soup.find_all(["li", "p", "h3", "h4"]):
            text = tag.get_text(" ", strip=True).lower()
            # Look for prohibition language
            if any(w in text for w in ["prohibit", "not allow", "must not", "forbidden", "banned", "violat", "suspend"]):
                # Extract noun phrases (simplified)
                words = re.findall(r'\b[a-z]{4,}\b', text)
                keywords.extend(words[:5])
        return list(set(keywords))

    def fetch_reddit_patterns(self, platform: str) -> List[dict]:
        """Fetch top suspension posts from Reddit JSON API."""
        patterns = []
        urls = REDDIT_SOURCES.get(platform, [])
        for url in urls:
            html = self.fetch_page(url)
            if not html:
                continue
            try:
                data = json.loads(html)
                posts = data.get("data", {}).get("children", [])
                for post in posts:
                    d = post.get("data", {})
                    title = d.get("title", "")
                    selftext = d.get("selftext", "")
                    score = d.get("score", 0)
                    if score < 5:
                        continue
                    # Only keep suspension-related posts
                    combined = (title + " " + selftext).lower()
                    if any(w in combined for w in ["suspend", "ban", "deactivat", "disable", "violat"]):
                        patterns.append({
                            "platform": platform,
                            "title": title,
                            "excerpt": selftext[:300],
                            "score": score,
                            "url": f"https://reddit.com{d.get('permalink', '')}",
                        })
            except json.JSONDecodeError:
                pass
        return patterns

    def refresh_all(self) -> dict:
        """Fetch all policy pages and Reddit patterns. Returns summary."""
        print("=== SellerShield Policy Fetcher ===\n")
        results = {"policies": {}, "reddit_patterns": {}, "timestamp": datetime.now().isoformat()}
        for platform, sources in POLICY_SOURCES.items():
            print(f"[{platform.upper()}] Fetching {len(sources)} policy pages...")
            results["policies"][platform] = []
            for name, url in sources:
                html = self.fetch_page(url)
                if html:
                    keywords = self.extract_policy_keywords(html, platform)
                    results["policies"][platform].append({"name": name, "url": url, "keywords": keywords[:20]})
                    print(f"  ✓ {name} ({len(keywords)} keywords extracted)")
                else:
                    print(f"  ✗ {name} (could not fetch — using cached rules)")
        for platform in REDDIT_SOURCES:
            print(f"\n[REDDIT/{platform.upper()}] Mining suspension patterns...")
            posts = self.fetch_reddit_patterns(platform)
            results["reddit_patterns"][platform] = posts
            print(f"  Found {len(posts)} relevant suspension posts")
        # Save results
        out = self.cache_dir / "latest_fetch.json"
        out.write_text(json.dumps(results, indent=2))
        print(f"\n✅ Results saved to {out}")
        return results


if __name__ == "__main__":
    fetcher = PolicyFetcher()
    fetcher.refresh_all()
