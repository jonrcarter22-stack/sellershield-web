"""
compliance_scanner.py
─────────────────────
Channel-specific compliance rule engine for SellerShield.

Usage:
    from compliance_scanner import ComplianceScanner
    scanner = ComplianceScanner(shop, token)
    violations = scanner.run(channels=["google", "amazon", "meta"])

Each violation is a dict:
    {
        "rule_id":     str,   # e.g. "POL-001"
        "channel":     str,   # "google" | "amazon" | "meta"
        "severity":    str,   # "critical" | "high" | "medium" | "low"
        "title":       str,
        "description": str,
        "fix_type":    str,   # "auto" | "one_click" | "guided" | "flagged"
        "fix_details": dict,
    }
"""

import re
import requests

# ── Shopify Admin API version ─────────────────────────────────────────────
_API_VERSION = "2024-01"
_TIMEOUT = 15


def _shopify_get(shop: str, token: str, path: str) -> dict:
    url = f"https://{shop}/admin/api/{_API_VERSION}/{path}"
    headers = {"X-Shopify-Access-Token": token}
    try:
        r = requests.get(url, headers=headers, timeout=_TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[scanner] shopify_get error {path}: {e}")
    return {}


def _paginate(shop: str, token: str, path: str, key: str) -> list:
    """Fetch all pages of a Shopify list endpoint."""
    items, page_info = [], None
    sep = "&" if "?" in path else "?"
    while True:
        url = path if not page_info else f"{path}{sep}page_info={page_info}"
        full_url = f"https://{shop}/admin/api/{_API_VERSION}/{url}"
        headers = {"X-Shopify-Access-Token": token}
        try:
            r = requests.get(full_url, headers=headers, timeout=_TIMEOUT)
            if r.status_code != 200:
                break
            items.extend(r.json().get(key, []))
            link = r.headers.get("Link", "")
            next_match = re.search(r'page_info=([^&>]+)[^>]*>;\s*rel="next"', link)
            if next_match:
                page_info = next_match.group(1)
            else:
                break
        except Exception as e:
            print(f"[scanner] paginate error {path}: {e}")
            break
    return items


class ComplianceScanner:
    def __init__(self, shop: str, token: str):
        self.shop = shop
        self.token = token
        self._shop_info = None
        self._pages = None
        self._products = None
        self._policies = None

    # ── Data loaders (lazy, cached) ───────────────────────────────────────

    def shop_info(self) -> dict:
        if self._shop_info is None:
            self._shop_info = _shopify_get(self.shop, self.token, "shop.json").get("shop", {})
        return self._shop_info

    def pages(self) -> list:
        if self._pages is None:
            self._pages = _paginate(self.shop, self.token, "pages.json?limit=250", "pages")
        return self._pages

    def products(self) -> list:
        if self._products is None:
            self._products = _paginate(self.shop, self.token, "products.json?limit=250&status=active", "products")
        return self._products

    def policies(self) -> dict:
        """Returns Shopify legal policies (refund, privacy, shipping, terms)."""
        if self._policies is None:
            data = _shopify_get(self.shop, self.token, "policies.json")
            self._policies = {p["handle"]: p for p in data.get("policies", [])}
        return self._policies

    # ── Entry point ───────────────────────────────────────────────────────

    def run(self, channels: list = None) -> list:
        if channels is None:
            channels = ["google"]
        violations = []
        runners = {
            "google":  self._check_google,
            "amazon":  self._check_amazon,
            "meta":    self._check_meta,
        }
        for ch in channels:
            if ch in runners:
                try:
                    violations.extend(runners[ch]())
                except Exception as e:
                    print(f"[scanner] {ch} check error: {e}")
        return violations

    # ── Helpers ───────────────────────────────────────────────────────────

    def _page_exists(self, *handles) -> bool:
        """Return True if any page/policy matches one of the given handle keywords."""
        page_handles = {p.get("handle", "").lower() for p in self.pages()}
        page_titles  = {p.get("title", "").lower() for p in self.pages()}
        policy_handles = set(self.policies().keys())
        for kw in handles:
            kw = kw.lower()
            if any(kw in h for h in page_handles | policy_handles | page_titles):
                return True
        return False

    def _strip_html(self, html: str) -> str:
        return re.sub(r"<[^>]+>", " ", html or "").strip()

    def _word_count(self, text: str) -> int:
        return len(text.split()) if text else 0

    # ─────────────────────────────────────────────────────────────────────
    # GOOGLE MERCHANT CENTER / SHOPPING
    # ─────────────────────────────────────────────────────────────────────

    def _check_google(self) -> list:
        v = []
        v.extend(self._google_policy_checks())
        v.extend(self._google_product_checks())
        v.extend(self._google_store_checks())
        return v

    def _google_policy_checks(self) -> list:
        v = []

        # POL-001: Privacy Policy
        if not self._page_exists("privacy", "privacy-policy"):
            v.append(dict(
                rule_id="POL-001", channel="google",
                severity="critical",
                title="Missing Privacy Policy page",
                description="Google Merchant Center requires a clearly accessible Privacy Policy. Missing this page can result in account suspension.",
                fix_type="auto",
                fix_details={
                    "action": "create_page",
                    "page_handle": "privacy-policy",
                    "template_key": "privacy",
                    "instructions": "We'll auto-create a Privacy Policy page and link it in your store footer.",
                },
            ))

        # POL-002: Refund / Return Policy
        if not self._page_exists("refund", "return", "returns", "refund-policy"):
            v.append(dict(
                rule_id="POL-002", channel="google",
                severity="critical",
                title="Missing Refund / Return Policy page",
                description="Google requires all merchants to have a clearly stated refund and return policy. Without it your listings may be disapproved.",
                fix_type="auto",
                fix_details={
                    "action": "create_page",
                    "page_handle": "refund-policy",
                    "template_key": "refund",
                },
            ))

        # POL-003: Shipping Policy
        if not self._page_exists("shipping", "shipping-policy"):
            v.append(dict(
                rule_id="POL-003", channel="google",
                severity="high",
                title="Missing Shipping Policy page",
                description="Google Shopping requires accurate shipping information. A Shipping Policy page helps prevent listing disapprovals.",
                fix_type="auto",
                fix_details={
                    "action": "create_page",
                    "page_handle": "shipping-policy",
                    "template_key": "shipping",
                },
            ))

        # POL-004: Terms of Service
        if not self._page_exists("terms", "terms-of-service", "tos"):
            v.append(dict(
                rule_id="POL-004", channel="google",
                severity="medium",
                title="Missing Terms of Service page",
                description="A Terms of Service page is required for subscription products and strongly recommended for all stores.",
                fix_type="auto",
                fix_details={
                    "action": "create_page",
                    "page_handle": "terms-of-service",
                    "template_key": "terms",
                },
            ))

        return v

    def _google_product_checks(self) -> list:
        v = []
        products = self.products()
        if not products:
            return v

        missing_desc, missing_img, zero_price, short_title, missing_gtin = [], [], [], [], []

        for p in products:
            pid = p.get("id")
            title = p.get("title", "")
            desc  = self._strip_html(p.get("body_html", ""))
            imgs  = p.get("images", [])
            variants = p.get("variants", [])

            # PRD-001: Missing/thin description
            if self._word_count(desc) < 20:
                missing_desc.append(title[:50])

            # PRD-002: No images
            if not imgs:
                missing_img.append(title[:50])

            # PRD-003: Zero or missing price
            for var in variants:
                price = float(var.get("price") or 0)
                if price <= 0:
                    zero_price.append(title[:50])
                    break

            # PRD-004: Title too short or generic
            if len(title) < 10 or title.lower() in {"product", "untitled", "new product", ""}:
                short_title.append(title[:50])

            # PRD-005: Missing GTIN/barcode for products with brand
            has_brand = bool(p.get("vendor") and p.get("vendor").lower() not in {"", "generic", "unbranded"})
            if has_brand and variants:
                if not any(var.get("barcode") for var in variants):
                    missing_gtin.append(title[:50])

        if missing_desc:
            v.append(dict(
                rule_id="PRD-001", channel="google", severity="high",
                title=f"Products with missing or thin descriptions ({len(missing_desc)} affected)",
                description=f"Google requires descriptive product content. Affected: {', '.join(missing_desc[:3])}{'...' if len(missing_desc) > 3 else ''}",
                fix_type="guided",
                fix_details={"affected_titles": missing_desc, "min_words": 20,
                             "instructions": "Add at least 20 words of descriptive content to each affected product's description in Shopify Admin > Products."},
            ))

        if missing_img:
            v.append(dict(
                rule_id="PRD-002", channel="google", severity="critical",
                title=f"Products with no images ({len(missing_img)} affected)",
                description=f"Google requires at least one high-quality product image. Affected: {', '.join(missing_img[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": missing_img,
                             "instructions": "Upload at least one product image (minimum 100x100px, recommended 800x800px) for each affected product."},
            ))

        if zero_price:
            v.append(dict(
                rule_id="PRD-003", channel="google", severity="critical",
                title=f"Products with zero or missing price ({len(zero_price)} affected)",
                description=f"Products must have a valid price. Affected: {', '.join(zero_price[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": zero_price,
                             "instructions": "Set a valid price greater than $0 for all variants of affected products."},
            ))

        if short_title:
            v.append(dict(
                rule_id="PRD-004", channel="google", severity="medium",
                title=f"Products with vague or incomplete titles ({len(short_title)} affected)",
                description=f"Google recommends descriptive titles (brand + product type + key attributes). Affected: {', '.join(short_title[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": short_title,
                             "instructions": "Update product titles to include brand, product type, size, color, and other key attributes. Recommended: 70-150 characters."},
            ))

        if missing_gtin:
            v.append(dict(
                rule_id="PRD-005", channel="google", severity="medium",
                title=f"Branded products missing GTIN/barcode ({len(missing_gtin)} affected)",
                description=f"Google requires GTINs (UPC, EAN, ISBN) for products with a brand. Missing for: {', '.join(missing_gtin[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": missing_gtin,
                             "instructions": "Add barcode/GTIN to product variants in Shopify Admin > Products > [Product] > Variants > Barcode."},
            ))

        return v

    def _google_store_checks(self) -> list:
        v = []
        info = self.shop_info()

        # CON-001: No contact email
        if not info.get("email"):
            v.append(dict(
                rule_id="CON-001", channel="google", severity="high",
                title="Store contact email not set",
                description="Google requires merchants to have a verifiable contact method. Set your store email in Shopify Admin > Settings > General.",
                fix_type="guided",
                fix_details={"instructions": "Go to Shopify Admin > Settings > General and set a valid store contact email."},
            ))

        # CON-002: No phone number
        if not info.get("phone"):
            v.append(dict(
                rule_id="CON-002", channel="google", severity="low",
                title="Store phone number not set",
                description="A phone number improves merchant trust score with Google. Add it in Shopify Admin > Settings > General.",
                fix_type="guided",
                fix_details={"instructions": "Go to Shopify Admin > Settings > General and add a store phone number."},
            ))

        # SEC-001: SSL check (always pass for Shopify — it handles SSL)
        # Shopify stores always have SSL, so no violation here.

        return v

    # ─────────────────────────────────────────────────────────────────────
    # AMAZON
    # ─────────────────────────────────────────────────────────────────────

    def _check_amazon(self) -> list:
        v = []
        products = self.products()
        if not products:
            return v

        long_title, html_desc, no_bullets, long_bullets, price_issues = [], [], [], [], []

        for p in products:
            title = p.get("title", "")
            desc  = p.get("body_html", "") or ""
            variants = p.get("variants", [])

            # AMZ-001: Title > 200 characters
            if len(title) > 200:
                long_title.append(title[:50])

            # AMZ-002: Description contains raw HTML tags
            # Amazon doesn't allow HTML in product descriptions
            if re.search(r"<(b|i|u|strong|em|h\d|div|span|p|br)[^>]*>", desc, re.I):
                html_desc.append(title[:50])

            # AMZ-003: Missing bullet points (check tags/metafields approximation via description length)
            plain_desc = self._strip_html(desc)
            if self._word_count(plain_desc) < 5:
                no_bullets.append(title[:50])

            # AMZ-004: Compare-at price set (may trigger Amazon price parity concerns)
            for var in variants:
                compare = float(var.get("compare_at_price") or 0)
                price   = float(var.get("price") or 0)
                if compare > 0 and compare < price:
                    price_issues.append(title[:50])
                    break

        if long_title:
            v.append(dict(
                rule_id="AMZ-001", channel="amazon", severity="high",
                title=f"Product titles exceed Amazon's 200-character limit ({len(long_title)} affected)",
                description=f"Amazon rejects listings with titles over 200 characters. Affected: {', '.join(long_title[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": long_title,
                             "instructions": "Shorten product titles to 200 characters or fewer. Focus on: Brand + Product Type + Key Features."},
            ))

        if html_desc:
            v.append(dict(
                rule_id="AMZ-002", channel="amazon", severity="high",
                title=f"Product descriptions contain HTML tags ({len(html_desc)} affected)",
                description=f"Amazon does not allow HTML in product descriptions. Affected: {', '.join(html_desc[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": html_desc,
                             "instructions": "Remove all HTML tags from product descriptions. Use plain text with line breaks only."},
            ))

        if no_bullets:
            v.append(dict(
                rule_id="AMZ-003", channel="amazon", severity="medium",
                title=f"Products missing key feature bullet points ({len(no_bullets)} affected)",
                description=f"Amazon listings perform significantly better with 5 bullet points. Affected: {', '.join(no_bullets[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": no_bullets,
                             "instructions": "Add 3-5 descriptive bullet points to each product description covering: key features, dimensions, materials, compatibility, and warranty."},
            ))

        if price_issues:
            v.append(dict(
                rule_id="AMZ-004", channel="amazon", severity="medium",
                title=f"Compare-at price lower than sale price ({len(price_issues)} affected)",
                description=f"Products where compare-at price is less than the selling price will confuse customers and may be flagged. Affected: {', '.join(price_issues[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": price_issues,
                             "instructions": "Ensure compare-at price is always higher than the sale price, or remove the compare-at price if not running a sale."},
            ))

        # AMZ-005: Missing return/refund policy page
        if not self._page_exists("refund", "return", "refund-policy"):
            v.append(dict(
                rule_id="AMZ-005", channel="amazon", severity="critical",
                title="Missing Refund/Return Policy (required for Amazon sync)",
                description="Amazon requires all third-party sellers to maintain a return policy at least as generous as Amazon's own 30-day policy.",
                fix_type="auto",
                fix_details={"action": "create_page", "page_handle": "refund-policy", "template_key": "refund"},
            ))

        return v

    # ─────────────────────────────────────────────────────────────────────
    # META (Facebook / Instagram Shopping)
    # ─────────────────────────────────────────────────────────────────────

    def _check_meta(self) -> list:
        v = []
        products = self.products()

        no_category, low_res_risk, restricted, long_name = [], [], [], []
        restricted_keywords = [
            "tobacco", "vape", "vaping", "e-cigarette", "cbd", "cannabis",
            "marijuana", "hemp", "alcohol", "beer", "wine", "spirits",
            "weapon", "firearm", "gun", "ammo", "ammunition", "knife",
            "supplement", "diet pill", "weight loss",
        ]

        for p in products:
            title   = p.get("title", "").lower()
            tags    = p.get("tags", "").lower()
            imgs    = p.get("images", [])
            product_type = p.get("product_type", "")

            # MET-001: No product_type set (Meta uses this for category)
            if not product_type:
                no_category.append(p.get("title", "")[:50])

            # MET-002: Potentially restricted product categories
            combined = title + " " + tags
            hits = [kw for kw in restricted_keywords if kw in combined]
            if hits:
                restricted.append((p.get("title", "")[:50], hits[:2]))

            # MET-003: Image likely low resolution (check width/height if available)
            for img in imgs:
                w = img.get("width", 999)
                h = img.get("height", 999)
                if w and h and (w < 500 or h < 500):
                    low_res_risk.append(p.get("title", "")[:50])
                    break

            # MET-004: Product name too long for Instagram Shopping (>150 chars)
            if len(p.get("title", "")) > 150:
                long_name.append(p.get("title", "")[:50])

        if no_category:
            v.append(dict(
                rule_id="MET-001", channel="meta", severity="high",
                title=f"Products missing product type / category ({len(no_category)} affected)",
                description=f"Meta requires a product type (category) for all items in your catalog. Affected: {', '.join(no_category[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": no_category,
                             "instructions": "In Shopify Admin > Products, set the 'Product type' field for each product. Use standard Google Product Taxonomy values for best results."},
            ))

        if restricted:
            titles_str = ", ".join(f"{t} ({', '.join(kws)})" for t, kws in restricted[:3])
            v.append(dict(
                rule_id="MET-002", channel="meta", severity="critical",
                title=f"Products may contain restricted content ({len(restricted)} flagged)",
                description=f"Meta prohibits or restricts certain product categories. Flagged products: {titles_str}",
                fix_type="flagged",
                fix_details={
                    "affected": [{"title": t, "keywords": kws} for t, kws in restricted],
                    "instructions": "Review Meta's Commerce Policies at facebook.com/policies/commerce. You may need to remove or recategorize these products from your Facebook/Instagram shop.",
                    "policy_url": "https://www.facebook.com/policies/commerce/",
                },
            ))

        if low_res_risk:
            v.append(dict(
                rule_id="MET-003", channel="meta", severity="medium",
                title=f"Products with potentially low-resolution images ({len(low_res_risk)} affected)",
                description=f"Meta recommends images of at least 500x500px (ideally 1024x1024px). Affected: {', '.join(low_res_risk[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": low_res_risk,
                             "instructions": "Replace product images with higher resolution versions. Minimum: 500×500px. Recommended: 1024×1024px, square format, white background."},
            ))

        if long_name:
            v.append(dict(
                rule_id="MET-004", channel="meta", severity="low",
                title=f"Product titles exceed Meta's 150-character recommendation ({len(long_name)} affected)",
                description=f"Long titles get truncated in Instagram Shopping. Affected: {', '.join(long_name[:3])}",
                fix_type="guided",
                fix_details={"affected_titles": long_name,
                             "instructions": "Shorten product titles to under 150 characters for optimal display in Instagram Shopping."},
            ))

        # MET-005: Missing Privacy Policy (required for Meta Business verification)
        if not self._page_exists("privacy", "privacy-policy"):
            v.append(dict(
                rule_id="MET-005", channel="meta", severity="critical",
                title="Missing Privacy Policy (required for Meta Business verification)",
                description="Meta requires a Privacy Policy to verify your business and enable Facebook/Instagram Shopping.",
                fix_type="auto",
                fix_details={"action": "create_page", "page_handle": "privacy-policy", "template_key": "privacy"},
            ))

        return v


# ── Rule-ID to fix_type mapping (for backward compat with AuditEngine findings) ──
_FIX_TYPE_MAP = {
    "POL-": "auto",
    "CON-": "guided",
    "PRD-": "guided",
    "AMZ-": "guided",
    "MET-": "guided",
    "GTN-": "guided",
    "APP-": "one_click",
    "REP-": "flagged",
    "SEC-": "guided",
}

def resolve_fix_type(rule_id: str) -> str:
    for prefix, ft in _FIX_TYPE_MAP.items():
        if rule_id.startswith(prefix):
            return ft
    return "flagged"
