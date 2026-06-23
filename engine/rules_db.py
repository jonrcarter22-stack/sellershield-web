"""
rules_db.py — SellerShield Compliance Rules Database

Sourced from official platform policy pages:
  Google Merchant Center: support.google.com/merchants
  Amazon Seller Central:  sellercentral.amazon.com/help
  TikTok Shop:            seller-us.tiktok.com/university
  Meta Commerce:          facebook.com/policies/commerce
  Walmart Marketplace:    sellerhelp.walmart.com

Each rule has:
  id        — unique identifier
  platform  — which marketplace it belongs to
  category  — rule category
  severity  — CRITICAL / HIGH / MEDIUM / LOW
  check     — type of check to perform
  pattern   — what to look for (keyword, regex, or presence/absence)
  message   — human-readable description of the violation
  fix       — step-by-step remediation guidance
"""

RULES = [

    # ═══════════════════════════════════════════════════════════
    # UNIVERSAL — applies to all platforms
    # ═══════════════════════════════════════════════════════════

    {
        "id": "UNI-001", "platform": "all", "category": "Website Basics",
        "severity": "CRITICAL",
        "check": "ssl",
        "message": "Website is not served over HTTPS",
        "fix": "Enable SSL on your domain. All major marketplaces require HTTPS. Use Let's Encrypt (free) or buy an SSL certificate from your hosting provider.",
    },
    {
        "id": "UNI-002", "platform": "all", "category": "Website Basics",
        "severity": "CRITICAL",
        "check": "page_missing", "pattern": "privacy",
        "message": "No Privacy Policy page found",
        "fix": "Add a Privacy Policy page that covers: what data you collect, how you use it, whether you share it with third parties, and how users can request deletion. Link it in your footer.",
    },
    {
        "id": "UNI-003", "platform": "all", "category": "Website Basics",
        "severity": "CRITICAL",
        "check": "page_missing", "pattern": "return|refund",
        "message": "No Return/Refund Policy page found",
        "fix": "Add a Return & Refund Policy that clearly states: return window (days), conditions for return, who pays return shipping, and refund timeline. Required by Google, Amazon, TikTok, and Walmart.",
    },
    {
        "id": "UNI-004", "platform": "all", "category": "Website Basics",
        "severity": "HIGH",
        "check": "page_missing", "pattern": "contact",
        "message": "No Contact page found",
        "fix": "Add a Contact Us page with at minimum: a contact email, and ideally a phone number and physical or mailing address.",
    },
    {
        "id": "UNI-005", "platform": "all", "category": "Website Basics",
        "severity": "HIGH",
        "check": "page_missing", "pattern": "terms|conditions",
        "message": "No Terms of Service / Terms & Conditions page found",
        "fix": "Add a Terms of Service page covering purchase terms, limitation of liability, and dispute resolution. Required for Meta Commerce approval.",
    },
    {
        "id": "UNI-006", "platform": "all", "category": "Contact Info",
        "severity": "HIGH",
        "check": "content_missing", "pattern": r"[\w\.-]+@[\w\.-]+\.\w+",
        "message": "No contact email address found on the website",
        "fix": "Display a contact email address on your Contact page and/or footer. It must be a real, monitored address — not a no-reply address.",
    },
    {
        "id": "UNI-007", "platform": "all", "category": "Prohibited Content",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(fake|counterfeit|replica|knockoff|bootleg)\b",
        "message": "Page contains terms associated with counterfeit goods",
        "fix": "Remove any references to 'fake', 'counterfeit', 'replica', or similar terms. Selling counterfeit goods violates all marketplace policies and is illegal.",
    },
    {
        "id": "UNI-008", "platform": "all", "category": "Prohibited Content",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(hack|crack|pirate|warez|keygen|serial key)\b",
        "message": "Page contains terms associated with piracy or circumvention tools",
        "fix": "Remove any content related to software piracy, license circumvention, or hacking tools. These are prohibited on all platforms.",
    },

    # ═══════════════════════════════════════════════════════════
    # GOOGLE MERCHANT CENTER
    # Source: support.google.com/merchants/answer/6150127
    # ═══════════════════════════════════════════════════════════

    {
        "id": "GMC-001", "platform": "google", "category": "Shopping Ads Policy",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(cure|treat|heal|miracle|guaranteed results)\b",
        "message": "Page contains unsubstantiated health or cure claims",
        "fix": "Remove all 'cure', 'treat', 'heal', or 'guaranteed results' claims unless you have clinical evidence and FDA clearance. Google prohibits misleading health claims in Shopping ads.",
    },
    {
        "id": "GMC-002", "platform": "google", "category": "Shopping Ads Policy",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(clickbait|you won|congratulations you|claim your prize)\b",
        "message": "Page contains deceptive or clickbait language",
        "fix": "Remove sensationalized or misleading language. Google will disapprove your Merchant Center account for deceptive content.",
    },
    {
        "id": "GMC-003", "platform": "google", "category": "Landing Page",
        "severity": "HIGH",
        "check": "page_load",
        "message": "Landing page is slow to load (over 3 seconds)",
        "fix": "Optimize images (use WebP format), enable browser caching, minify CSS/JS, and consider a CDN. Google penalizes slow landing pages in Shopping ads.",
    },
    {
        "id": "GMC-004", "platform": "google", "category": "Product Data",
        "severity": "HIGH",
        "check": "structured_data",
        "message": "No product structured data (schema.org/Product) found on product pages",
        "fix": "Add schema.org Product markup to all product pages. Include: name, price, currency, availability, and condition fields. Use Google's Rich Results Test to verify.",
    },
    {
        "id": "GMC-005", "platform": "google", "category": "Landing Page",
        "severity": "HIGH",
        "check": "content_missing", "pattern": r"\$[\d,]+|price|USD|buy now|add to cart",
        "message": "Product price is not clearly displayed on the landing page",
        "fix": "Display the product price prominently on your landing page. The price must match what is submitted in your Merchant Center feed exactly.",
    },
    {
        "id": "GMC-006", "platform": "google", "category": "Business Verification",
        "severity": "HIGH",
        "check": "page_missing", "pattern": "shipping",
        "message": "No Shipping Policy page found",
        "fix": "Add a Shipping Policy page with: estimated delivery times, shipping costs, carriers used, and international shipping info if applicable. Required for Google Merchant Center approval.",
    },
    {
        "id": "GMC-007", "platform": "google", "category": "Prohibited Products",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(CBD|THC|cannabis|marijuana|hemp oil)\b",
        "message": "Page may contain references to CBD/cannabis products",
        "fix": "CBD and cannabis products are prohibited in Google Shopping ads in most regions. Remove these products from your Shopping feed or consult Google's restricted product policies.",
    },
    {
        "id": "GMC-008", "platform": "google", "category": "Misrepresentation",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(as seen on tv|endorsed by|official partner of google|google approved)\b",
        "message": "Page makes misleading endorsement claims",
        "fix": "Remove false or unverified endorsement claims. 'Google approved' or 'Official Google partner' claims without authorization will result in immediate account suspension.",
    },

    # ═══════════════════════════════════════════════════════════
    # AMAZON SELLER CENTRAL
    # Source: sellercentral.amazon.com/help/hub/reference
    # ═══════════════════════════════════════════════════════════

    {
        "id": "AMZ-001", "platform": "amazon", "category": "Listing Quality",
        "severity": "HIGH",
        "check": "content_contains", "pattern": r"\b(best seller|#1|number one|top rated|amazon choice)\b",
        "message": "Listing may contain prohibited performance claims or Amazon badges",
        "fix": "Do not use 'Best Seller', '#1', or 'Amazon's Choice' in product titles or descriptions unless Amazon has officially granted these badges to your ASIN. This violates Amazon's listing policy.",
    },
    {
        "id": "AMZ-002", "platform": "amazon", "category": "Listing Quality",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(free shipping|ships from amazon|fulfilled by amazon|prime eligible)\b",
        "message": "Listing uses Amazon-specific fulfillment language that must match actual setup",
        "fix": "Only display fulfillment claims (FBA, Prime) that match your actual account setup. Incorrect claims trigger listing suppression.",
    },
    {
        "id": "AMZ-003", "platform": "amazon", "category": "Review Policy",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(leave a review|please review|5 star|five star|in exchange for|free product for review)\b",
        "message": "Page may contain review solicitation language that violates Amazon policy",
        "fix": "Remove all language asking for reviews, especially incentivized reviews. Amazon prohibits offering anything in exchange for reviews. Use Amazon's 'Request a Review' button instead.",
    },
    {
        "id": "AMZ-004", "platform": "amazon", "category": "Restricted Categories",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(weapon|firearm|gun|ammo|ammunition|silencer|suppressor)\b",
        "message": "Page references restricted or prohibited weapons-related products",
        "fix": "Firearms, ammunition, and related accessories require Amazon approval. Apply for category approval before listing. Suppressors and silencers are prohibited outright.",
    },
    {
        "id": "AMZ-005", "platform": "amazon", "category": "Product Safety",
        "severity": "HIGH",
        "check": "content_contains", "pattern": r"\b(FDA approved|clinically proven|doctor recommended|medically proven)\b",
        "message": "Listing contains medical/FDA claims that require verification",
        "fix": "Only use FDA-approval claims if you have official FDA clearance documentation. Amazon will require compliance documentation for all medical claims during listing review.",
    },
    {
        "id": "AMZ-006", "platform": "amazon", "category": "Seller Information",
        "severity": "HIGH",
        "check": "content_missing", "pattern": r"(amazon store|amazon seller|storefront|asin)",
        "message": "No clear link to your Amazon storefront found",
        "fix": "Link your website to your Amazon storefront. Ensure your business name on Amazon matches your website. Inconsistencies trigger Amazon's fraud detection.",
    },
    {
        "id": "AMZ-007", "platform": "amazon", "category": "Pricing",
        "severity": "HIGH",
        "check": "content_contains", "pattern": r"\b(cheaper than amazon|beat amazon|lower than amazon price)\b",
        "message": "Page claims to undercut Amazon pricing in a way that may violate agreements",
        "fix": "Remove direct Amazon price comparisons. Amazon's seller agreement prohibits directing customers away from Amazon. Competing on price is fine, but don't reference Amazon specifically.",
    },

    # ═══════════════════════════════════════════════════════════
    # TIKTOK SHOP
    # Source: seller-us.tiktok.com/university/essay
    # ═══════════════════════════════════════════════════════════

    {
        "id": "TTK-001", "platform": "tiktok", "category": "Content Policy",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(get rich quick|make money fast|passive income guaranteed|financial freedom guaranteed)\b",
        "message": "Page contains prohibited 'get rich quick' or guaranteed income claims",
        "fix": "Remove all guaranteed income, 'get rich quick', or financial freedom claims. TikTok Shop prohibits misleading financial claims and will remove your products.",
    },
    {
        "id": "TTK-002", "platform": "tiktok", "category": "Product Safety",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(weight loss guaranteed|lose \d+ pounds|fat burner|thermogenic|appetite suppressant)\b",
        "message": "Page contains prohibited weight loss claims",
        "fix": "Weight loss supplements with guaranteed claims are prohibited on TikTok Shop. Remove specific weight/pound loss guarantees and consult TikTok's Health & Beauty policy.",
    },
    {
        "id": "TTK-003", "platform": "tiktok", "category": "Age-Restricted Content",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(alcohol|liquor|spirits|wine|vape|e-cigarette|tobacco|beer\s+(bottle|can|keg|pack|case|brand|shop|store)|buy\s+beer|sell\s+beer|craft\s+beer)\b",
        "message": "Page may contain age-restricted product listings",
        "fix": "Alcohol, tobacco, and vaping products are prohibited or heavily restricted on TikTok Shop. Remove these listings or apply for the restricted goods selling program.",
    },
    {
        "id": "TTK-004", "platform": "tiktok", "category": "Authenticity",
        "severity": "HIGH",
        "check": "content_contains", "pattern": r"\b(inspired by|style of|looks like|dupe|designer inspired)\b",
        "message": "Page uses 'dupe' or 'inspired by' language that may indicate counterfeit risk",
        "fix": "TikTok Shop has zero tolerance for counterfeit goods. Remove 'dupe', 'inspired by', and 'designer' comparisons. Sell only authentic products with proof of authenticity.",
    },

    # ═══════════════════════════════════════════════════════════
    # META COMMERCE (Facebook & Instagram Shops)
    # Source: facebook.com/policies/commerce
    # ═══════════════════════════════════════════════════════════

    {
        "id": "META-001", "platform": "meta", "category": "Commerce Policy",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(subscription box|auto-renew|recurring charge)\b",
        "message": "Page offers subscription products — Meta has specific disclosure requirements",
        "fix": "Subscription products require clear disclosure of: billing frequency, total cost, and how to cancel. Add a dedicated subscription terms section. Missing disclosure = account restriction.",
    },
    {
        "id": "META-002", "platform": "meta", "category": "Commerce Policy",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(adult|explicit|18\+|nsfw|xxx)\b",
        "message": "Page may contain adult content prohibited in Meta Shops",
        "fix": "Adult content is prohibited in Meta Shops (Facebook & Instagram). Remove all explicit content, adult product listings, or 18+ references from your commerce-linked pages.",
    },
    {
        "id": "META-003", "platform": "meta", "category": "Business Verification",
        "severity": "HIGH",
        "check": "page_missing", "pattern": "about",
        "message": "No 'About Us' page found — required for Meta Business verification",
        "fix": "Add an About Us page describing your business, founding story, and what you sell. Meta's commerce review team checks this during shop approval.",
    },
    {
        "id": "META-004", "platform": "meta", "category": "Checkout",
        "severity": "HIGH",
        "check": "content_missing",
        "pattern": r"(secure checkout|ssl|https|encrypted|visa|mastercard|paypal|american express|apple pay|shop pay|payment)",
        "message": "No visible security indicators or payment trust signals found on the website",
        "fix": "Display payment method logos (Visa, Mastercard, PayPal) and/or a 'Secure Checkout' badge near your checkout button. For Shopify stores, ensure your theme shows the payment icons in the footer — these count as trust signals for Meta's review. Add 'Your payment information is processed securely' text near checkout.",
    },
    {
        "id": "META-005", "platform": "meta", "category": "Prohibited Products",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(diet pill|weight loss pill|slimming|detox tea|flat tummy)\b",
        "message": "Page contains diet/slimming product references common in Meta policy violations",
        "fix": "Meta prohibits before/after weight loss images and misleading claims in ads and shop listings. Remove unsubstantiated claims or risk shop restriction.",
    },

    # ═══════════════════════════════════════════════════════════
    # WALMART MARKETPLACE
    # Source: sellerhelp.walmart.com
    # ═══════════════════════════════════════════════════════════

    {
        "id": "WMT-001", "platform": "walmart", "category": "Content Standards",
        "severity": "HIGH",
        "check": "content_missing", "pattern": r"(return|refund|30 day|money back)",
        "message": "No clear return/money-back policy language on product pages",
        "fix": "Walmart requires sellers to display return policy prominently. Minimum: 30-day return window for most categories. Display this on product pages and your policy page.",
    },
    {
        "id": "WMT-002", "platform": "walmart", "category": "Pricing",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(price match|lowest price guaranteed|best price guarantee)\b",
        "message": "Price guarantee claims must comply with Walmart's competitive pricing policy",
        "fix": "If making price guarantee claims, ensure your price is genuinely the lowest available online. Walmart's pricing algorithm compares prices continuously — violations lead to listing suppression.",
    },
    {
        "id": "WMT-003", "platform": "walmart", "category": "Seller Standards",
        "severity": "HIGH",
        "check": "page_missing", "pattern": "shipping",
        "message": "No Shipping Policy page found — required for Walmart Marketplace",
        "fix": "Add a Shipping Policy with: processing time (Walmart requires 1-2 business days), carrier options, and estimated delivery. Walmart enforces strict seller performance metrics on shipping speed.",
    },
    {
        "id": "WMT-004", "platform": "walmart", "category": "Product Safety",
        "severity": "CRITICAL",
        "check": "content_contains", "pattern": r"\b(not tested|no warranty|sold as-is|no returns accepted)\b",
        "message": "Page contains language that conflicts with Walmart's seller guarantee requirements",
        "fix": "Walmart requires sellers to honor basic product warranties and return policies. Remove 'no warranty', 'sold as-is', or 'no returns' language from all product listings.",
    },
]

# ═══════════════════════════════════════════════════════════
# SUSPENSION PATTERNS — built from Reddit/forum research
# Sources: r/FulfillmentByAmazon, r/GoogleMerchantCenter,
#          r/TikTokShop, r/ecommerce, seller forums
# ═══════════════════════════════════════════════════════════

SUSPENSION_PATTERNS = [
    {
        "id": "SP-001", "platform": "google",
        "title": "Google MC suspended for 'Misrepresentation of self or products'",
        "frequency": "Very Common",
        "triggers": ["misleading pricing", "shipping time mismatch", "unavailable products in feed", "checkout errors"],
        "reddit_examples": [
            "Suspended after Google found my advertised price didn't match checkout price (tax display issue)",
            "Got hit with misrepresentation because my site showed 'In Stock' but products were backordered 3 weeks",
            "Suspension for showing $0 shipping on MC but charging $8.99 at checkout",
        ],
        "check_pattern": r"(free shipping|ships in \d+ day|in stock|available)",
        "warning": "Ensure all prices, shipping costs, and availability on your website EXACTLY match your Google Merchant Center feed.",
    },
    {
        "id": "SP-002", "platform": "google",
        "title": "Google MC suspended for 'Unavailable landing page'",
        "frequency": "Very Common",
        "triggers": ["404 errors on linked pages", "geo-blocked content", "login-required pages", "slow page load"],
        "reddit_examples": [
            "All 340 products disapproved because my site returns 403 to Googlebot",
            "Suspended because I had a country redirect that blocked Google's crawler",
            "Pages required login to view — Google couldn't crawl product content",
        ],
        "check_pattern": None,
        "warning": "Ensure your website is accessible to Googlebot, loads under 3 seconds, and does not redirect based on geography.",
    },
    {
        "id": "SP-003", "platform": "amazon",
        "title": "Amazon suspended for 'Review manipulation'",
        "frequency": "Very Common",
        "triggers": ["email inserts asking for reviews", "discount in exchange for review", "multiple accounts", "review trading groups"],
        "reddit_examples": [
            "Got suspended for including a card in packaging offering a discount for a 5-star review",
            "Amazon linked my new account to a suspended one because I used the same bank account",
            "Suspended for joining a Facebook group to trade reviews — Amazon monitors these groups",
        ],
        "check_pattern": r"(review|5 star|feedback|in exchange)",
        "warning": "Never solicit reviews with incentives. Do not create multiple seller accounts. Amazon actively monitors review trading groups.",
    },
    {
        "id": "SP-004", "platform": "amazon",
        "title": "Amazon suspended for 'Inauthentic item complaints'",
        "frequency": "Very Common",
        "triggers": ["buying from wholesale sites without invoices", "unable to provide supplier invoices", "sourcing from retail stores"],
        "reddit_examples": [
            "Suspended for inauthentic — bought from Alibaba supplier who sent fake items I didn't know about",
            "Amazon asked for invoices from my supplier. I bought from a liquidation site with no real invoices",
            "Customer complained item was fake. Amazon suspended me before I could respond",
        ],
        "check_pattern": None,
        "warning": "Always source from verifiable, legitimate suppliers and keep proper invoices. Amazon will ask for invoices within 48 hours of an authenticity complaint.",
    },
    {
        "id": "SP-005", "platform": "amazon",
        "title": "Amazon suspended for 'Account health — Late Shipment Rate'",
        "frequency": "Common",
        "triggers": ["LSR above 4%", "holiday volume spikes", "supplier delays", "manual fulfillment without buffer"],
        "reddit_examples": [
            "Suspended during Q4 because I couldn't keep up with orders and LSR hit 12%",
            "Got deactivated because USPS delays caused my LSR to spike — not my fault but Amazon didn't care",
        ],
        "check_pattern": None,
        "warning": "Monitor your Late Shipment Rate daily. Set handling time conservatively. Use FBA during high-volume periods to avoid LSR spikes.",
    },
    {
        "id": "SP-006", "platform": "tiktok",
        "title": "TikTok Shop suspended for 'Prohibited product listing'",
        "frequency": "Very Common",
        "triggers": ["health supplements with unverified claims", "cosmetics without ingredient lists", "electronics without certifications"],
        "reddit_examples": [
            "My entire shop was suspended because one supplement listing had 'cures anxiety' in the description",
            "TikTok removed all my beauty products because I didn't have INCI ingredient lists in the listings",
            "Electronics listing killed my shop — needed FCC certification I didn't know about",
        ],
        "check_pattern": r"(supplement|vitamin|cure|anxiety|depression|certif)",
        "warning": "TikTok Shop requires product certifications for electronics, health claims to be substantiated, and full ingredient lists for beauty products.",
    },
    {
        "id": "SP-007", "platform": "tiktok",
        "title": "TikTok Shop suspended for 'Creator-seller policy violation'",
        "frequency": "Common",
        "triggers": ["failing to disclose paid partnerships", "misleading product demonstrations in videos", "fake before/after content"],
        "reddit_examples": [
            "Got my shop banned because a creator I worked with didn't disclose our paid partnership",
            "Suspended for a video showing dramatic before/after that TikTok flagged as misleading",
        ],
        "check_pattern": r"(before.?after|results may vary|real results)",
        "warning": "All TikTok Shop creator partnerships must include #ad or #sponsored disclosure. Before/after content must include 'Results not typical' disclaimer.",
    },
    {
        "id": "SP-008", "platform": "meta",
        "title": "Meta Commerce restricted for 'Landing page policy violation'",
        "frequency": "Very Common",
        "triggers": ["missing privacy policy", "checkout redirects to third-party", "pop-ups blocking content", "required login before viewing products"],
        "reddit_examples": [
            "Facebook Shop restricted because my privacy policy link in footer was broken",
            "Rejected because I use a pop-up email capture that covers product content before checkout",
            "Shop blocked because my checkout redirected to PayPal on a different domain with no return URL",
        ],
        "check_pattern": r"(privacy|popup|pop-up|subscribe|modal)",
        "warning": "Meta crawls your landing pages. Broken policy links, aggressive pop-ups, or redirected checkouts all trigger automatic restrictions.",
    },
    {
        "id": "SP-009", "platform": "meta",
        "title": "Meta ads account disabled for 'Unusual activity'",
        "frequency": "Common",
        "triggers": ["new account spending large amounts quickly", "multiple people accessing account from different locations", "VPN usage on ad account"],
        "reddit_examples": [
            "New account, spent $5K in first week — flagged and disabled with no warning",
            "My VA in the Philippines accessing my ad account triggered a security flag",
        ],
        "check_pattern": None,
        "warning": "Avoid rapid spending ramp-ups on new Meta ad accounts. Grant team access through Business Manager — never share login credentials.",
    },
    {
        "id": "SP-010", "platform": "walmart",
        "title": "Walmart seller suspended for 'Performance threshold violations'",
        "frequency": "Common",
        "triggers": ["order defect rate above 2%", "cancellation rate above 2%", "on-time delivery rate below 95%"],
        "reddit_examples": [
            "Walmart suspended me with no warning — my cancellation rate hit 3.1% for one week",
            "Suspended for 90 days because my ODR went to 2.4% during a supplier stockout",
        ],
        "check_pattern": None,
        "warning": "Walmart has strict automated enforcement. Monitor all metrics daily: Order Defect Rate <2%, Cancellation Rate <2%, On-Time Delivery >95%.",
    },
]
