"""
report_generator.py — SellerShield Report Generator

Produces two outputs from an AuditResult:
  1. A console summary (always)
  2. A PDF report (requires reportlab)
"""

import json
from pathlib import Path
from datetime import datetime

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable, PageBreak, Preformatted)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from audit_engine import AuditResult, Finding, PlatformScore

# ── Visual fix examples ───────────────────────────────────────────────────────
# Each entry is a list of lines to display in a monospace "before/after" box.
# Shown in the PDF immediately below the fix text for that rule.

FIX_EXAMPLES = {

    "META-004": {
        "label": "How to add trust signals near your checkout",
        "lines": [
            "  Shopify stores (most common):                           ",
            "  ─────────────────────────────────────────────────────  ",
            "  1. In Shopify, go to:  Online Store > Themes > Customize",
            "  2. Select your Cart or Checkout page from the top menu  ",
            "  3. Add a Text block just above or below the checkout    ",
            "     button and type:                                     ",
            "       'Secure checkout — your info is always protected'  ",
            "  4. In your Theme settings, turn ON 'Show payment icons' ",
            "     in the Footer section — this displays Visa,          ",
            "     Mastercard, PayPal logos automatically.              ",
            "                                                          ",
            "  Not on Shopify?                                         ",
            "  ─────────────────────────────────────────────────────  ",
            "  Ask your web designer to add a small line of text near  ",
            "  the checkout button that says:                          ",
            "    'Secure checkout  |  Visa  Mastercard  PayPal'        ",
            "  and make sure your site address starts with https://    ",
        ],
    },

    "UNI-001": {
        "label": "How to turn on HTTPS (the padlock) for your store",
        "lines": [
            "  How to check: open your store in a browser and look at  ",
            "  the address bar at the top.                             ",
            "                                                          ",
            "  GOOD  ->  https://yourstore.com   (has a padlock icon)  ",
            "  BAD   ->  http://yourstore.com    (no padlock)          ",
            "                                                          ",
            "  How to fix — find your platform below:                  ",
            "                                                          ",
            "  Shopify:     It's on by default. Go to Settings >       ",
            "               Domains and make sure 'Redirect all        ",
            "               traffic to this domain' is turned on.      ",
            "                                                          ",
            "  Squarespace: Settings > Domains > SSL — toggle ON.      ",
            "                                                          ",
            "  WooCommerce: Contact your hosting company and ask them  ",
            "               to install a free SSL certificate.         ",
            "               (Most hosts do this for free in 5 minutes) ",
        ],
    },

    "UNI-002": {
        "label": "How to create a Privacy Policy page (free, 5 minutes)",
        "lines": [
            "  The easiest way — use a free generator:                 ",
            "                                                          ",
            "  Shopify stores:                                         ",
            "    1. Go to: shopify.com/tools/policy-generator          ",
            "    2. Fill in your business name and email               ",
            "    3. Copy the generated policy                          ",
            "    4. In Shopify: Online Store > Pages > Add page        ",
            "    5. Title it 'Privacy Policy', paste the text, Save    ",
            "    6. Add a link to it in your footer navigation         ",
            "                                                          ",
            "  Other platforms — use Termly (free):                    ",
            "    1. Go to: termly.io/privacy-policy-generator          ",
            "    2. Answer the questions about your business           ",
            "    3. Copy and paste the result into a new page          ",
            "                                                          ",
            "  The policy must cover: what info you collect, how you   ",
            "  use it, and how customers can contact you.              ",
        ],
    },

    "UNI-003": {
        "label": "What your Return Policy page must include",
        "lines": [
            "  Every marketplace checks for these 5 things:            ",
            "                                                          ",
            "  1. How long do customers have to return?                ",
            "     Example: '30 days from the date of delivery'         ",
            "                                                          ",
            "  2. What condition must the item be in?                  ",
            "     Example: 'Unused, in original packaging'             ",
            "                                                          ",
            "  3. Who pays for return shipping?                        ",
            "     Example: 'We cover defective items. Buyer pays for   ",
            "     change-of-mind returns.'                             ",
            "                                                          ",
            "  4. How fast will you refund them?                       ",
            "     Example: 'Refunds within 5-7 business days'          ",
            "                                                          ",
            "  5. How do they start a return?                          ",
            "     Example: 'Email hello@yourstore.com with your order  ",
            "     number and reason for return.'                       ",
            "                                                          ",
            "  Shopify tip: Settings > Policies has a built-in         ",
            "  Return Policy template you can edit and publish.        ",
        ],
    },

    "GMC-004": {
        "label": "How to add product data that Google can read",
        "lines": [
            "  What this means in plain English:                       ",
            "  Google wants your product pages to include hidden data   ",
            "  (called 'structured data') so it can show your price,   ",
            "  availability, and rating in search results.             ",
            "                                                          ",
            "  If you're on Shopify — you're likely already covered:   ",
            "  ─────────────────────────────────────────────────────  ",
            "  1. Most Shopify themes include this automatically.      ",
            "  2. To confirm, go to:                                   ",
            "       search.google.com/test/rich-results                ",
            "  3. Enter one of your product page URLs and click Test   ",
            "  4. If you see a green checkmark, you're good to go!     ",
            "                                                          ",
            "  If the test shows errors:                               ",
            "  ─────────────────────────────────────────────────────  ",
            "  1. In the Shopify App Store, search for:                ",
            "       'JSON-LD for SEO' (by Hextom — free version works) ",
            "  2. Install it — it adds the data automatically          ",
            "  3. Re-run the Google test above to confirm it's working ",
        ],
    },

    "META-003": {
        "label": "How to create an About Us page that passes Meta's review",
        "lines": [
            "  Meta's team checks your About Us page before approving  ",
            "  your shop. It doesn't need to be long — 2-3 sentences   ",
            "  is enough. They just want to know you're a real brand.  ",
            "                                                          ",
            "  What to include:                                        ",
            "  - Your business name                                    ",
            "  - What you sell                                         ",
            "  - Why customers should trust you                        ",
            "                                                          ",
            "  Example you can edit and use:                           ",
            "  ─────────────────────────────────────────────────────  ",
            "  '[Your Brand] is a [city/online] store specializing in  ",
            "  [product type]. We started in [year] because [reason].  ",
            "  Every order ships within [X] days with free returns.'   ",
            "  ─────────────────────────────────────────────────────  ",
            "                                                          ",
            "  How to add it in Shopify:                               ",
            "  1. Online Store > Pages > Add page                      ",
            "  2. Title: 'About Us'   URL slug: about-us               ",
            "  3. Paste your text, click Save                          ",
            "  4. Navigation > Footer menu > Add 'About Us' link       ",
        ],
    },
}

# ── Brand colors ─────────────────────────────────────────────────────────────
C_GREEN       = colors.HexColor("#22C55E")
C_GREEN_DARK  = colors.HexColor("#16A34A")
C_DARK_BG     = colors.HexColor("#0B1120")
C_MID_DARK    = colors.HexColor("#0F1F38")
C_WHITE       = colors.white
C_GRAY        = colors.HexColor("#64748B")
C_LIGHT_GRAY  = colors.HexColor("#CBD5E1")
C_OFF_WHITE   = colors.HexColor("#F8FAFC")
C_RED         = colors.HexColor("#EF4444")
C_YELLOW      = colors.HexColor("#FBBF24")
C_BLUE        = colors.HexColor("#3B82F6")
C_GREEN_LIGHT = colors.HexColor("#DCFCE7")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#EF4444"),
    "HIGH":     colors.HexColor("#F97316"),
    "MEDIUM":   colors.HexColor("#FBBF24"),
    "LOW":      colors.HexColor("#22C55E"),
}

GRADE_COLORS = {
    "Great":    colors.HexColor("#22C55E"),
    "Good":     colors.HexColor("#3B82F6"),
    "Medium":   colors.HexColor("#FBBF24"),
    "Low":      colors.HexColor("#F97316"),
    "Critical": colors.HexColor("#EF4444"),
}


# ════════════════════════════════════════════════════════════════════════════
# CONSOLE REPORTER
# ════════════════════════════════════════════════════════════════════════════

def print_report(result: AuditResult):
    W = 72
    def line(char="─"): print(char * W)
    def header(text): print(f"\n{'═' * W}\n  {text}\n{'═' * W}")

    header("SELLERSHIELD COMPLIANCE AUDIT REPORT")
    print(f"  URL:       {result.url}")
    print(f"  Audited:   {result.timestamp[:19].replace('T', ' ')}")
    print(f"  SSL:       {'✓ Valid' if result.ssl_ok else '✗ MISSING'}")
    if result.crawl_error:
        print(f"  ⚠ Note:    {result.crawl_error}")

    print(f"\n{'─' * W}")
    score = result.overall_score
    bar_len = int(score * 50 / 100)
    bar = "█" * bar_len + "░" * (50 - bar_len)
    print(f"  OVERALL SCORE: {score}/100  [{result.overall_grade}]")
    print(f"  [{bar}]")

    # Platform breakdown
    print(f"\n  PLATFORM BREAKDOWN")
    print(f"  {'Platform':<30} {'Score':>6}  {'Grade':<10}  Issues")
    line()
    for ps in sorted(result.platform_scores, key=lambda x: -x.score):
        crit = sum(1 for f in ps.findings if f.severity == "CRITICAL")
        high = sum(1 for f in ps.findings if f.severity == "HIGH")
        print(f"  {ps.name:<30} {ps.score:>5}/100  {ps.grade:<10}  "
              f"{crit} CRITICAL  {high} HIGH")

    # Pages
    print(f"\n  REQUIRED PAGES")
    print(f"  Found:   {', '.join(result.pages_found) or 'none detected'}")
    print(f"  Missing: {', '.join(result.pages_missing) or 'none'}")

    # Findings by severity
    findings_by_sev = {}
    for f in result.all_findings:
        findings_by_sev.setdefault(f.severity, []).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        flist = findings_by_sev.get(sev, [])
        if not flist:
            continue
        # Deduplicate by rule_id across platforms
        seen = set()
        unique = []
        for f in flist:
            if f.rule_id not in seen:
                seen.add(f.rule_id)
                unique.append(f)
        header(f"[{sev}] — {len(unique)} FINDING{'S' if len(unique) != 1 else ''}")
        for f in unique:
            print(f"\n  [{f.rule_id}] {f.message}")
            if f.evidence:
                print(f"  Evidence: {f.evidence[:120]}")
            print(f"  Fix: {f.fix[:200]}")
            line("·")

    # Suspension warnings
    if result.suspension_warnings:
        header(f"SUSPENSION RISK PATTERNS — {len(result.suspension_warnings)} MATCH(ES)")
        for w in result.suspension_warnings:
            plat = w["platform"].upper()
            print(f"\n  [{plat}] {w['title']}  (Frequency: {w['frequency']})")
            print(f"  ⚠ {w['warning']}")
            if w.get("examples"):
                print("  Real reports from sellers:")
                for ex in w["examples"][:2]:
                    print(f"    • \"{ex}\"")
            line("·")

    header("NEXT STEPS")
    criticals = [f for f in result.all_findings if f.severity == "CRITICAL"]
    if criticals:
        print(f"  1. Fix {len(criticals)} CRITICAL issue(s) immediately before listing on any platform.")
    highs = [f for f in result.all_findings if f.severity == "HIGH"]
    if highs:
        print(f"  2. Address {len(highs)} HIGH issue(s) within the next 7 days.")
    print(f"  3. Re-run this audit after making changes to verify your score improves.")
    print(f"  4. For ongoing protection, upgrade to SellerShield monthly monitoring.")
    print(f"\n  sellershield.com  |  contact@sellershield.com")
    print("═" * W + "\n")


# ════════════════════════════════════════════════════════════════════════════
# PDF REPORTER
# ════════════════════════════════════════════════════════════════════════════

def generate_pdf(result: AuditResult, output_path: str) -> str:
    if not HAS_REPORTLAB:
        raise RuntimeError("reportlab is required for PDF generation. pip install reportlab")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    def S(name, **kwargs):
        return ParagraphStyle(name, **kwargs)

    sTitle    = S("sTitle",    fontSize=26, textColor=C_WHITE,      fontName="Helvetica-Bold",   spaceAfter=4,  leading=30)
    sSubtitle = S("sSubt",     fontSize=11, textColor=C_GREEN,       fontName="Helvetica",        spaceAfter=2)
    sSmall    = S("sSmall",    fontSize=8,  textColor=C_LIGHT_GRAY,  fontName="Helvetica",        spaceAfter=2)
    sH1       = S("sH1",       fontSize=14, textColor=C_DARK_BG,     fontName="Helvetica-Bold",   spaceBefore=14, spaceAfter=4)
    sH2       = S("sH2",       fontSize=11, textColor=C_GREEN_DARK,  fontName="Helvetica-Bold",   spaceBefore=8,  spaceAfter=3)
    sBody     = S("sBody",     fontSize=9,  textColor=colors.HexColor("#1E293B"), fontName="Helvetica", spaceAfter=4, leading=14)
    sBodyBold = S("sBodyBold", fontSize=9,  textColor=colors.HexColor("#1E293B"), fontName="Helvetica-Bold", spaceAfter=2)
    sFix      = S("sFix",      fontSize=8,  textColor=C_GRAY,        fontName="Helvetica-Oblique", spaceAfter=4, leading=12)
    sCenter   = S("sCenter",   fontSize=9,  textColor=C_GRAY,        fontName="Helvetica",        alignment=TA_CENTER, spaceAfter=2)
    sEvidence = S("sEvidence", fontSize=8,  textColor=C_GRAY,        fontName="Courier",          backColor=colors.HexColor("#F1F5F9"), spaceAfter=4, leftIndent=8, rightIndent=8)

    story = []

    def spacer(h=0.15): return Spacer(1, h * inch)
    def hr(color=C_GREEN, thickness=1.5): return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6, spaceBefore=4)

    # ── Cover block ──────────────────────────────────────────────────────

    cover_data = [[
        Paragraph("SellerShield", sTitle),
        ""
    ]]
    cover_table = Table(cover_data, colWidths=[4.5 * inch, 2.5 * inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_DARK_BG),
        ("TOPPADDING",   (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 18),
        ("LEFTPADDING",  (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [8, 8, 8, 8]),
    ]))
    story.append(cover_table)
    story.append(spacer(0.1))
    story.append(Paragraph("COMPLIANCE AUDIT REPORT", sSubtitle))
    story.append(Paragraph(f"URL: {result.url}  |  Audited: {result.timestamp[:19].replace('T', ' ')}  |  SSL: {'✓ Valid' if result.ssl_ok else '✗ Missing'}", sSmall))
    story.append(hr())
    story.append(spacer(0.1))

    # ── Overall score ────────────────────────────────────────────────────

    score = result.overall_score
    grade = result.overall_grade
    grade_color = GRADE_COLORS.get(grade, C_GREEN)

    score_data = [
        [
            Paragraph(f"<b>{score}</b><font size='11'>/100</font>", ParagraphStyle("sc", fontSize=40, textColor=grade_color, fontName="Helvetica-Bold", leading=44, alignment=TA_CENTER)),
            Paragraph(f"<b>{grade}</b>", ParagraphStyle("gr", fontSize=20, textColor=grade_color, fontName="Helvetica-Bold", leading=24, alignment=TA_CENTER)),
            Paragraph("Overall Readiness Score", ParagraphStyle("ors", fontSize=9, textColor=C_GRAY, fontName="Helvetica", alignment=TA_CENTER)),
        ],
    ]
    score_table = Table([[score_data[0][0], score_data[0][1]]], colWidths=[3 * inch, 4 * inch])
    score_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_OFF_WHITE),
        ("TOPPADDING",   (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 16),
        ("LEFTPADDING",  (0, 0), (-1, -1), 18),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(score_table)
    story.append(spacer(0.15))

    # ── Platform breakdown table ─────────────────────────────────────────

    story.append(Paragraph("Platform Risk Breakdown", sH1))
    story.append(hr(C_LIGHT_GRAY, 0.5))

    header_row = ["Platform", "Score", "Grade", "Critical", "High", "Passed"]
    rows = [header_row]
    for ps in sorted(result.platform_scores, key=lambda x: -x.score):
        crit = sum(1 for f in ps.findings if f.severity == "CRITICAL")
        high = sum(1 for f in ps.findings if f.severity == "HIGH")
        rows.append([ps.name, f"{ps.score}/100", ps.grade,
                     str(crit) if crit else "—",
                     str(high) if high else "—",
                     str(ps.passed)])

    pt = Table(rows, colWidths=[2.2 * inch, 0.8 * inch, 0.85 * inch, 0.75 * inch, 0.6 * inch, 0.7 * inch])
    pt_style = [
        ("BACKGROUND",   (0, 0), (-1, 0), C_DARK_BG),
        ("TEXTCOLOR",    (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 8),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("ALIGN",        (0, 0), (0, -1), "LEFT"),
        ("FONTSIZE",     (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_OFF_WHITE, C_WHITE]),
        ("GRID",         (0, 0), (-1, -1), 0.25, C_LIGHT_GRAY),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
    ]
    # Color-code grade column
    grade_col_idx = 2
    for i, ps in enumerate(sorted(result.platform_scores, key=lambda x: -x.score)):
        row_idx = i + 1
        gc = GRADE_COLORS.get(ps.grade, C_GREEN)
        pt_style.append(("TEXTCOLOR", (grade_col_idx, row_idx), (grade_col_idx, row_idx), gc))
        pt_style.append(("FONTNAME",  (grade_col_idx, row_idx), (grade_col_idx, row_idx), "Helvetica-Bold"))
    # Red for critical counts
    for i, ps in enumerate(sorted(result.platform_scores, key=lambda x: -x.score)):
        row_idx = i + 1
        crit = sum(1 for f in ps.findings if f.severity == "CRITICAL")
        if crit > 0:
            pt_style.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), C_RED))
            pt_style.append(("FONTNAME",  (3, row_idx), (3, row_idx), "Helvetica-Bold"))
    pt.setStyle(TableStyle(pt_style))
    story.append(pt)
    story.append(spacer(0.2))

    # ── Required pages ───────────────────────────────────────────────────

    story.append(Paragraph("Required Pages Check", sH1))
    story.append(hr(C_LIGHT_GRAY, 0.5))

    PAGE_CHECK_KEYS = ["privacy", "return", "contact", "about", "terms", "shipping"]
    page_rows = [["Page", "Status"]]
    for p in PAGE_CHECK_KEYS:
        found = p in result.pages_found
        label = {"about": "About Us", "contact": "Contact Us", "return": "Return / Refund Policy",
                 "privacy": "Privacy Policy", "terms": "Terms of Service", "shipping": "Shipping Policy"}.get(p, p.replace("-", " ").title())
        page_rows.append([label, "✓  Found" if found else "✗  Missing"])

    pgt = Table(page_rows, colWidths=[3 * inch, 3.9 * inch])
    pgt_style = [
        ("BACKGROUND",   (0, 0), (-1, 0), C_MID_DARK),
        ("TEXTCOLOR",    (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 8),
        ("FONTSIZE",     (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_OFF_WHITE, C_WHITE]),
        ("GRID",         (0, 0), (-1, -1), 0.25, C_LIGHT_GRAY),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
    ]
    for i, page in enumerate(PAGE_CHECK_KEYS):
        row_idx = i + 1
        found = page in result.pages_found
        color = C_GREEN_DARK if found else C_RED
        pgt_style.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), color))
        pgt_style.append(("FONTNAME",  (1, row_idx), (1, row_idx), "Helvetica-Bold"))
    pgt.setStyle(TableStyle(pgt_style))
    story.append(pgt)
    story.append(spacer(0.2))

    # ── Findings ─────────────────────────────────────────────────────────

    story.append(PageBreak())
    story.append(Paragraph("Compliance Findings", sH1))
    story.append(Paragraph("Issues are listed by severity — fix CRITICAL items first.", sBody))
    story.append(hr())

    seen_ids = set()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        # Build deduplicated list one item at a time so seen_ids is updated
        # before the next item is checked — list comprehension was checking all
        # items against an empty set, letting duplicates through
        sev_findings = []
        for f in result.all_findings:
            if f.severity == sev and f.rule_id not in seen_ids:
                seen_ids.add(f.rule_id)
                sev_findings.append(f)
        if not sev_findings:
            continue

        sev_color = SEVERITY_COLORS.get(sev, C_GREEN)
        sev_label = Paragraph(
            f"<b>{sev}</b>  —  {len(sev_findings)} Issue{'s' if len(sev_findings) != 1 else ''}",
            ParagraphStyle("sevLabel", fontSize=11, textColor=sev_color, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
        )
        story.append(sev_label)

        for f in sev_findings:
            finding_data = [
                [
                    Paragraph(f"<b>{f.message}</b>", sBodyBold),
                    Paragraph(f.category, ParagraphStyle("cat", fontSize=7, textColor=C_GRAY, fontName="Helvetica", alignment=TA_RIGHT)),
                ],
            ]
            if f.evidence:
                finding_data.append([
                    Paragraph(f"Evidence: {f.evidence[:150]}", sEvidence), ""
                ])
            finding_data.append([
                Paragraph(f"<b>How to fix:</b> {f.fix}", sFix), ""
            ])

            ft = Table(finding_data, colWidths=[5.8 * inch, 1.1 * inch])
            ft.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), C_OFF_WHITE),
                ("TOPPADDING",   (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                ("LEFTPADDING",  (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("SPAN",         (0, 1), (-1, 1)),
                ("SPAN",         (0, 2), (-1, 2)),
                ("LINEAFTER",    (0, 0), (0, -1), 2, sev_color),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(ft)

            # ── Visual fix example (if available for this rule) ──────────
            if f.rule_id in FIX_EXAMPLES:
                ex = FIX_EXAMPLES[f.rule_id]
                # Use Preformatted so angle brackets and special chars render
                # verbatim without breaking ReportLab's XML parser.
                ex_text = "\n".join(ex["lines"])
                ex_pre = Preformatted(
                    ex_text,
                    ParagraphStyle("exPre", fontSize=7,
                                   textColor=colors.HexColor("#1E293B"),
                                   fontName="Courier", leading=11)
                )
                # Wrap label + content in a single Table cell for the blue box
                label_para = Paragraph(
                    f"<b>Fix Example —</b> {ex['label']}",
                    ParagraphStyle("exLbl", fontSize=8, textColor=C_BLUE,
                                   fontName="Helvetica-Bold", spaceAfter=4, leading=11)
                )
                ex_table = Table([[label_para], [ex_pre]], colWidths=[6.9 * inch])
                ex_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                    ("BOX",           (0, 0), (-1, -1), 0.75, C_BLUE),
                    ("TOPPADDING",    (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ]))
                story.append(spacer(0.05))
                story.append(ex_table)
                story.append(spacer(0.08))
            else:
                story.append(spacer(0.06))

    # ── Suspension warnings ──────────────────────────────────────────────

    if result.suspension_warnings:
        story.append(PageBreak())
        story.append(Paragraph("Suspension Risk Patterns", sH1))
        story.append(Paragraph(
            "These patterns were matched based on real seller suspension reports from Reddit and marketplace forums. "
            "They indicate your store may share characteristics with sellers who have been suspended.",
            sBody
        ))
        story.append(hr(C_YELLOW))

        for w in result.suspension_warnings:
            story.append(Paragraph(f"<b>{w['title']}</b>  ({w['frequency']})", sH2))
            story.append(Paragraph(f"⚠ {w['warning']}", sBody))
            if w.get("examples"):
                story.append(Paragraph("Real seller reports:", sFix))
                for ex in w["examples"][:2]:
                    story.append(Paragraph(f'• "{ex}"',
                        ParagraphStyle("ex", fontSize=8, textColor=C_GRAY, fontName="Helvetica-Oblique",
                                       leftIndent=12, spaceAfter=3, leading=12)))
            story.append(spacer(0.08))

    # ── Footer ───────────────────────────────────────────────────────────

    story.append(PageBreak())
    story.append(spacer(0.5))
    story.append(hr())
    story.append(Paragraph(
        "This report was generated by SellerShield — Marketplace Compliance Audits That Keep You Approved.",
        sCenter
    ))
    story.append(Paragraph(
        f"Generated: {result.timestamp[:10]}  |  sellershield.com  |  contact@sellershield.com",
        sCenter
    ))
    story.append(Paragraph(
        "This report is for informational purposes only and does not constitute legal advice. "
        "Platform policies change frequently — always verify against current official documentation.",
        ParagraphStyle("disc", fontSize=7, textColor=C_LIGHT_GRAY, fontName="Helvetica-Oblique",
                       alignment=TA_CENTER, spaceAfter=4)
    ))

    doc.build(story)
    return output_path


# ════════════════════════════════════════════════════════════════════════════
# JSON export
# ════════════════════════════════════════════════════════════════════════════

def save_json(result: AuditResult, output_path: str) -> str:
    data = {
        "url":           result.url,
        "timestamp":     result.timestamp,
        "overall_score": result.overall_score,
        "overall_grade": result.overall_grade,
        "ssl_ok":        result.ssl_ok,
        "pages_found":   result.pages_found,
        "pages_missing": result.pages_missing,
        "platforms": [
            {
                "platform": ps.platform,
                "name":     ps.name,
                "score":    ps.score,
                "grade":    ps.grade,
                "passed":   ps.passed,
                "failed":   ps.failed,
                "findings": [
                    {"rule_id": f.rule_id, "severity": f.severity,
                     "category": f.category, "message": f.message,
                     "fix": f.fix, "evidence": f.evidence}
                    for f in ps.findings
                ],
            }
            for ps in result.platform_scores
        ],
        "suspension_warnings": result.suspension_warnings,
        "crawl_error": result.crawl_error,
    }
    Path(output_path).write_text(json.dumps(data, indent=2))
    return output_path
