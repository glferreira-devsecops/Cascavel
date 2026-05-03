#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  CASCAVEL v2.2.0 — Elite PDF Report Generator                        ║
║  Product of RET Tecnologia (https://rettecnologia.org)               ║
║  Enterprise-grade pentest reporting with legal compliance             ║
╚══════════════════════════════════════════════════════════════════════╝

Architecture: reportlab Platypus engine with custom page templates,
CVSS v4.0 scoring, OWASP Top 10 mapping, risk matrix visualization,
12-clause legal disclaimer (LGPD/Marco Civil/ISO 27001/PCI DSS/NIST),
RET Tecnologia branding, and 2026 Elite features:
  • Intelligent page breaks with table splitting & header repeat
  • Widows/orphans typographic control
  • Diagonal CONFIDENCIAL watermark on all internal pages
  • "Página X de Y" footer with total page count (two-pass render)
  • QR Code on cover linking to rettecnologia.org
  • Glossary of security terms
  • Revision history table
  • Prioritized remediation summary
  • Clickable rettecnologia.org links throughout the document

© 2026 RET Tecnologia. All rights reserved.
SPDX-License-Identifier: MIT
"""

import datetime
import html as html_mod
import io
import os
from typing import Any

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Optional: QR Code (graceful degradation if not installed)
try:
    import qrcode
    import qrcode.image.pil

    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

# ═══════════════════════════════════════════════════════════════════════
# DESIGN SYSTEM — 2026 Premium Palette
# Inspired by: Business Navy + Ice Blue + Champagne Gold
# ═══════════════════════════════════════════════════════════════════════

# Primary
NAVY = colors.HexColor("#0D1B2A")
NAVY_LIGHT = colors.HexColor("#1B2838")
STEEL = colors.HexColor("#415A77")
ICE_BLUE = colors.HexColor("#778DA9")

# Accents
CYAN_NEON = colors.HexColor("#00D4FF")
GOLD = colors.HexColor("#C89F5D")
CREAM = colors.HexColor("#F2EEE9")

# Severity palette (CVSS-aligned)
SEV_CRITICAL = colors.HexColor("#DC3545")
SEV_HIGH = colors.HexColor("#FD7E14")
SEV_MEDIUM = colors.HexColor("#FFC107")
SEV_LOW = colors.HexColor("#0DCAF0")
SEV_INFO = colors.HexColor("#6C757D")

SEVERITY_MAP = {
    "CRITICO": (
        SEV_CRITICAL,
        "9.0 – 10.0",
        "Comprometimento total. Exfiltração de dados, RCE, ou bypass de autenticação.",
    ),
    "ALTO": (SEV_HIGH, "7.0 – 8.9", "Acesso não autorizado, escalação de privilégios, ou exposição massiva."),
    "MEDIO": (SEV_MEDIUM, "4.0 – 6.9", "Information disclosure, bypass parcial, ou configuração insegura."),
    "BAIXO": (SEV_LOW, "0.1 – 3.9", "Configuração subótima, risco mitigado por controles existentes."),
    "INFO": (SEV_INFO, "0.0", "Achado informacional sem impacto direto na segurança."),
}

# Typography
FONT_BOLD = "Helvetica-Bold"
FONT_REG = "Helvetica"
FONT_MONO = "Courier"

VERSION = "3.0.1"
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(BASE_PATH, "docs", "cascavel_logo.png")


def _sanitize_html(text: str) -> str:
    """Sanitiza texto não confiável para uso em reportlab Paragraph.

    CVE-2023-33733: reportlab Paragraph()/rl_safe_eval permite RCE via
    HTML injection em atributos como color/src de tags <img>/<font>.
    Essa função escapa TODAS as entidades HTML, prevenindo injeção.
    """
    if not isinstance(text, str):
        text = str(text)
    # Escape HTML entities: < > & " '
    safe = html_mod.escape(text, quote=True)
    # Truncar para evitar PDFs gigantes com output malicioso
    return safe[:5000]


# ═══════════════════════════════════════════════════════════════════════
# COMPANY BRANDING
# ═══════════════════════════════════════════════════════════════════════

COMPANY_NAME = "RET Tecnologia"
COMPANY_SITE = "rettecnologia.org"
COMPANY_TAGLINE = "Engenharia de Software & Cibersegurança Ofensiva"
COMPANY_CNPJ = ""  # Client fills if needed
FOUNDER = "Gabriel L. Ferreira"
FOUNDER_TITLE = "Fundador & DevSecOps Lead"


# ═══════════════════════════════════════════════════════════════════════
# CUSTOM STYLES
# ═══════════════════════════════════════════════════════════════════════


def _build_styles():
    """Build premium paragraph styles aligned with 2026 design standards."""
    s = getSampleStyleSheet()

    def _add(name, **kw):
        if name in [st.name for st in s.byName.values()]:
            return
        s.add(ParagraphStyle(name, **kw))

    # Cover
    _add("CoverTitle", fontName=FONT_BOLD, fontSize=32, textColor=NAVY, alignment=TA_CENTER, spaceAfter=6, leading=38)
    _add("CoverSub", fontName=FONT_REG, fontSize=14, textColor=STEEL, alignment=TA_CENTER, spaceAfter=4, leading=18)
    _add("CoverMeta", fontName=FONT_REG, fontSize=10, textColor=ICE_BLUE, alignment=TA_CENTER, spaceAfter=3)

    # Section titles
    _add(
        "SectionH1",
        fontName=FONT_BOLD,
        fontSize=16,
        textColor=NAVY,
        spaceBefore=18,
        spaceAfter=10,
        leading=20,
        borderWidth=0,
        borderPadding=0,
    )
    _add("SectionH2", fontName=FONT_BOLD, fontSize=12, textColor=STEEL, spaceBefore=12, spaceAfter=6, leading=16)

    # Body — with widows/orphans control
    _add(
        "Body",
        fontName=FONT_REG,
        fontSize=9.5,
        textColor=colors.black,
        alignment=TA_JUSTIFY,
        spaceBefore=3,
        spaceAfter=3,
        leading=13,
        allowWidows=0,
        allowOrphans=0,
    )
    _add(
        "BodySmall",
        fontName=FONT_REG,
        fontSize=8,
        textColor=colors.black,
        alignment=TA_JUSTIFY,
        spaceBefore=2,
        spaceAfter=2,
        leading=11,
        allowWidows=0,
        allowOrphans=0,
    )

    # Legal — with widows/orphans control
    _add(
        "Legal",
        fontName=FONT_REG,
        fontSize=7,
        textColor=ICE_BLUE,
        alignment=TA_JUSTIFY,
        spaceBefore=1,
        spaceAfter=1,
        leading=9.5,
        allowWidows=0,
        allowOrphans=0,
    )

    # Links — clickable style for URLs
    _add(
        "Link",
        fontName=FONT_REG,
        fontSize=8,
        textColor=colors.HexColor("#0066CC"),
        alignment=TA_LEFT,
        spaceBefore=1,
        spaceAfter=1,
        leading=10,
    )
    _add("LegalTitle", fontName=FONT_BOLD, fontSize=8, textColor=NAVY, spaceBefore=6, spaceAfter=2, leading=10)

    # Code
    _add(
        "Code",
        fontName=FONT_MONO,
        fontSize=7.5,
        textColor=colors.black,
        backColor=colors.HexColor("#F6F8FA"),
        borderWidth=0.5,
        borderColor=colors.HexColor("#D0D7DE"),
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=4,
        leading=10,
    )

    # Footer
    _add("Footer", fontName=FONT_REG, fontSize=7, textColor=ICE_BLUE, alignment=TA_CENTER)

    return s


# ═══════════════════════════════════════════════════════════════════════
# PAGE TEMPLATE — Premium Header/Footer
# ═══════════════════════════════════════════════════════════════════════


class _NumberedCanvas(canvas.Canvas):
    """Canvas subclass that tracks total page count for 'Page X of Y' footer.

    Uses the two-pass technique: first pass renders all pages,
    second pass stamps total count on each page.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list = []

    def showPage(self):  # noqa: N802 — ReportLab override
        self._saved_page_states.append(dict(self.__dict__))
        super().showPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(total)
            super().showPage()
        super().save()

    def draw_page_number(self, total: int):
        """Stamp 'Página X de Y' on each page (overwrites placeholder)."""
        w, _ = A4
        self.saveState()
        self.setFillColor(ICE_BLUE)
        self.setFont(FONT_REG, 6)
        self.drawRightString(w - 12 * mm, 8 * mm, f"Página {self._pageNumber} de {total}")
        self.restoreState()


class _PremiumPageTemplate:
    """Custom header/footer rendering for every page (except cover).

    2026 Elite features:
      • Header bar with CASCAVEL branding + target info
      • Gold classification stripe
      • Diagonal CONFIDENCIAL watermark (50% opacity)
      • Footer with copyright + clickable rettecnologia.org link
      • 'Página X de Y' via _NumberedCanvas two-pass
    """

    def __init__(self, target: str, report_id: str, classification: str = "CONFIDENCIAL"):
        self.target = target
        self.report_id = report_id
        self.classification = classification

    def on_first_page(self, c: canvas.Canvas, doc):
        """Cover page has no header/footer."""
        pass

    def on_later_pages(self, c: canvas.Canvas, doc):
        """Premium header + footer with classification watermark."""
        c.saveState()
        w, h = A4

        # ── Diagonal watermark ──
        c.saveState()
        c.setFillColor(colors.Color(0.85, 0.85, 0.85, alpha=0.15))
        c.setFont(FONT_BOLD, 60)
        c.translate(w / 2, h / 2)
        c.rotate(45)
        c.drawCentredString(0, 0, self.classification)
        c.restoreState()

        # ── Header bar ──
        c.setFillColor(NAVY)
        c.rect(0, h - 18 * mm, w, 18 * mm, fill=True)

        # Logo text
        c.setFillColor(CYAN_NEON)
        c.setFont(FONT_BOLD, 9)
        c.drawString(12 * mm, h - 12 * mm, f"CASCAVEL v{VERSION}")

        c.setFillColor(colors.HexColor("#FFFFFF80"))
        c.setFont(FONT_REG, 7)
        c.drawString(12 * mm, h - 15.5 * mm, f"{COMPANY_NAME} — {COMPANY_TAGLINE}")

        # Right side
        c.setFillColor(colors.white)
        c.setFont(FONT_REG, 7)
        c.drawRightString(w - 12 * mm, h - 12 * mm, f"Target: {self.target}")
        c.drawRightString(w - 12 * mm, h - 15.5 * mm, f"Report: {self.report_id}")

        # ── Classification stripe ──
        c.setFillColor(GOLD)
        c.rect(0, h - 21 * mm, w, 3 * mm, fill=True)
        c.setFillColor(NAVY)
        c.setFont(FONT_BOLD, 6)
        c.drawCentredString(w / 2, h - 20.5 * mm, self.classification)

        # ── Footer ──
        c.setStrokeColor(ICE_BLUE)
        c.setLineWidth(0.3)
        c.line(12 * mm, 12 * mm, w - 12 * mm, 12 * mm)

        c.setFillColor(ICE_BLUE)
        c.setFont(FONT_REG, 6)
        footer_txt = (
            f"© {datetime.datetime.now().year} {COMPANY_NAME}"
            f" — https://{COMPANY_SITE}"
            f" — Documento {self.classification}"
        )
        c.drawString(12 * mm, 8 * mm, footer_txt)
        # Note: "Página X de Y" is stamped by _NumberedCanvas.draw_page_number()

        c.restoreState()


# ═══════════════════════════════════════════════════════════════════════
# RISK MATRIX DRAWING
# ═══════════════════════════════════════════════════════════════════════


def _build_risk_matrix_drawing(sev_counts: dict) -> Drawing:
    """Build a visual risk matrix (Likelihood x Impact) as a reportlab Drawing."""
    d = Drawing(250, 120)

    # Background
    d.add(Rect(0, 0, 250, 120, fillColor=colors.HexColor("#F6F8FA"), strokeColor=None))

    # Grid cells (5x1 horizontal bar chart style)
    severities = ["INFO", "BAIXO", "MEDIO", "ALTO", "CRITICO"]
    sev_colors = [SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL]
    bar_width = 40
    gap = 6
    max_count = max(sev_counts.values()) if sev_counts.values() else 1
    if max_count == 0:
        max_count = 1

    for i, sev in enumerate(severities):
        x = 15 + i * (bar_width + gap)
        count = sev_counts.get(sev, 0)
        bar_h = max(4, (count / max_count) * 70)

        # Bar
        d.add(Rect(x, 25, bar_width, bar_h, fillColor=sev_colors[i], strokeColor=None, rx=3, ry=3))

        # Count label
        d.add(
            String(
                x + bar_width / 2,
                27 + bar_h,
                str(count),
                fontName=FONT_BOLD,
                fontSize=8,
                textAnchor="middle",
                fillColor=NAVY,
            )
        )

        # Severity label
        d.add(
            String(x + bar_width / 2, 10, sev[:4], fontName=FONT_BOLD, fontSize=6, textAnchor="middle", fillColor=STEEL)
        )

    # Title
    d.add(
        String(
            125, 107, "DISTRIBUIÇÃO DE SEVERIDADE", fontName=FONT_BOLD, fontSize=7, textAnchor="middle", fillColor=NAVY
        )
    )

    return d


# ═══════════════════════════════════════════════════════════════════════
# LEGAL DISCLAIMERS — 12 Cláusulas
# ═══════════════════════════════════════════════════════════════════════


def _build_disclaimers(company: str, now: datetime.datetime) -> list:
    """Return list of (title, text) tuples for 12 legal disclaimer clauses."""
    year = now.year
    return [
        (
            "1. Confidencialidade e Classificação",
            f"Este documento é classificado como CONFIDENCIAL e é propriedade exclusiva de {company} "
            f"e do destinatário autorizado (doravante 'Cliente'). A reprodução, distribuição, "
            f"transmissão ou divulgação total ou parcial deste relatório, por qualquer meio, sem "
            f"autorização prévia por escrito, é estritamente proibida e constitui violação de "
            f"acordo de confidencialidade (NDA) e da legislação aplicável.",
        ),
        (
            "2. Escopo e Limitações da Avaliação",
            "Os testes foram conduzidos exclusivamente dentro do escopo previamente acordado "
            "entre as partes via Statement of Work (SOW). Este relatório reflete a postura "
            "de segurança dos sistemas avaliados no momento específico da análise e não "
            "constitui garantia de segurança futura. Vulnerabilidades não detectadas não "
            "implicam inexistência das mesmas. Ameaças de segurança são dinâmicas e novas "
            "vulnerabilidades podem emergir após a data desta avaliação.",
        ),
        (
            "3. Autorização Formal e Base Legal",
            "Todos os testes foram realizados com autorização explícita, formal e documentada "
            "do proprietário do sistema ou de pessoa com poderes legais para tal. Os testes "
            "foram conduzidos em estrita conformidade com a legislação brasileira vigente, "
            "incluindo: Marco Civil da Internet (Lei nº 12.965/2014), Lei Geral de Proteção "
            "de Dados — LGPD (Lei nº 13.709/2018), Código Penal Brasileiro (Art. 154-A — "
            "Invasão de dispositivo informático), e o Projeto de Lei nº 4752/2025 "
            "(Framework Nacional de Cibersegurança — ANC).",
        ),
        (
            "4. Limitação de Responsabilidade",
            f"Na extensão máxima permitida pela legislação aplicável, {company} não será "
            f"responsável por quaisquer danos diretos, indiretos, incidentais, especiais, "
            f"consequentes ou exemplares, incluindo, sem limitação, danos por perda de lucros, "
            f"fundo de comércio, uso, dados ou outras perdas intangíveis, resultantes dos "
            f"serviços de teste de penetração ou do uso das informações contidas neste relatório. "
            f"A responsabilidade total de {company} não excederá o valor pago pelo Cliente "
            f"pelos serviços específicos prestados sob o contrato vigente.",
        ),
        (
            "5. Ausência de Garantias",
            f"Este relatório é fornecido 'COMO ESTÁ' (AS IS), sem quaisquer garantias ou "
            f"representações, expressas ou implícitas. {company} não garante, representa ou "
            f"certifica que os sistemas testados estejam 100% seguros, livres de todos os "
            f"defeitos, ou em conformidade com quaisquer padrões da indústria após a remediação "
            f"das vulnerabilidades identificadas. Nenhum teste de penetração pode garantir "
            f"segurança absoluta.",
        ),
        (
            "6. Responsabilidade de Remediação do Cliente",
            f"O Cliente reconhece e concorda que a implementação das recomendações e a "
            f"remediação das vulnerabilidades identificadas é de sua exclusiva responsabilidade. "
            f"{company} não é responsável pela falha do Cliente em implementar as medidas de "
            f"remediação sugeridas ou por quaisquer incidentes de segurança subsequentes que "
            f"possam decorrer de vulnerabilidades não remediadas.",
        ),
        (
            "7. Reconhecimento de Riscos Inerentes",
            f"O Cliente reconhece que serviços de teste de penetração envolvem tentativas "
            f"intencionais de explorar vulnerabilidades, o que pode acarretar riscos inerentes, "
            f"incluindo potencial instabilidade de sistemas, indisponibilidade temporária, ou "
            f"corrupção não intencional de dados. O Cliente concorda em assumir esses riscos "
            f"e eximir {company} de qualquer responsabilidade por danos resultantes da execução "
            f"dos serviços dentro do escopo e metodologia acordados.",
        ),
        (
            "8. Conformidade Regulatória e Frameworks",
            f"Este relatório foi elaborado em alinhamento com os seguintes frameworks e "
            f"padrões internacionais de segurança: OWASP Web Security Testing Guide v4.2, "
            f"OWASP Top 10 ({year}), PTES (Penetration Testing Execution Standard), "
            f"NIST SP 800-115 (Technical Guide to Information Security Testing), "
            f"ISO/IEC 27001:2022 (Information Security Management), "
            f"ISO/IEC 27005:2022 (Information Security Risk Management), "
            f"PCI DSS v4.0 (quando aplicável), e CVSS v4.0 (Common Vulnerability Scoring System).",
        ),
        (
            "9. Proteção de Dados Pessoais (LGPD)",
            f"Quaisquer dados pessoais eventualmente coletados durante a execução dos testes "
            f"foram tratados em conformidade com a LGPD (Lei nº 13.709/2018). {company} "
            f"compromete-se a: (i) não armazenar dados pessoais além do estritamente necessário "
            f"para a elaboração deste relatório; (ii) eliminar dados residuais em até 30 dias "
            f"após a entrega; (iii) notificar imediatamente o Cliente e a ANPD em caso de "
            f"incidente de segurança envolvendo dados pessoais, conforme Art. 48 da LGPD.",
        ),
        (
            "10. Retenção e Destruição de Evidências",
            "Este relatório e suas evidências associadas devem ser armazenados em ambiente "
            "seguro com controles de acesso adequados (criptografia AES-256, MFA, least "
            "privilege). Recomenda-se a destruição segura (NIST SP 800-88 Rev.1) deste "
            "documento e de todas as cópias após a remediação completa das vulnerabilidades "
            "ou após o período de retenção acordado contratualmente, o que ocorrer primeiro.",
        ),
        (
            "11. Propriedade Intelectual",
            f"As metodologias, ferramentas proprietárias, scripts e técnicas utilizadas na "
            f"condução dos testes constituem propriedade intelectual de {company} — protegidas "
            f"pela Lei de Propriedade Industrial (Lei nº 9.279/1996) e Lei de Direito Autoral "
            f"(Lei nº 9.610/1998). O Cliente não adquire direitos sobre tais ativos pelo "
            f"recebimento deste relatório.",
        ),
        (
            "12. Aviso Jurídico Final",
            "Este relatório e seus disclaimers são fornecidos para fins informativos "
            "e técnicos, não constituindo aconselhamento jurídico. Recomenda-se que o Cliente "
            "consulte assessoria jurídica própria para questões legais específicas. A jurisdição "
            "para resolução de quaisquer disputas é o Foro da Comarca da cidade do contratante, "
            "com renúncia a qualquer outro, por mais privilegiado que seja.",
        ),
    ]


# ═══════════════════════════════════════════════════════════════════════
# COMPLIANCE MAPPING
# ═══════════════════════════════════════════════════════════════════════

COMPLIANCE_FRAMEWORKS = [
    ("OWASP Top 10", "A01–A10 (2021/2025)", "Mapeamento de achados contra categorias OWASP"),
    ("CVSS v4.0", "FIRST.org", "Scoring padronizado de severidade"),
    ("NIST SP 800-115", "NIST", "Guia técnico para testes de segurança"),
    ("ISO/IEC 27001:2022", "ISO", "Gestão de segurança da informação"),
    ("ISO/IEC 27005:2022", "ISO", "Gestão de riscos de segurança"),
    ("PCI DSS v4.0", "PCI SSC", "Segurança de dados de pagamento"),
    ("LGPD", "Lei 13.709/2018", "Proteção de dados pessoais"),
    ("Marco Civil", "Lei 12.965/2014", "Princípios do uso da Internet no Brasil"),
    ("PTES", "pentest-standard.org", "Padrão de execução de pentest"),
]


# ═══════════════════════════════════════════════════════════════════════
# REPORT BUILDER
# ═══════════════════════════════════════════════════════════════════════


def generate_pdf_report(
    target: str,
    scan_results: dict[str, Any],
    output_path: str | None = None,
    analyst_name: str | None = None,
    company: str | None = None,
    classification: str = "CONFIDENCIAL",
) -> str:
    """
    Generate a professional PDF pentest report.

    Args:
        target: The scan target (domain/IP)
        scan_results: Dict with keys: vulns, tools, plugins_count, duration
        output_path: Custom output path (default: reports/cascavel_YYYYMMDD_HHMMSS.pdf)
        analyst_name: Analyst name (default: FOUNDER)
        company: Company name (default: COMPANY_NAME)
        classification: Document classification level

    Returns:
        Absolute path to the generated PDF
    """
    styles = _build_styles()
    now = datetime.datetime.now()
    report_id = f"CSR-{now.strftime('%Y%m%d-%H%M%S')}"

    if analyst_name is None:
        analyst_name = FOUNDER
    if company is None:
        company = COMPANY_NAME

    if output_path is None:
        reports_dir = os.path.join(BASE_PATH, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        output_path = os.path.join(reports_dir, f"cascavel_{now.strftime('%Y%m%d_%H%M%S')}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=25 * mm,
        bottomMargin=18 * mm,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        title=f"Cascavel Security Report — {target}",
        author=company,
        subject=f"Penetration Test Report for {target}",
        creator=f"Cascavel v{VERSION} — {COMPANY_SITE}",
    )

    page_tpl = _PremiumPageTemplate(target, report_id, classification)
    story = []

    vulns = scan_results.get("vulns", [])
    duration = scan_results.get("duration", 0)
    plugins_count = scan_results.get("plugins_count", 84)
    tools_count = scan_results.get("tools_count", 0)

    # Count severities
    sev_count = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}
    for v in vulns:
        sev = v.get("severity", "INFO").upper()
        if sev in sev_count:
            sev_count[sev] += 1
    total_vulns = sum(sev_count.values())

    # ═══════════════════════════════════════════════════════════════════
    # PAGE 1: COVER
    # ═══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 30 * mm))

    # Logo
    if os.path.exists(LOGO_PATH):
        try:
            logo = Image(LOGO_PATH, width=55 * mm, height=55 * mm)
            logo.hAlign = "CENTER"
            story.append(logo)
            story.append(Spacer(1, 8 * mm))
        except Exception:
            pass

    story.append(Paragraph("CASCAVEL", styles["CoverTitle"]))
    story.append(Paragraph("Quantum Security Framework", styles["CoverSub"]))
    story.append(Spacer(1, 4 * mm))

    story.append(HRFlowable(width="50%", thickness=2, color=CYAN_NEON, spaceAfter=6, hAlign="CENTER"))

    story.append(Paragraph("RELATÓRIO DE ANÁLISE DE SEGURANÇA", styles["CoverSub"]))
    story.append(Spacer(1, 8 * mm))

    # Meta table — with clickable rettecnologia.org link
    empresa_link = Paragraph(
        f'{company} — <a href="https://{COMPANY_SITE}" color="#0066CC">{COMPANY_SITE}</a>',
        styles["Link"],
    )
    cover_rows = [
        ["Alvo", target],
        ["Report ID", report_id],
        ["Classificação", classification],
        ["Data", now.strftime("%d/%m/%Y — %H:%M:%S BRT")],
        ["Analista", f"{analyst_name}"],
        ["Empresa", empresa_link],
        ["Framework", f"Cascavel v{VERSION}"],
        ["Plugins Executados", str(plugins_count)],
        ["Ferramentas Externas", str(tools_count)],
        ["Duração do Scan", f"{round(duration, 1)}s"],
    ]
    cover_table = Table(cover_rows, colWidths=[50 * mm, 115 * mm])
    cover_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), FONT_BOLD),
                ("FONTNAME", (1, 0), (1, -1), FONT_REG),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.black),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, ICE_BLUE),
                ("LINEBELOW", (0, -1), (-1, -1), 1, CYAN_NEON),
                ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    cover_table.hAlign = "CENTER"
    story.append(cover_table)

    # QR Code linking to rettecnologia.org (graceful degradation)
    if HAS_QRCODE:
        try:
            qr = qrcode.QRCode(version=1, box_size=4, border=2)
            qr.add_data(f"https://{COMPANY_SITE}")
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="#0D1B2A", back_color="white")
            qr_buffer = io.BytesIO()
            qr_img.save(qr_buffer, format="PNG")
            qr_buffer.seek(0)
            qr_flowable = Image(qr_buffer, width=22 * mm, height=22 * mm)
            qr_flowable.hAlign = "CENTER"
            story.append(Spacer(1, 4 * mm))
            story.append(qr_flowable)
            story.append(
                Paragraph(
                    f'<a href="https://{COMPANY_SITE}" color="#0066CC">{COMPANY_SITE}</a>',
                    styles["Link"],
                )
            )
        except Exception:
            pass

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # PAGE 2: TABLE OF CONTENTS
    # ═══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("ÍNDICE", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    toc_items = [
        "1. Disclaimer Jurídico e Termos de Uso",
        "2. Sumário Executivo",
        "3. Matriz de Risco e Severidade",
        "4. Achados Detalhados",
        "5. Sumário de Remediação Priorizado",
        "6. Mapeamento de Compliance",
        "7. Metodologia",
        "8. Ferramentas Utilizadas",
        "9. Glossário de Termos de Segurança",
        "10. Histórico de Revisões",
        "11. Assinatura e Validação",
    ]
    for item in toc_items:
        story.append(Paragraph(item, styles["Body"]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # PAGE 3-4: LEGAL DISCLAIMERS (12 cláusulas)
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("1. DISCLAIMER JURÍDICO E TERMOS DE USO", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    disclaimers = _build_disclaimers(company, now)
    for title, text in disclaimers:
        story.append(Paragraph(title, styles["LegalTitle"]))
        story.append(Paragraph(text, styles["Legal"]))

    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=ICE_BLUE, spaceAfter=4))
    story.append(
        Paragraph(
            f"<i>© {now.year} {company}. Todos os direitos reservados. "
            f"Gerado por Cascavel v{VERSION} — {COMPANY_SITE}.</i>",
            styles["Legal"],
        )
    )

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # PAGE 5: EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("2. SUMÁRIO EXECUTIVO", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    # Risk posture
    if sev_count["CRITICO"] > 0:
        posture = "CRÍTICA — Ação imediata necessária"
        posture_color = SEV_CRITICAL
    elif sev_count["ALTO"] > 0:
        posture = "ELEVADA — Remediação prioritária recomendada"
        posture_color = SEV_HIGH
    elif sev_count["MEDIO"] > 0:
        posture = "MODERADA — Melhorias recomendadas"
        posture_color = SEV_MEDIUM
    elif sev_count["BAIXO"] > 0:
        posture = "ACEITÁVEL — Ajustes menores sugeridos"
        posture_color = SEV_LOW
    else:
        posture = "SAUDÁVEL — Nenhuma vulnerabilidade identificada"
        posture_color = colors.HexColor("#28A745")

    # Posture badge
    posture_data = [[f"POSTURA DE SEGURANÇA: {posture}"]]
    posture_badge = Table(posture_data, colWidths=[170 * mm])
    posture_badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), posture_color),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("FONTNAME", (0, 0), (0, 0), FONT_BOLD),
                ("FONTSIZE", (0, 0), (0, 0), 10),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("TOPPADDING", (0, 0), (0, 0), 8),
                ("BOTTOMPADDING", (0, 0), (0, 0), 8),
            ]
        )
    )
    posture_badge.hAlign = "CENTER"
    story.append(posture_badge)
    story.append(Spacer(1, 6 * mm))

    summary_text = (
        f"A análise de segurança automatizada do alvo <b>{target}</b> foi conduzida "
        f"utilizando o Cascavel Quantum Security Framework v{VERSION}, operado por "
        f"<b>{company}</b>. Foram executados <b>{plugins_count}</b> plugins de segurança "
        f"especializados e <b>{tools_count}</b> ferramentas externas em um período de "
        f"<b>{round(duration, 1)} segundos</b>. "
        f"Ao total, <b>{total_vulns}</b> achados foram identificados e categorizados "
        f"conforme a escala CVSS v4.0."
    )
    story.append(Paragraph(summary_text, styles["Body"]))
    story.append(Spacer(1, 6 * mm))

    # Severity breakdown table
    story.append(Paragraph("Distribuição por Severidade", styles["SectionH2"]))
    sev_data = [["Severidade", "CVSS Range", "Quantidade", "Descrição de Impacto"]]
    for sev_name in ["CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"]:
        count = sev_count.get(sev_name, 0)
        color, cvss_range, desc = SEVERITY_MAP[sev_name]
        sev_data.append([sev_name, cvss_range, str(count), desc])

    sev_table = Table(sev_data, colWidths=[25 * mm, 25 * mm, 20 * mm, 112 * mm], repeatRows=1)
    sev_style = [
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.3, ICE_BLUE),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CREAM]),
    ]
    for row_idx in range(1, len(sev_data)):
        sev_name_cell = sev_data[row_idx][0]
        if sev_name_cell in SEVERITY_MAP:
            sev_style.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), SEVERITY_MAP[sev_name_cell][0]))
            sev_style.append(("FONTNAME", (0, row_idx), (0, row_idx), FONT_BOLD))
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # PAGE 6: RISK MATRIX
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("3. MATRIZ DE RISCO E SEVERIDADE", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    # Visual chart
    risk_drawing = _build_risk_matrix_drawing(sev_count)
    risk_drawing.hAlign = "CENTER"
    story.append(risk_drawing)
    story.append(Spacer(1, 8 * mm))

    # CVSS explanation
    story.append(Paragraph("Escala CVSS v4.0 (Common Vulnerability Scoring System)", styles["SectionH2"]))
    cvss_text = (
        "O CVSS é um framework padronizado do FIRST.org para atribuição de scores numéricos (0.0–10.0) "
        "a vulnerabilidades, refletindo sua severidade técnica. Os scores são calculados com base em "
        "métricas de Base (complexidade de ataque, privilégios necessários, impacto em confidencialidade, "
        "integridade e disponibilidade), métricas Temporais (maturidade do exploit, nível de remediação) "
        "e métricas Ambientais (criticidade do ativo para o negócio do Cliente)."
    )
    story.append(Paragraph(cvss_text, styles["BodySmall"]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # PAGE 7+: DETAILED FINDINGS
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("4. ACHADOS DETALHADOS", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    if vulns:
        for idx, vuln in enumerate(vulns, 1):
            name = vuln.get("plugin", vuln.get("name", f"Achado #{idx}"))
            severity = vuln.get("severity", "INFO").upper()
            details = vuln.get("details", vuln.get("description", ""))
            evidence = vuln.get("evidence", "")
            remediation = vuln.get("remediation", vuln.get("fix", ""))
            refs = vuln.get("references", [])
            owasp_cat = vuln.get("owasp", "")

            sev_color = SEVERITY_MAP.get(severity, (SEV_INFO, "", ""))[0]
            cvss_range = SEVERITY_MAP.get(severity, (SEV_INFO, "N/A", ""))[1]

            card = []

            # Title with severity badge
            title_data = [[f"#{idx}", name, f"{severity} (CVSS {cvss_range})"]]
            title_table = Table(title_data, colWidths=[12 * mm, 115 * mm, 55 * mm])
            title_table.setStyle(
                TableStyle(
                    [
                        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
                        ("FONTSIZE", (0, 0), (1, 0), 9),
                        ("FONTSIZE", (2, 0), (2, 0), 8),
                        ("TEXTCOLOR", (0, 0), (0, 0), NAVY),
                        ("TEXTCOLOR", (1, 0), (1, 0), NAVY),
                        ("BACKGROUND", (2, 0), (2, 0), sev_color),
                        ("TEXTCOLOR", (2, 0), (2, 0), colors.white),
                        ("ALIGN", (2, 0), (2, 0), "CENTER"),
                        ("TOPPADDING", (0, 0), (-1, 0), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
                        ("LINEBELOW", (0, 0), (-1, 0), 1, sev_color),
                        ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
                    ]
                )
            )
            card.append(title_table)

            if owasp_cat:
                card.append(Paragraph(f"<b>OWASP:</b> {_sanitize_html(owasp_cat)}", styles["BodySmall"]))

            if details:
                card.append(Paragraph("<b>Descrição:</b>", styles["BodySmall"]))
                card.append(Paragraph(_sanitize_html(str(details)), styles["Body"]))

            if evidence:
                card.append(Paragraph("<b>Evidência:</b>", styles["BodySmall"]))
                card.append(Paragraph(_sanitize_html(str(evidence)), styles["Code"]))

            if remediation:
                card.append(Paragraph("<b>Remediação Recomendada:</b>", styles["BodySmall"]))
                card.append(Paragraph(_sanitize_html(str(remediation)), styles["Body"]))

            if refs:
                card.append(Paragraph("<b>Referências:</b>", styles["BodySmall"]))
                for ref in refs[:5]:
                    safe_ref = _sanitize_html(str(ref))
                    card.append(
                        Paragraph(
                            f'• <a href="{safe_ref}" color="#0066CC">{safe_ref}</a>',
                            styles["Legal"],
                        )
                    )

            card.append(Spacer(1, 5 * mm))
            story.append(KeepTogether(card))
    else:
        story.append(
            Paragraph(
                "✓ Nenhuma vulnerabilidade identificada durante esta avaliação.",
                styles["Body"],
            )
        )

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 5: PRIORITIZED REMEDIATION SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("5. SUMÁRIO DE REMEDIAÇÃO PRIORIZADO", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    story.append(
        Paragraph(
            "Tabela consolidada de ações de remediação ordenadas por severidade "
            "(CRÍTICO → INFO), com estimativa de esforço e prazo recomendado.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 4 * mm))

    remediation_header = ["#", "Achado", "Severidade", "Ação Recomendada", "Esforço", "Prazo"]
    remediation_rows = [remediation_header]

    effort_map = {"CRITICO": "Alto", "ALTO": "Alto", "MEDIO": "Médio", "BAIXO": "Baixo", "INFO": "Mínimo"}
    deadline_map = {"CRITICO": "24h", "ALTO": "72h", "MEDIO": "2 semanas", "BAIXO": "30 dias", "INFO": "Backlog"}

    # Sort vulns by severity priority
    sev_priority = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}
    sorted_vulns = sorted(vulns, key=lambda v: sev_priority.get(v.get("severity", "INFO").upper(), 4))

    for idx, vuln in enumerate(sorted_vulns, 1):
        name = vuln.get("plugin", vuln.get("name", f"Achado #{idx}"))
        severity = vuln.get("severity", "INFO").upper()
        remediation = vuln.get("remediation", vuln.get("fix", "Avaliar e corrigir."))
        effort = effort_map.get(severity, "Médio")
        deadline = deadline_map.get(severity, "30 dias")
        # Truncate remediation text for table cell
        rem_short = str(remediation)[:120] + ("..." if len(str(remediation)) > 120 else "")
        remediation_rows.append([str(idx), name[:30], severity, rem_short, effort, deadline])

    if not vulns:
        remediation_rows.append(["—", "Nenhum achado", "—", "N/A", "—", "—"])

    rem_table = Table(
        remediation_rows,
        colWidths=[8 * mm, 30 * mm, 20 * mm, 80 * mm, 18 * mm, 18 * mm],
        repeatRows=1,
    )
    rem_style = [
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, ICE_BLUE),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CREAM]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (4, 0), (5, -1), "CENTER"),
    ]
    # Color-code severity column
    for row_idx in range(1, len(remediation_rows)):
        sev_val = remediation_rows[row_idx][2]
        if sev_val in SEVERITY_MAP:
            sev_color = SEVERITY_MAP[sev_val][0]
            rem_style.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), sev_color))
            rem_style.append(("FONTNAME", (2, row_idx), (2, row_idx), FONT_BOLD))
    rem_table.setStyle(TableStyle(rem_style))
    story.append(rem_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # COMPLIANCE MAPPING
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("6. MAPEAMENTO DE COMPLIANCE", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    comp_data = [["Framework", "Referência", "Aplicação"]]
    for fw, ref, app in COMPLIANCE_FRAMEWORKS:
        comp_data.append([fw, ref, app])

    comp_table = Table(comp_data, colWidths=[40 * mm, 42 * mm, 100 * mm], repeatRows=1)
    comp_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, ICE_BLUE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CREAM]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(comp_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # METHODOLOGY
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("7. METODOLOGIA", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    phases = [
        (
            "Fase 1 — Reconhecimento",
            (
                "Coleta passiva e ativa: DNS enumeration, subdomain discovery (subfinder), WHOIS, "
                "fingerprinting de tecnologias (httpx/wappalyzer), port scanning (nmap/naabu), "
                "banner grabbing, OSINT e coleta de surface area."
            ),
        ),
        (
            "Fase 2 — Enumeração",
            (
                "Identificação de serviços expostos, endpoints web, APIs, versões de software, "
                "configurações de segurança (headers, CORS, CSP, HSTS), e vetores de ataque "
                "potenciais via 84 plugins especializados."
            ),
        ),
        (
            "Fase 3 — Análise de Vulnerabilidades",
            (
                "Teste automatizado contra CVEs conhecidas (nuclei templates), misconfigurations, "
                "injection vectors (SQLi, XSS, SSRF, XXE, RCE, SSTI, LFI/RFI), "
                "problemas criptográficos (TLS/SSL), e falhas de autenticação/autorização."
            ),
        ),
        (
            "Fase 4 — Exploração Controlada",
            (
                "Validação de vulnerabilidades com técnicas de baixo impacto — detecção passiva, "
                "sem payload destrutivo, garantindo zero falso positivo e zero dano à infraestrutura "
                "do Cliente. Todos os testes seguem o princípio do mínimo privilégio necessário."
            ),
        ),
        (
            "Fase 5 — Relatório e Entrega",
            (
                "Geração automatizada de relatório profissional em PDF com CVSS scoring, "
                "compliance mapping, evidências técnicas sanitizadas, recomendações de remediação "
                "priorizadas, e disclaimers legais completos."
            ),
        ),
    ]

    for title, desc in phases:
        story.append(Paragraph(title, styles["SectionH2"]))
        story.append(Paragraph(desc, styles["Body"]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # TOOLS
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("7. FERRAMENTAS UTILIZADAS", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    tools_rows = [["Ferramenta", "Categoria", "Propósito"]]
    tools_list = [
        ("Cascavel Core", "Framework", "Orquestração de plugins e análise centralizada"),
        ("Nmap / Naabu", "Scanner", "Port scanning e service detection"),
        ("Nuclei", "Scanner", "Vulnerability scanning com 10.000+ templates"),
        ("Subfinder", "OSINT", "Subdomain enumeration passiva"),
        ("HTTPx", "Probe", "HTTP probing, tech detection, status codes"),
        ("Katana", "Spider", "Web crawler e endpoint discovery"),
        ("SQLMap", "Exploit", "SQL injection detection e exploitation"),
        ("Nikto", "Scanner", "Web server vulnerability scanner"),
        ("Wafw00f", "Detection", "WAF fingerprinting"),
        ("Feroxbuster", "Scanner", "Forced browsing / directory brute-force"),
        ("84 Plugins", "Custom", "Módulos especializados de segurança da informação"),
    ]
    for t in tools_list:
        tools_rows.append(list(t))

    tools_table = Table(tools_rows, colWidths=[35 * mm, 28 * mm, 119 * mm], repeatRows=1)
    tools_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, ICE_BLUE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CREAM]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(tools_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 9: GLOSSARY — Security Terms
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("9. GLOSSÁRIO DE TERMOS DE SEGURANÇA", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    glossary = [
        (
            "CVSS",
            "Common Vulnerability Scoring System — sistema padronizado"
            " do FIRST.org para atribuir scores (0.0–10.0) a vulnerabilidades.",
        ),
        (
            "OWASP",
            "Open Worldwide Application Security Project — comunidade"
            " global que produz metodologias, ferramentas e documentação"
            " sobre segurança.",
        ),
        (
            "PTES",
            "Penetration Testing Execution Standard — padrão que define"
            " as fases e práticas para testes de intrusão profissionais.",
        ),
        (
            "NIST",
            "National Institute of Standards and Technology — agência"
            " dos EUA que publica frameworks de segurança (SP 800-xxx).",
        ),
        (
            "LGPD",
            "Lei Geral de Proteção de Dados (Lei nº 13.709/2018) —"
            " legislação brasileira de proteção de dados pessoais.",
        ),
        (
            "RCE",
            "Remote Code Execution — execução remota de código, permitindo ao atacante executar comandos no servidor.",
        ),
        (
            "XSS",
            "Cross-Site Scripting — injeção de scripts maliciosos em páginas web visualizadas por outros usuários.",
        ),
        (
            "SQLi",
            "SQL Injection — injeção de comandos SQL via input não"
            " sanitizado para acessar ou manipular banco de dados.",
        ),
        (
            "SSRF",
            "Server-Side Request Forgery — técnica que faz o servidor executar requisições HTTP maliciosas.",
        ),
        (
            "CORS",
            "Cross-Origin Resource Sharing — mecanismo de segurança"
            " do navegador que controla requisições entre domínios.",
        ),
        (
            "HSTS",
            "HTTP Strict Transport Security — header que força o uso exclusivo de HTTPS.",
        ),
        (
            "CSP",
            "Content Security Policy — header que restringe quais recursos um navegador pode carregar.",
        ),
        (
            "WAF",
            "Web Application Firewall — firewall de camada 7 que filtra tráfego HTTP malicioso.",
        ),
        (
            "SAST",
            "Static Application Security Testing — análise de segurança do código-fonte sem execução.",
        ),
        (
            "DAST",
            "Dynamic Application Security Testing — análise de segurança com a aplicação em execução.",
        ),
        (
            "PCI DSS",
            "Payment Card Industry Data Security Standard — padrão de"
            " segurança para organizações que lidam com dados de cartão.",
        ),
        (
            "ISO 27001",
            "Padrão internacional para Sistemas de Gestão de Segurança da Informação (SGSI).",
        ),
        (
            "Zero Trust",
            "Modelo de segurança que assume violação e verifica cada"
            " requisição como se viesse de uma rede não confiável.",
        ),
        (
            "Red Team",
            "Equipe que simula ataques reais contra uma organização para testar defesas e resposta a incidentes.",
        ),
        (
            "SARIF",
            "Static Analysis Results Interchange Format — formato JSON"
            " padronizado para resultados de ferramentas SAST.",
        ),
    ]

    glossary_data = [["Termo", "Definição"]]
    for term, definition in glossary:
        glossary_data.append([term, definition])

    glossary_table = Table(glossary_data, colWidths=[28 * mm, 154 * mm], repeatRows=1)
    glossary_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 1), (0, -1), FONT_BOLD),
                ("TEXTCOLOR", (0, 1), (0, -1), NAVY),
                ("GRID", (0, 0), (-1, -1), 0.3, ICE_BLUE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CREAM]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(glossary_table)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # SECTION 10: REVISION HISTORY
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("10. HISTÓRICO DE REVISÕES", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    revision_data = [
        ["Versão", "Data", "Autor", "Descrição"],
        ["1.0", now.strftime("%d/%m/%Y"), analyst_name, "Primeira versão do relatório — scan automatizado completo."],
    ]
    revision_table = Table(revision_data, colWidths=[18 * mm, 24 * mm, 40 * mm, 100 * mm], repeatRows=1)
    revision_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, ICE_BLUE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CREAM]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(revision_table)

    story.append(Spacer(1, 6 * mm))
    story.append(
        Paragraph(
            "Revisões futuras devem ser registradas nesta tabela com incremento de versão, "
            "data da revisão, nome do responsável e descrição das alterações realizadas.",
            styles["BodySmall"],
        )
    )

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════
    # SIGNATURE PAGE
    # ═══════════════════════════════════════════════════════════════════
    story.append(Paragraph("11. ASSINATURA E VALIDAÇÃO", styles["SectionH1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))

    story.append(Spacer(1, 8 * mm))

    sig_rows = [
        ["Campo", "Valor"],
        ["Empresa Responsável", f"{company}"],
        ["Website", f"{COMPANY_SITE}"],
        ["Analista Responsável", f"{analyst_name}"],
        ["Cargo", FOUNDER_TITLE],
        ["Data do Relatório", now.strftime("%d/%m/%Y")],
        ["Hora UTC", now.strftime("%H:%M:%S UTC-3")],
        ["Report ID", report_id],
        ["Framework", f"Cascavel v{VERSION}"],
        ["Classificação", classification],
    ]

    sig_table = Table(sig_rows, colWidths=[50 * mm, 132 * mm])
    sig_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.3, ICE_BLUE),
                ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ("FONTNAME", (0, 1), (0, -1), FONT_BOLD),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(sig_table)

    story.append(Spacer(1, 20 * mm))

    # Signature lines
    story.append(Paragraph("_" * 40, styles["CoverMeta"]))
    story.append(Paragraph(f"<b>{analyst_name}</b>", styles["CoverMeta"]))
    story.append(Paragraph(f"{FOUNDER_TITLE} — {company}", styles["CoverMeta"]))
    story.append(Paragraph(now.strftime("%d/%m/%Y"), styles["CoverMeta"]))

    story.append(Spacer(1, 15 * mm))

    # Document integrity hash
    integrity_note = (
        f"<b>Integridade do Documento:</b> Este relatório foi gerado automaticamente pelo "
        f"Cascavel v{VERSION}. A integridade pode ser verificada comparando o hash SHA-256 "
        f"do arquivo PDF com o hash registrado no sistema de controle de versão."
    )
    story.append(Paragraph(integrity_note, styles["Legal"]))

    story.append(Spacer(1, 8 * mm))

    # Final legal block
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceAfter=4))
    story.append(
        Paragraph(
            f"<b>AVISO LEGAL FINAL:</b> Este relatório foi gerado automaticamente pelo Cascavel "
            f"Quantum Security Framework v{VERSION}, produto de {company} "
            f'(<a href="https://{COMPANY_SITE}" color="#0066CC">{COMPANY_SITE}</a>). '
            f"As informações contidas neste documento são CONFIDENCIAIS e destinadas exclusivamente "
            f"ao uso do destinatário autorizado. A disseminação, distribuição ou cópia não autorizada "
            f"é proibida nos termos da legislação vigente. Caso tenha recebido este documento por "
            f"engano, notifique imediatamente o remetente e destrua todas as cópias.",
            styles["Legal"],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(
        Paragraph(
            f"© {now.year} {company}. Todos os direitos reservados. "
            f"MÉTODO CASCAVEL™ é marca registrada de "
            f'<a href="https://{COMPANY_SITE}" color="#0066CC">RET Tecnologia</a>. '
            f"Cascavel Framework é licenciado sob MIT. "
            f"O uso desta ferramenta para atividades ilegais ou não autorizadas é expressa "
            f"e irrevogavelmente proibido. Qualquer uso em desacordo com a legislação vigente "
            f"é de responsabilidade exclusiva do executor.",
            styles["Legal"],
        )
    )

    # ═══════════════════════════════════════════════════════════════════
    # BUILD PDF — Two-pass render for "Página X de Y" via _NumberedCanvas
    # ═══════════════════════════════════════════════════════════════════
    doc.build(
        story,
        onFirstPage=page_tpl.on_first_page,
        onLaterPages=page_tpl.on_later_pages,
        canvasmaker=_NumberedCanvas,
    )

    return os.path.abspath(output_path)


# ═══════════════════════════════════════════════════════════════════════
# STANDALONE GENERATION (for testing / template preview)
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sample_results = {
        "vulns": [
            {
                "plugin": "xss_scanner",
                "severity": "ALTO",
                "details": (
                    "Reflected XSS identificado no parâmetro de busca."
                    " Input do usuário é refletido na resposta sem sanitização adequada."
                ),
                "evidence": (
                    "GET /search?q=<script>alert(1)</script> → 200 OK\n"
                    "Response body contains: <script>alert(1)</script>"
                ),
                "remediation": (
                    "Implementar sanitização de input (escaping HTML)."
                    " Adicionar headers Content-Security-Policy."
                    " Utilizar frameworks com auto-escaping (React, Vue)."
                ),
                "references": [
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cwe.mitre.org/data/definitions/79.html",
                ],
                "owasp": "A03:2021 — Injection",
            },
            {
                "plugin": "ssl_analyzer",
                "severity": "MEDIO",
                "details": (
                    "TLS 1.0 ainda habilitado no servidor. Protocolo considerado inseguro desde 2018 (PCI DSS 3.2.1)."
                ),
                "evidence": ("TLSv1.0 handshake successful\nCipher: TLS_RSA_WITH_AES_128_CBC_SHA"),
                "remediation": (
                    "Desabilitar TLS 1.0 e 1.1. Configurar servidor"
                    " para aceitar apenas TLS 1.2+ com cipher suites modernas."
                ),
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"],
                "owasp": "A02:2021 — Cryptographic Failures",
            },
            {
                "plugin": "cors_checker",
                "severity": "ALTO",
                "details": (
                    "Política CORS wildcard detectada (Access-Control-Allow-Origin: *)."
                    " Permite que qualquer domínio faça requisições cross-origin."
                ),
                "evidence": ("Response header: Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"),
                "remediation": (
                    "Restringir CORS para origens confiáveis específicas."
                    " Nunca combinar wildcard com Allow-Credentials."
                ),
                "references": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                "owasp": "A05:2021 — Security Misconfiguration",
            },
            {
                "plugin": "header_audit",
                "severity": "BAIXO",
                "details": "Header X-Frame-Options ausente. O servidor não envia proteção contra clickjacking.",
                "evidence": (
                    "Response headers:\nServer: nginx/1.24.0\nContent-Type: text/html\n(X-Frame-Options: ABSENT)"
                ),
                "remediation": "Adicionar X-Frame-Options: DENY ou SAMEORIGIN. Considerar também CSP frame-ancestors.",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                "owasp": "A05:2021 — Security Misconfiguration",
            },
        ],
        "tools_count": 27,
        "plugins_count": 84,
        "duration": 187.4,
    }

    path = generate_pdf_report(
        target="rettecnologia.org",
        scan_results=sample_results,
    )
    print(f"✓ Report generated: {path}")
