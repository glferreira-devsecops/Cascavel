import os
import tempfile

from hypothesis import given
from hypothesis import strategies as st

from report_generator import (
    _build_risk_matrix_drawing,
    _sanitize_html,
    generate_pdf_report,
)


def test_sanitize_html():
    """Ensure HTML is properly sanitized."""
    assert _sanitize_html("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert _sanitize_html('onload="alert(1)"') == "onload=&quot;alert(1)&quot;"
    assert _sanitize_html("normal text") == "normal text"


@given(st.text())
def test_sanitize_html_fuzz(text):
    """Fuzz HTML sanitizer to ensure it never crashes."""
    sanitized = _sanitize_html(text)
    assert isinstance(sanitized, str)
    assert "<script" not in sanitized.lower() or "&lt;script" in sanitized.lower()


def test_build_risk_matrix_drawing():
    """Ensure risk matrix is built without crashing."""
    counts = {"CRITICO": 5, "ALTO": 10, "MEDIO": 2, "BAIXO": 0, "INFO": 1}
    drawing = _build_risk_matrix_drawing(counts)
    assert drawing is not None


def test_generate_pdf_report():
    """Test generating a PDF report successfully."""
    scan_results = {
        "vulns": [
            {
                "tipo": "XSS",
                "severity": "ALTO",
                "cwe": "CWE-79",
                "descricao": "Reflected XSS",
                "evidencia": "<script>alert(1)</script>",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            },
            {
                "tipo": "MISSING_HEADER",
                "severity": "INFO",
                "cwe": "CWE-200",
                "descricao": "Missing CSP",
                "cvss_score": 0.0,
            },
        ],
        "duration": 45.2,
        "plugins_count": 84,
        "tools_count": 5,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "test_report.pdf")
        result_path = generate_pdf_report(
            target="example.com",
            scan_results=scan_results,
            output_path=output_path,
            analyst_name="Test Analyst",
            company="Test Company",
            classification="CONFIDENCIAL",
        )

        assert os.path.exists(result_path)
        assert os.path.getsize(result_path) > 1000  # Should be a valid PDF size
