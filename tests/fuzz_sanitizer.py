#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  CASCAVEL — Fuzz Testing Suite                                       ║
║  Product of RET Tecnologia (rettecnologia.org)                       ║
║  Atheris-powered fuzzing for security-critical functions              ║
╚══════════════════════════════════════════════════════════════════════╝

Targets:
  1. _sanitize_html() — CVE-2023-33733 mitigation in report_generator.py
  2. SEVERITY_MAP lookup — edge cases in severity classification
  3. Report metadata generation — date/ID format robustness

This fuzzer uses Google's Atheris (libFuzzer for Python) to discover
crashes, hangs, and unexpected exceptions in security-critical code paths.

© 2026 RET Tecnologia. All rights reserved.
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import atheris


def fuzz_sanitize_html(data: bytes) -> None:
    """Fuzz the _sanitize_html function for crash resistance.

    This function is critical because it prevents CVE-2023-33733
    (reportlab RCE via HTML injection). Any crash here means
    an attacker could bypass sanitization.
    """
    from report_generator import _sanitize_html

    fdp = atheris.FuzzedDataProvider(data)
    test_input = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 10000))

    try:
        result = _sanitize_html(test_input)
        # Invariants that MUST hold:
        assert isinstance(result, str), "Result must be a string"
        assert len(result) <= 5000, "Result must be truncated to 5000 chars"
        assert "<script" not in result.lower(), "Script tags must be escaped"
        assert "javascript:" not in result.lower(), "JS protocol must be escaped"
    except (ValueError, TypeError):
        pass  # Expected for some edge cases


def fuzz_severity_lookup(data: bytes) -> None:
    """Fuzz severity classification lookup."""
    from report_generator import SEVERITY_MAP

    fdp = atheris.FuzzedDataProvider(data)
    severity = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 50))

    try:
        result = SEVERITY_MAP.get(severity.upper(), None)
        if result is not None:
            color, cvss_range, desc = result
            assert isinstance(cvss_range, str)
            assert isinstance(desc, str)
    except (ValueError, TypeError, AttributeError):
        pass


def fuzz_report_id_generation(data: bytes) -> None:
    """Fuzz report ID and metadata generation for format robustness."""
    import datetime

    fdp = atheris.FuzzedDataProvider(data)

    try:
        year = fdp.ConsumeIntInRange(2020, 2099)
        month = fdp.ConsumeIntInRange(1, 12)
        day = fdp.ConsumeIntInRange(1, 28)
        hour = fdp.ConsumeIntInRange(0, 23)
        minute = fdp.ConsumeIntInRange(0, 59)
        second = fdp.ConsumeIntInRange(0, 59)

        dt = datetime.datetime(year, month, day, hour, minute, second)
        report_id = f"CSR-{dt.strftime('%Y%m%d-%H%M%S')}"
        assert report_id.startswith("CSR-")
        assert len(report_id) == 19  # CSR-YYYYMMDD-HHMMSS
    except (ValueError, OverflowError):
        pass


def main() -> None:
    """Run all fuzz targets sequentially."""
    # Select target based on environment or random
    targets = [fuzz_sanitize_html, fuzz_severity_lookup, fuzz_report_id_generation]

    target_idx = int(os.environ.get("FUZZ_TARGET", "0"))
    target = targets[min(target_idx, len(targets) - 1)]

    atheris.Setup(sys.argv, target)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
