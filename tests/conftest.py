"""
Cascavel v3.0.0 — Test Fixtures
Shared fixtures for plugin and core tests.
"""

from __future__ import annotations

import os
import sys

import pytest

# Add project root to sys.path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture
def mock_target() -> str:
    """Standard test target (safe, non-routable)."""
    return "example.com"


@pytest.fixture
def mock_ip() -> str:
    """Standard test IP (documentation range, RFC 5737)."""
    return "192.0.2.1"


@pytest.fixture
def mock_ports() -> list[int]:
    """Common open ports for testing."""
    return [80, 443, 8080, 22, 3306]


@pytest.fixture
def mock_banners() -> dict[int, str]:
    """Mock banner grab results."""
    return {
        80: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.4\r\n",
        443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.59\r\n",
        8080: "HTTP/1.1 200 OK\r\nServer: Jetty/11.0.20\r\n",
        22: "SSH-2.0-OpenSSH_9.6",
        3306: "N/A",
    }


@pytest.fixture
def plugins_dir() -> str:
    """Path to the plugins directory."""
    return os.path.join(PROJECT_ROOT, "plugins")


@pytest.fixture
def profiles_dir() -> str:
    """Path to the profiles directory."""
    return os.path.join(PROJECT_ROOT, "profiles")
