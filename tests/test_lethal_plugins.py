from unittest.mock import MagicMock, patch

import plugins.broker_ssrf_relay as plugin_broker
import plugins.cloud_ghosting as plugin_cloud
import plugins.coerced_auth_web as plugin_coerced
import plugins.graphql_nuclear as plugin_graphql
import plugins.http2_rapid_reset as plugin_http2
import plugins.memshell_injector as plugin_memshell
import plugins.oidc_poisoning as plugin_oidc
import plugins.smtp_smuggling as plugin_smtp
import plugins.sspp_rce as plugin_sspp
import plugins.wasm_reverser as plugin_wasm

# Helper mock for socket
def mock_socket_response(resp_text: bytes):
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [resp_text, b""]
    mock_socket_class = MagicMock(return_value=mock_sock)
    return mock_socket_class

# Helper mock for requests if still used anywhere
def mock_requests_response(status_code: int, text: str):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = text
    mock_resp.content = text.encode()
    return mock_resp

# --- MEMSHELL INJECTOR ---
@patch("plugins.memshell_injector.requests.Session")
def test_memshell_injector_vulnerable(mock_session_class):
    mock_session = mock_session_class.return_value
    mock_session.post.return_value = mock_requests_response(200, "9801547")
    mock_session.get.return_value = mock_requests_response(200, "9801547")
    result = plugin_memshell.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.memshell_injector.requests.Session")
def test_memshell_injector_safe(mock_session_class):
    mock_session = mock_session_class.return_value
    mock_session.post.return_value = mock_requests_response(403, "Access Denied")
    mock_session.get.return_value = mock_requests_response(403, "Access Denied")
    result = plugin_memshell.run("example.com", "127.0.0.1", [80], {})
    assert result is None

# --- SMTP SMUGGLING ---
@patch("plugins.smtp_smuggling.socket.create_connection")
def test_smtp_smuggling_vulnerable(mock_create_conn):
    mock_sock = mock_create_conn.return_value.__enter__.return_value
    mock_sock.recv.side_effect = [b"220 banner\r\n", b"250 ehlo\r\n", b"250 mail from\r\n", b"250 rcpt to\r\n", b"354 data\r\n", b"250 final resp\r\n", b"221 quit\r\n", b""]
    result = plugin_smtp.run("example.com", "127.0.0.1", [25], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.smtp_smuggling.socket.create_connection")
def test_smtp_smuggling_safe(mock_create_conn):
    mock_sock = mock_create_conn.return_value.__enter__.return_value
    mock_sock.recv.side_effect = [b"220 banner\r\n", b"250 ehlo\r\n", b"250 mail from\r\n", b"250 rcpt to\r\n", b"354 data\r\n", b"500 Invalid format\r\n", b"221 quit\r\n", b""]
    result = plugin_smtp.run("example.com", "127.0.0.1", [25], {})
    assert result is None

# --- SSPP RCE ---
@patch("plugins.sspp_rce.requests.Session")
def test_sspp_rce_vulnerable(mock_session_class):
    mock_session = mock_session_class.return_value
    mock_session.post.return_value = mock_requests_response(201, "polluted")
    mock_session.get.return_value = mock_requests_response(201, "9801547")
    result = plugin_sspp.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.sspp_rce.requests.Session")
def test_sspp_rce_safe(mock_session_class):
    mock_session = mock_session_class.return_value
    mock_session.post.return_value = mock_requests_response(201, "clean")
    mock_session.get.return_value = mock_requests_response(201, "clean")
    result = plugin_sspp.run("example.com", "127.0.0.1", [80], {})
    assert result is None

# --- HTTP2 RAPID RESET ---
@patch("plugins.http2_rapid_reset.socket.create_connection")
@patch("plugins.http2_rapid_reset.ssl.create_default_context")
def test_http2_rapid_reset_vulnerable(mock_ssl, mock_create_conn):
    import socket
    mock_context = mock_ssl.return_value
    mock_ssock = mock_context.wrap_socket.return_value
    mock_ssock.selected_alpn_protocol.return_value = 'h2'
    mock_ssock.recv.side_effect = socket.timeout("Connection dropped")
    result = plugin_http2.run("example.com", "127.0.0.1", [443], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.http2_rapid_reset.socket.create_connection")
@patch("plugins.http2_rapid_reset.ssl.create_default_context")
def test_http2_rapid_reset_safe(mock_ssl, mock_create_conn):
    mock_context = mock_ssl.return_value
    mock_ssock = mock_context.wrap_socket.return_value
    mock_ssock.selected_alpn_protocol.return_value = 'h2'
    mock_ssock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
    result = plugin_http2.run("example.com", "127.0.0.1", [443], {})
    assert result is None

# --- BROKER SSRF RELAY ---
@patch("plugins.broker_ssrf_relay.requests.Session")
def test_broker_ssrf_relay_vulnerable(mock_session_class):
    mock_session = mock_session_class.return_value
    mock_session.post.return_value = mock_requests_response(200, "+PONG")
    mock_session.get.return_value = mock_requests_response(200, "+PONG")
    result = plugin_broker.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.broker_ssrf_relay.requests.Session")
def test_broker_ssrf_relay_safe(mock_session_class):
    mock_session = mock_session_class.return_value
    mock_session.post.return_value = mock_requests_response(403, "Forbidden")
    mock_session.get.return_value = mock_requests_response(403, "Forbidden")
    result = plugin_broker.run("example.com", "127.0.0.1", [80], {})
    assert result is None

# --- GRAPHQL NUCLEAR ---
@patch("plugins.graphql_nuclear.requests.Session")
def test_graphql_nuclear_vulnerable(mock_session_class):
    import requests
    mock_session = mock_session_class.return_value
    mock_session.post.side_effect = [mock_requests_response(200, "data"), requests.exceptions.Timeout("Timeout")]
    result = plugin_graphql.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.graphql_nuclear.requests.Session")
def test_graphql_nuclear_safe(mock_session_class):
    mock_session = mock_session_class.return_value
    mock_session.post.return_value = mock_requests_response(200, "data")
    result = plugin_graphql.run("example.com", "127.0.0.1", [80], {})
    assert result is None

# --- OIDC POISONING ---
@patch("plugins.oidc_poisoning.socket.socket")
def test_oidc_poisoning_vulnerable(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 201 Created\r\n\r\n{\"client_id\": \"123\", \"logo_uri\": \"http://169.254.169.254\"}", b""]
    result = plugin_oidc.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.oidc_poisoning.socket.socket")
def test_oidc_poisoning_safe(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid URI", b""]
    result = plugin_oidc.run("example.com", "127.0.0.1", [80], {})
    assert result is None

# --- COERCED AUTH WEB ---
@patch("plugins.coerced_auth_web.socket.socket")
def test_coerced_auth_web_vulnerable(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 500 Internal Server Error\r\n\r\nThe network path was not found cascavel-test", b""]
    result = plugin_coerced.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.coerced_auth_web.socket.socket")
def test_coerced_auth_web_safe(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid path", b""]
    result = plugin_coerced.run("example.com", "127.0.0.1", [80], {})
    assert result is None

# --- CLOUD GHOSTING ---
@patch("plugins.cloud_ghosting.socket.socket")
def test_cloud_ghosting_vulnerable(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nami-0abcdef123456", b""]
    result = plugin_cloud.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "CRITICAL"

@patch("plugins.cloud_ghosting.socket.socket")
def test_cloud_ghosting_safe(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 403 Forbidden\r\n\r\nIMDSv2 token required", b""]
    result = plugin_cloud.run("example.com", "127.0.0.1", [80], {})
    assert result is None

# --- WASM REVERSER ---
@patch("plugins.wasm_reverser.socket.socket")
def test_wasm_reverser_vulnerable(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n\x00asm...verify_signature...", b""]
    result = plugin_wasm.run("example.com", "127.0.0.1", [80], {})
    assert result is not None
    assert result["severity"] == "HIGH"

@patch("plugins.wasm_reverser.socket.socket")
def test_wasm_reverser_safe(mock_socket):
    mock_socket.return_value.recv.side_effect = [b"HTTP/1.1 404 Not Found\r\n\r\nNot found", b""]
    result = plugin_wasm.run("example.com", "127.0.0.1", [80], {})
    assert result is None
