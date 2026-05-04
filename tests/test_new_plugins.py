from unittest.mock import MagicMock, patch

import requests

import plugins.graphql_ast_bomb as plugin_graphql
import plugins.kubelet_anonymous_rce as plugin_kubelet

# Import the newly added plugins
import plugins.llm_rag_poisoning as plugin_llm
import plugins.serverless_event_injection as plugin_serverless
import plugins.web3_rpc_exposure as plugin_web3


@patch("plugins.llm_rag_poisoning.requests.post")
def test_llm_rag_poisoning_vulnerable(mock_post):
    mock_resp = MagicMock()
    mock_resp.text = "Here is the response: VULNERABLE_AI_2026"
    mock_post.return_value = mock_resp
    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_llm.run(target, ip, [], {})
    assert finding is not None
    assert finding["severity"] == "CRITICAL"
    assert "LLM RAG Poisoning" in finding["vulnerability"]

@patch("plugins.llm_rag_poisoning.requests.post")
def test_llm_rag_poisoning_safe(mock_post):
    mock_resp = MagicMock()
    mock_resp.text = "I cannot fulfill this request."
    mock_post.return_value = mock_resp
    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_llm.run(target, ip, [], {})
    assert finding is None

@patch("plugins.kubelet_anonymous_rce.requests.post")
@patch("plugins.kubelet_anonymous_rce.requests.get")
def test_kubelet_anonymous_rce_vulnerable(mock_get, mock_post):
    mock_resp_get = MagicMock()
    mock_resp_get.status_code = 200
    mock_resp_get.json.return_value = {
        "items": [
            {
                "metadata": {"name": "test-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "test-container"}]}
            }
        ]
    }
    mock_get.return_value = mock_resp_get

    mock_resp_post = MagicMock()
    mock_resp_post.status_code = 200
    mock_resp_post.text = "CASCADE_RCE_CONFIRMED"
    mock_post.return_value = mock_resp_post

    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_kubelet.run(target, ip, [10250], {})
    assert finding is not None
    assert finding["severity"] == "CRITICAL"
    assert "Kubelet" in finding["vulnerability"]

@patch("plugins.kubelet_anonymous_rce.requests.get")
def test_kubelet_anonymous_rce_safe(mock_get):
    mock_resp_get = MagicMock()
    mock_resp_get.status_code = 401
    mock_get.return_value = mock_resp_get
    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_kubelet.run(target, ip, [10250], {})
    assert finding is None

@patch("plugins.graphql_ast_bomb.requests.post")
def test_graphql_ast_bomb_vulnerable(mock_post):
    mock_baseline = MagicMock()
    mock_baseline.status_code = 200
    mock_baseline.json.return_value = {"data": {}}

    # The bomb request will raise a timeout exception to match the logic where bomb works
    mock_post.side_effect = [mock_baseline, requests.exceptions.Timeout("Timeout")]

    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_graphql.run(target, ip, [], {})
    assert finding is not None
    assert finding["severity"] == "HIGH"
    assert "GraphQL" in finding["vulnerability"]

@patch("plugins.graphql_ast_bomb.requests.post")
def test_graphql_ast_bomb_safe(mock_post):
    mock_baseline = MagicMock()
    mock_baseline.status_code = 200
    mock_baseline.json.return_value = {"data": {}}

    mock_bomb = MagicMock()
    mock_bomb.status_code = 200
    # Simulate time elapsed, we mock time in actual case or just mock it to be short
    # Here we won't throw timeout and we won't return >= 500, so it should be safe

    mock_post.side_effect = [mock_baseline, mock_bomb]
    target = "example.com"
    ip = "127.0.0.1"
    with patch("plugins.graphql_ast_bomb.time.time", side_effect=[0, 0.1, 0.2, 0.3]):
        finding = plugin_graphql.run(target, ip, [], {})
    assert finding is None

@patch("plugins.web3_rpc_exposure.requests.post")
def test_web3_rpc_exposure_vulnerable(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": ["0x123", "0x456"]}
    mock_post.return_value = mock_resp
    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_web3.run(target, ip, [8545], {})
    assert finding is not None
    assert finding["severity"] == "CRITICAL"
    assert "Web3" in finding["vulnerability"]

@patch("plugins.web3_rpc_exposure.requests.post")
def test_web3_rpc_exposure_safe(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_post.return_value = mock_resp
    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_web3.run(target, ip, [8545], {})
    assert finding is None

@patch("plugins.serverless_event_injection.requests.post")
def test_serverless_event_injection_vulnerable(mock_post):
    mock_resp = MagicMock()
    mock_resp.text = "Error trace: AWS_SESSION_TOKEN=ABC"
    mock_post.return_value = mock_resp
    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_serverless.run(target, ip, [], {})
    assert finding is not None
    assert finding["severity"] == "CRITICAL"
    assert "Serverless" in finding["vulnerability"]

@patch("plugins.serverless_event_injection.requests.post")
def test_serverless_event_injection_safe(mock_post):
    mock_resp = MagicMock()
    mock_resp.text = "Internal Server Error"
    mock_post.return_value = mock_resp
    target = "example.com"
    ip = "127.0.0.1"
    finding = plugin_serverless.run(target, ip, [], {})
    assert finding is None
