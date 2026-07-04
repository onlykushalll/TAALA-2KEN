"""
TAALA-2KEN — Unified Test Suite.

Covers device classification, filtering, IPC protocol, and PKCS#11 configuration.
"""

from unittest.mock import patch, MagicMock
from taala2ken.detection import helpers as H
from taala2ken.pipe_server import NamedPipeServer
import taala2ken.pkcs11_auth as pkcs11_auth


# ═══════════════════════════════════════════════════════════════════════
#  DEVICE DETECTION & CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════

def test_is_protected_token():
    assert H.is_protected_token_str("USB\\VID_096E&PID_0608\\12345", "ePass2003") is True
    assert H.is_protected_token_str("USB\\VID_1234&PID_5678\\abc", "Generic Flash Drive") is False
    assert H.is_protected_token_str("SCFILTER\\CID_12345", "Smart Card Reader") is True


def test_is_usb_infrastructure():
    assert H.is_usb_infrastructure_str("USB Root Hub", "USB\\ROOT_HUB30\\1") is True
    assert H.is_usb_infrastructure_str("Intel USB 3.0 eXtensible Host Controller", "PCI\\VEN_8086") is True
    # Non-infrastructure
    assert H.is_usb_infrastructure_str("FT CCID Smartcard Reader", "USB\\VID_096E&PID_0608") is False
    assert H.is_usb_infrastructure_str("Generic USB Device", "USB\\VID_1234") is False


def test_extract_pnp_serial():
    assert H.extract_pnp_serial("USB\\VID_096E&PID_0608\\123456&0") == "123456"
    assert H.extract_pnp_serial("USB\\VID_096E&PID_0608\\ABCDEF") == "ABCDEF"
    assert H.extract_pnp_serial("SIMPLE_ID") == ""


def test_is_epass2003():
    assert H.is_epass2003("USB\\VID_096E&PID_0608", "ePass2003 Token") is True
    assert H.is_epass2003("USB\\VID_1234&PID_5678", "Normal Key") is False


# ═══════════════════════════════════════════════════════════════════════
#  NAMED PIPE IPC PROTOCOL
# ═══════════════════════════════════════════════════════════════════════

def test_pipe_server_query_status():
    mock_config = MagicMock()
    mock_config.is_configured = True
    mock_config.registered_device_type = "TOKEN"
    mock_config.public_key_der = "aabbcc"

    server = NamedPipeServer(mock_config)
    server.broadcast_status("PRESENT", 0.0)

    req = {"action": "query_status"}
    res = server._process_request(req)
    assert res["status"] == "PRESENT"
    assert res["is_configured"] is True
    assert res["device_type"] == "TOKEN"
    assert res["requires_challenge"] is True


def test_pipe_server_unknown_action():
    mock_config = MagicMock()
    server = NamedPipeServer(mock_config)

    req = {"action": "invalid_action"}
    res = server._process_request(req)
    assert "error" in res["status"]


# ═══════════════════════════════════════════════════════════════════════
#  PKCS#11 CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

def test_find_middleware_dll_exists():
    with patch("os.path.exists", return_value=True):
        dll = pkcs11_auth.find_middleware_dll()
        assert dll is not None


def test_find_middleware_dll_missing():
    with patch("os.path.exists", return_value=False):
        dll = pkcs11_auth.find_middleware_dll()
        assert dll is None


def test_verify_token_challenge_no_pubkey():
    assert pkcs11_auth.verify_token_challenge("") is False
