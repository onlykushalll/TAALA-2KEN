"""
TAALA-2KEN — PKCS#11 Challenge-Response Authentication.

Handles discovery of middleware DLLs, opening PKCS#11 sessions,
reading certificates/public keys, and performing random challenge-response
signatures using the token's private key via OpenSC CLI utilities.
"""

import os
import secrets
import subprocess
import tempfile
from taala2ken import constants as C
from taala2ken.log import log

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key, Encoding, PublicFormat
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def find_middleware_dll() -> str | None:
    """Finds first available PKCS#11 middleware DLL on the system."""
    for path in C.PKCS11_MIDDLEWARE_PATHS:
        if os.path.exists(path):
            log.debug(f"[PKCS11] Found middleware DLL: {path}")
            return path
    log.debug("[PKCS11] No standard middleware DLLs found on disk.")
    return None


def find_opensc_tool(tool_name: str) -> str | None:
    """Finds OpenSC tool executable on Windows."""
    paths = [
        r"C:\Program Files\OpenSC Project\OpenSC\tools",
        r"C:\Program Files (x86)\OpenSC Project\OpenSC\tools"
    ]
    for p in paths:
        full_path = os.path.join(p, tool_name + ".exe")
        if os.path.exists(full_path):
            return full_path
    return None


def get_token_pin() -> str:
    """Gets PIN from environment variable or defaults to 123456."""
    return os.environ.get("TAALA_2KEN_PIN", "123456")


def enroll_token() -> str:
    """
    Enrolls the token by extracting its public key as DER-encoded hex.
    Returns DER public key hex string, or empty string on failure.
    """
    if not _CRYPTO_AVAILABLE:
        log.warning("[PKCS11] Cryptography package missing. Cannot enroll token.")
        return ""

    pkcs15_tool = find_opensc_tool("pkcs15-tool")
    if not pkcs15_tool:
        log.warning("[PKCS11] OpenSC pkcs15-tool.exe not found on disk.")
        return ""

    try:
        # Run pkcs15-tool --read-public-key 01 to read the public key PEM
        cmd = [pkcs15_tool, "--read-public-key", "01"]
        
        # Suppress window creation
        creation_flags = 0
        if os.name == 'nt':
            creation_flags = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            creationflags=creation_flags
        )
        pem_data = result.stdout

        # Load PEM and convert to DER hex format
        pub_key = load_pem_public_key(pem_data.encode('utf-8'))
        der_bytes = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        log.info("[PKCS11] Successfully extracted public key from Kushal-TOKEN during enrollment.")
        return der_bytes.hex()
    except Exception as e:
        log.error(f"[PKCS11] Public key enrollment failed: {e}")
        return ""


def verify_token_challenge(stored_pubkey_der_hex: str) -> bool:
    """
    Generates a random challenge nonce, signs it using the token's private key via pkcs11-tool.exe,
    and verifies the signature using the stored public key.
    """
    if not stored_pubkey_der_hex:
        return False

    if not _CRYPTO_AVAILABLE:
        log.warning("[PKCS11] Cryptography package missing. Cannot verify signature.")
        return False

    pkcs11_tool = find_opensc_tool("pkcs11-tool")
    if not pkcs11_tool:
        log.warning("[PKCS11] OpenSC pkcs11-tool.exe not found on disk.")
        return False

    # Set up temporary challenge and signature files
    challenge = secrets.token_bytes(C.PKCS11_CHALLENGE_SIZE)
    pin = get_token_pin()

    challenge_fd, challenge_path = tempfile.mkstemp(suffix=".bin", prefix="t2k_challenge_")
    sig_fd, sig_path = tempfile.mkstemp(suffix=".bin", prefix="t2k_sig_")

    try:
        os.write(challenge_fd, challenge)
        os.close(challenge_fd)
        os.close(sig_fd)

        # Run pkcs11-tool to sign the challenge
        cmd = [
            pkcs11_tool,
            "--sign",
            "-m", "SHA256-RSA-PKCS",
            "--pin", pin,
            "--id", "01",
            "-i", challenge_path,
            "-o", sig_path
        ]

        creation_flags = 0
        if os.name == 'nt':
            creation_flags = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            cmd,
            capture_output=True,
            check=True,
            creationflags=creation_flags
        )

        # Read signature from file
        with open(sig_path, "rb") as f:
            signature = f.read()

        # Load public key from DER format
        pub_key_bytes = bytes.fromhex(stored_pubkey_der_hex)
        public_key = load_der_public_key(pub_key_bytes)

        # Verify signature
        public_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        log.debug("[PKCS11] Challenge-response verified successfully using physical Kushal-TOKEN.")
        return True

    except Exception as e:
        log.error(f"[PKCS11] Challenge verification failed: {e}")
        return False
    finally:
        # Zero-Residue cleanup of temporary files
        for path in (challenge_path, sig_path):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception as cleanup_err:
                log.debug(f"[PKCS11] Error cleaning up temporary file {path}: {cleanup_err}")

