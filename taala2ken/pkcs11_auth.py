"""
TAALA-2KEN — PKCS#11 Challenge-Response Authentication.

Handles discovery of middleware DLLs, opening PKCS#11 sessions,
reading certificates/public keys, and performing random challenge-response
signatures using the token's private key.
"""

import os
import secrets
from taala2ken import constants as C
from taala2ken.log import log

try:
    import PyKCS11
    from PyKCS11 import LowLevel as KCS
    _PYKCS11_AVAILABLE = True
except ImportError:
    _PYKCS11_AVAILABLE = False
    PyKCS11 = None
    KCS = None

try:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_der_public_key
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


def enroll_token() -> str:
    """
    Enrolls the token by extracting its public key as DER-encoded hex.
    Returns DER public key hex string, or empty string on failure.
    """
    if not _PYKCS11_AVAILABLE:
        log.warning("[PKCS11] PyKCS11 library not installed. Cannot enroll token cryptographically.")
        return ""

    dll_path = find_middleware_dll()
    if not dll_path:
        log.warning("[PKCS11] No PKCS#11 middleware DLL found. Install Feitian/ePass2003 drivers.")
        return ""

    try:
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(dll_path)

        slots = pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            log.warning("[PKCS11] No slot with token present found.")
            return ""

        slot = slots[0]
        pin = input("  Enter Token PIN (default is usually 12345678): ").strip()
        
        session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
        session.login(pin)

        public_keys = session.findObjects([
            (KCS.CKA_CLASS, KCS.CKO_PUBLIC_KEY)
        ])

        if not public_keys:
            log.warning("[PKCS11] No public keys found on token.")
            session.logout()
            session.closeSession()
            return ""

        pub_key_obj = public_keys[0]
        attrs = session.getAttributeValue(pub_key_obj, [KCS.CKA_MODULUS, KCS.CKA_PUBLIC_EXPONENT])
        modulus = bytes(attrs[0])
        exponent = bytes(attrs[1])

        session.logout()
        session.closeSession()

        if _CRYPTO_AVAILABLE:
            mod_int = int.from_bytes(modulus, byteorder='big')
            exp_int = int.from_bytes(exponent, byteorder='big')
            pub_key = rsa.RSAPublicNumbers(exp_int, mod_int).public_key()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            der_bytes = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            return der_bytes.hex()
        else:
            log.error("[PKCS11] cryptography library not found. Cannot construct public key DER.")
            return ""

    except Exception as e:
        log.error(f"[PKCS11] Enrollment failed: {e}")
        return ""


def verify_token_challenge(stored_pubkey_der_hex: str) -> bool:
    """
    Generates a random challenge nonce, signs it using the token's private key,
    and verifies the signature using the stored public key.
    """
    if not stored_pubkey_der_hex:
        return False

    if not _PYKCS11_AVAILABLE:
        log.warning("[PKCS11] PyKCS11 missing. Verification skipped.")
        return False

    dll_path = find_middleware_dll()
    if not dll_path:
        log.warning("[PKCS11] PKCS#11 middleware DLL missing. Verification failed.")
        return False

    if not _CRYPTO_AVAILABLE:
        log.warning("[PKCS11] cryptography package missing. Cannot verify signature.")
        return False

    try:
        pub_key_bytes = bytes.fromhex(stored_pubkey_der_hex)
        public_key = load_der_public_key(pub_key_bytes)

        challenge = secrets.token_bytes(C.PKCS11_CHALLENGE_SIZE)

        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(dll_path)
        slots = pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            log.warning("[PKCS11] Verification failed: Token removed.")
            return False

        slot = slots[0]
        session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)

        private_keys = session.findObjects([
            (KCS.CKA_CLASS, KCS.CKO_PRIVATE_KEY)
        ])
        if not private_keys:
            log.warning("[PKCS11] No private keys found on token.")
            session.closeSession()
            return False

        priv_key = private_keys[0]
        mechanism = PyKCS11.Mechanism(KCS.CKM_SHA256_RSA_PKCS, None)
        signature = bytes(session.sign(priv_key, challenge, mechanism))

        session.closeSession()

        public_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        log.debug("[PKCS11] Challenge-response verified successfully.")
        return True

    except Exception as e:
        log.error(f"[PKCS11] Challenge verification failed: {e}")
        return False
