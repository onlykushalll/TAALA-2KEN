"""
TAALA-2KEN — All constants, keywords, ctypes structures, and configuration.

Single source of truth for every magic number, keyword list, and
compile-time-equivalent value in the project.
"""

import ctypes
from pathlib import Path


# ═════════════════════════════════════════════════════════════════════════════
#  RUNTIME CONFIG  (mutable — set by CLI at startup)
# ═════════════════════════════════════════════════════════════════════════════

DEBUG_MODE: bool = False


# ═════════════════════════════════════════════════════════════════════════════
#  PATHS
# ═════════════════════════════════════════════════════════════════════════════

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
CONFIG_FILE: Path = PROJECT_ROOT / "usb_auth_guard_config.json"
LOG_FILE: Path | None = PROJECT_ROOT / "usb_auth_guard.log"


# ═════════════════════════════════════════════════════════════════════════════
#  TIMING
# ═════════════════════════════════════════════════════════════════════════════

CHECK_INTERVAL_SECONDS: float = 1.0
REMOVAL_GRACE_PERIOD_SECONDS: float = 2.0


# ═════════════════════════════════════════════════════════════════════════════
#  LOCK METHOD
# ═════════════════════════════════════════════════════════════════════════════

LOCK_METHOD: str = "rundll32"


# ═════════════════════════════════════════════════════════════════════════════
#  WMI EVENT WATCHER
# ═════════════════════════════════════════════════════════════════════════════

ENABLE_WMI_EVENT_WATCHER: bool = True


# ═════════════════════════════════════════════════════════════════════════════
#  NAMED PIPE (IPC between Python monitor ↔ Credential Provider DLL)
# ═════════════════════════════════════════════════════════════════════════════

PIPE_NAME: str = r"\\.\pipe\Taala2KenAuth"
PIPE_BUFFER_SIZE: int = 4096
PIPE_TIMEOUT_MS: int = 5000


# ═════════════════════════════════════════════════════════════════════════════
#  PKCS#11 MIDDLEWARE PATHS (tried in order)
# ═════════════════════════════════════════════════════════════════════════════

PKCS11_MIDDLEWARE_PATHS: tuple[str, ...] = (
    r"C:\Windows\System32\eps2003csp11.dll",
    r"C:\Windows\System32\eTPKCS11.dll",
    r"C:\Program Files\Feitian\PKI\eps2003csp11.dll",
    r"C:\Program Files (x86)\Feitian\PKI\eps2003csp11.dll",
    r"C:\Windows\System32\opensc-pkcs11.dll",
)

PKCS11_CHALLENGE_SIZE: int = 32  # bytes of random nonce


# ═════════════════════════════════════════════════════════════════════════════
#  USB INFRASTRUCTURE KEYWORDS (excluded from selectable devices)
# ═════════════════════════════════════════════════════════════════════════════

USB_INFRA_KEYWORDS: tuple[str, ...] = (
    "usb root hub",
    "root hub",
    "usb hub",
    "generic usb hub",
    "usb 3.0 hub",
    "usb 2.0 hub",
    "host controller",
    "enhanced host",
    "universal host",
    "open host",
    "xhci",
    "ehci",
    "ohci",
    "uhci",
)


# ═════════════════════════════════════════════════════════════════════════════
#  SMART CARD / TOKEN KEYWORD FILTERS
# ═════════════════════════════════════════════════════════════════════════════

SMART_CARD_NAME_KEYWORDS: tuple[str, ...] = (
    "smart card",
    "smartcard",
    "epass",
    "epass2003",
    "feitian",
    "ccid",
    "crypto token",
    "cryptographic token",
    "pkcs",
    "safenet",
    "gemalto",
    "oberthur",
    "acs acr",
    "identiv",
    "yubico",
    "yubikey",
    "nitrokey",
    "token",
)

SMART_CARD_MFR_KEYWORDS: tuple[str, ...] = (
    "feitian",
    "safenet",
    "gemalto",
    "oberthur",
    "acs",
    "identiv",
    "yubico",
    "nitrolab",
    "hid global",
    "cryptovision",
    "bit4id",
    "certgate",
    "athena",
)


# ═════════════════════════════════════════════════════════════════════════════
#  FEITIAN / ePASS2003 IDENTIFIERS
# ═════════════════════════════════════════════════════════════════════════════

FEITIAN_VID: str = "VID_096E"

FEITIAN_KNOWN_PIDS: tuple[str, ...] = (
    "PID_0608",
    "PID_060B",
    "PID_060C",
    "PID_0303",
)

EPASS_NAME_KEYWORDS: tuple[str, ...] = (
    "epass2003",
    "epass",
    "feitian",
    "vid_096e",
    "ft ccid",
    "ft smartcard",
)

CCID_IDENTIFIERS: tuple[str, ...] = (
    "ccid",
    "usbccid",
    "composite ccid",
    "scfilter",
    "smartcardfilter",
)


# ═════════════════════════════════════════════════════════════════════════════
#  DETECTION SOURCE PRIORITIES (higher = preferred in dedup)
# ═════════════════════════════════════════════════════════════════════════════

SOURCE_PRIORITY: dict[str, int] = {
    "SETUPAPI": 3,
    "USBCTRL":  2,
    "WMI":      1,
}


# ═════════════════════════════════════════════════════════════════════════════
#  WINDOWS SetupAPI CTYPES CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DIGCF_PRESENT:          int = 0x00000002
DIGCF_ALLCLASSES:       int = 0x00000004
DIGCF_PROFILE:          int = 0x00000008
DIGCF_DEVICEINTERFACE:  int = 0x00000010

SPDRP_DEVICEDESC:       int = 0x00000000
SPDRP_HARDWAREID:       int = 0x00000001
SPDRP_COMPATIBLEIDS:    int = 0x00000002
SPDRP_MFG:              int = 0x0000000B
SPDRP_FRIENDLYNAME:     int = 0x0000000C

ERROR_NO_MORE_ITEMS:    int = 259
ERROR_INSUFFICIENT_BUFFER: int = 122

INVALID_HANDLE_VALUE:   int = ctypes.c_void_p(-1).value


# ═════════════════════════════════════════════════════════════════════════════
#  WINDOWS SetupAPI CTYPES STRUCTURES
# ═════════════════════════════════════════════════════════════════════════════

class GUID(ctypes.Structure):
    """Windows GUID structure — used inside SP_DEVINFO_DATA."""
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SP_DEVINFO_DATA(ctypes.Structure):
    """
    SP_DEVINFO_DATA — passed to SetupDiEnumDeviceInfo / SetupDiGetDeviceXxx.
    cbSize MUST be set to sizeof(SP_DEVINFO_DATA) before any call.
    """
    _fields_ = [
        ("cbSize",    ctypes.c_uint),
        ("ClassGuid", GUID),
        ("DevInst",   ctypes.c_uint),
        ("Reserved",  ctypes.c_size_t),
    ]
