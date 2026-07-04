"""
TAALA-2KEN — Device model classes.

Three classes represent the devices the system can detect:
  • USBDevice        — USB mass-storage drives
  • GenericUSBDevice — Non-storage USB peripherals (tokens, HID, etc.)
  • SmartCardDevice  — Smart card readers and crypto tokens (subclass of Generic)
"""

import re
import hashlib

from taala2ken.log import log


# ═════════════════════════════════════════════════════════════════════════════
#  USB STORAGE DEVICE
# ═════════════════════════════════════════════════════════════════════════════

class USBDevice:
    """
    Represents a single detected USB STORAGE device.

    Attributes
    ----------
    device_id        : WMI Win32_DiskDrive DeviceID
    pnp_device_id    : Plug-and-play instance string
    volume_serial    : NTFS/FAT32 volume serial number (hex string)
    label            : Drive label visible in Explorer
    drive_letter     : Current drive letter (informational only)
    model            : Disk model string from firmware
    fingerprint      : SHA-256 hash of stable identifiers
    device_type      : "STORAGE"
    manufacturer     : Empty string (uniformity with GenericUSBDevice)
    detection_source : "WMI" (always for storage devices)
    """

    DEVICE_TYPE: str = "STORAGE"

    def __init__(
        self,
        device_id:     str,
        pnp_device_id: str,
        volume_serial: str,
        label:         str,
        drive_letter:  str,
        model:         str,
    ):
        self.device_id        = device_id
        self.pnp_device_id    = pnp_device_id
        self.volume_serial    = volume_serial
        self.label            = label
        self.drive_letter     = drive_letter
        self.model            = model
        self.device_type      = self.DEVICE_TYPE
        self.manufacturer     = ""
        self.detection_source = "WMI"
        self.fingerprint      = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        stable_pnp = (
            self.pnp_device_id.rsplit("&", 1)[0]
            if "&" in self.pnp_device_id
            else self.pnp_device_id
        )
        raw    = f"{stable_pnp}::{self.volume_serial}::{self.model}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        log.debug(f"[STORAGE] Fingerprint source → '{raw}'")
        log.debug(f"[STORAGE] Fingerprint SHA-256 → {digest}")
        return digest

    def __repr__(self) -> str:
        return (
            f"USBDevice(label='{self.label}', model='{self.model}', "
            f"drive='{self.drive_letter}', vol_serial='{self.volume_serial}', "
            f"fp='{self.fingerprint[:16]}...')"
        )


# ═════════════════════════════════════════════════════════════════════════════
#  GENERIC USB DEVICE (tokens, HID, etc.)
# ═════════════════════════════════════════════════════════════════════════════

class GenericUSBDevice:
    """
    Represents a non-storage USB device (token, smart card, CCID, etc.).

    Attributes
    ----------
    pnp_device_id    : Plug-and-play instance string
    name             : Human-readable device name
    description      : WMI device description
    manufacturer     : Manufacturer string
    device_id        : Fallback device ID
    status           : WMI device status string
    device_type      : "TOKEN"
    fingerprint      : SHA-256 of stable identifiers
    detection_source : "WMI" | "USBCTRL" | "SETUPAPI"
    """

    DEVICE_TYPE: str = "TOKEN"

    def __init__(
        self,
        pnp_device_id:    str,
        name:             str,
        description:      str,
        manufacturer:     str,
        device_id:        str = "",
        status:           str = "",
        detection_source: str = "WMI",
    ):
        self.pnp_device_id    = pnp_device_id
        self.name             = name
        self.description      = description
        self.manufacturer     = manufacturer
        self.device_id        = device_id or pnp_device_id
        self.status           = status
        self.detection_source = detection_source

        self.device_type   = self.DEVICE_TYPE
        self.label         = name
        self.model         = name
        self.drive_letter  = ""
        self.volume_serial = ""

        self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        pnp_parts = self.pnp_device_id.rsplit("\\", 1)
        if len(pnp_parts) == 2:
            prefix_path, instance = pnp_parts
            instance_clean = re.sub(r"&\d+$", "", instance)
            stable_pnp = f"{prefix_path}\\{instance_clean}"
        else:
            stable_pnp = self.pnp_device_id

        raw    = f"{stable_pnp}::{self.manufacturer}::{self.name}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        log.debug(f"[TOKEN] Fingerprint source → '{raw}'")
        log.debug(f"[TOKEN] Fingerprint SHA-256 → {digest}")
        return digest

    def __repr__(self) -> str:
        return (
            f"GenericUSBDevice(name='{self.name}', "
            f"mfr='{self.manufacturer}', "
            f"src='{self.detection_source}', "
            f"pnp='{self.pnp_device_id[:50]}', "
            f"fp='{self.fingerprint[:16]}...')"
        )


# ═════════════════════════════════════════════════════════════════════════════
#  SMART CARD / CRYPTO TOKEN DEVICE
# ═════════════════════════════════════════════════════════════════════════════

class SmartCardDevice(GenericUSBDevice):
    """
    Represents a smart card reader or USB crypto token.
    device_type = 'SMART CARD / TOKEN'
    """

    DEVICE_TYPE: str = "SMART CARD / TOKEN"

    def __repr__(self) -> str:
        return (
            f"SmartCardDevice(name='{self.name}', "
            f"mfr='{self.manufacturer}', "
            f"src='{self.detection_source}', "
            f"pnp='{self.pnp_device_id[:50]}', "
            f"fp='{self.fingerprint[:16]}...')"
        )
