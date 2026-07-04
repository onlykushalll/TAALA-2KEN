"""
TAALA-2KEN — Configuration management.

Manages loading, saving, and checking registration of the authorized USB device.
"""

import json
from datetime import datetime
from taala2ken import constants as C
from taala2ken.log import log

class AuthConfig:
    """
    Manages persistent storage of the authorized USB fingerprint and metadata.
    """

    def __init__(self, config_path=C.CONFIG_FILE):
        self.path = config_path
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
                log.debug(f"Config loaded from: {self.path}")
            except (json.JSONDecodeError, OSError) as e:
                log.warning(f"Config file corrupt or unreadable ({e}). Starting fresh.")
                self._data = {}
        else:
            log.debug("No config file found — first-run mode will be needed.")

    def _save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
            log.debug(f"Config saved to: {self.path}")
        except OSError as e:
            log.error(f"Failed to save config: {e}")

    @property
    def is_configured(self) -> bool:
        return bool(self._data.get("fingerprint"))

    @property
    def authorized_fingerprint(self) -> str:
        return self._data.get("fingerprint", "")

    @property
    def registered_device_type(self) -> str:
        return self._data.get("device_type", "STORAGE")

    @property
    def public_key_der(self) -> str:
        """DER-encoded public key hex string from enrollment for PKCS#11 challenge verification."""
        return self._data.get("public_key_der", "")

    def register_device(self, device, public_key_der: str = "") -> None:
        """Stores the given device's fingerprint as the sole authorized USB."""
        self._data = {
            "fingerprint":        device.fingerprint,
            "registered_at":      datetime.now().isoformat(),
            "device_label":       getattr(device, "label", ""),
            "device_model":       getattr(device, "model", ""),
            "pnp_id_prefix":      device.pnp_device_id.rsplit("&", 1)[0],
            "device_type":        getattr(device, "device_type", "STORAGE"),
            "manufacturer":       getattr(device, "manufacturer", ""),
            "detection_source":   getattr(device, "detection_source", "WMI"),
            "public_key_der":     public_key_der,
        }
        self._save()
        dev_type = self._data["device_type"]
        src      = self._data["detection_source"]
        log.info(f"Authorized USB registered [{dev_type}][{src}]: '{device.label or device.model}'")
        log.info(f"  Fingerprint: {device.fingerprint}")
        if public_key_der:
            log.info("  PKCS#11 Authentication: ENABLED (stored public key)")

    def clear(self) -> None:
        self._data = {}
        if self.path.exists():
            self.path.unlink()
        log.info("Authorization cleared.")

    def describe(self) -> str:
        if not self.is_configured:
            return "(none registered)"
        label = (
            self._data.get("device_label") or
            self._data.get("device_model") or
            "Unknown device"
        )
        ts       = self._data.get("registered_at", "unknown time")
        dev_type = self._data.get("device_type", "STORAGE")
        src      = self._data.get("detection_source", "WMI")
        pkcs11   = " + PKCS#11" if self.public_key_der else ""
        return f"'{label}' [{dev_type}][{src}{pkcs11}] registered at {ts}"
