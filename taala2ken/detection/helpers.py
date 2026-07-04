"""
TAALA-2KEN — Device detection helper functions.

Contains low-level functions for checking VID/PID, CCID identifiers,
smart card keywords, drive mappings, and SetupAPI ctypes interactions.
"""

import re
import ctypes
from taala2ken import constants as C
from taala2ken.log import log

# Load setupapi.dll lazily
_setupapi_dll = None

def load_setupapi() -> object | None:
    """Lazy-load and configure setupapi.dll with proper argtypes / restype declarations."""
    global _setupapi_dll
    if _setupapi_dll is not None:
        return _setupapi_dll

    try:
        dll = ctypes.windll.setupapi

        dll.SetupDiGetClassDevsW.restype  = ctypes.c_void_p
        dll.SetupDiGetClassDevsW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]

        dll.SetupDiEnumDeviceInfo.restype  = ctypes.c_bool
        dll.SetupDiEnumDeviceInfo.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(C.SP_DEVINFO_DATA),
        ]

        dll.SetupDiGetDeviceInstanceIdW.restype  = ctypes.c_bool
        dll.SetupDiGetDeviceInstanceIdW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(C.SP_DEVINFO_DATA),
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        ]

        dll.SetupDiGetDeviceRegistryPropertyW.restype  = ctypes.c_bool
        dll.SetupDiGetDeviceRegistryPropertyW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(C.SP_DEVINFO_DATA),
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        ]

        dll.SetupDiDestroyDeviceInfoList.restype  = ctypes.c_bool
        dll.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]

        _setupapi_dll = dll
        log.debug("[SETUPAPI] setupapi.dll loaded and configured.")
        return dll
    except Exception as e:
        log.debug(f"[SETUPAPI] Failed to load setupapi.dll: {e}")
        return None

def get_volume_serial(drive_letter: str) -> str:
    """Queries the volume serial number for a drive letter via win32api."""
    if not drive_letter:
        return ""
    try:
        import win32api
        import pywintypes
        info   = win32api.GetVolumeInformation(drive_letter + "\\")
        serial = format(info[1] & 0xFFFFFFFF, "08X")
        log.debug(f"  Volume serial for {drive_letter}: {serial}")
        return serial
    except Exception as e:
        log.debug(f"  Could not get volume serial for {drive_letter}: {e}")
        return ""

def map_disk_to_drive_letter(wmi_conn, disk_device_id: str) -> str:
    """Resolves a physical disk DeviceID to its current drive letter via partition association."""
    try:
        partitions = wmi_conn.query(
            f"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{disk_device_id}'}}"
            f" WHERE AssocClass=Win32_DiskDriveToDiskPartition"
        )
        for part in partitions:
            logicals = wmi_conn.query(
                f"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part.DeviceID}'}}"
                f" WHERE AssocClass=Win32_LogicalDiskToPartition"
            )
            for logical in logicals:
                return logical.DeviceID
    except Exception as e:
        log.debug(f"  Drive letter mapping failed for '{disk_device_id}': {e}")
    return ""

def contains_vid_096e(text: str) -> bool:
    """Returns True if the text contains VID_096E (case-insensitive)."""
    return C.FEITIAN_VID in text.upper()

def contains_ccid_identifier(text: str) -> bool:
    """Returns True if the text contains any CCID identifier (case-insensitive)."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in C.CCID_IDENTIFIERS)

def contains_smart_card_keyword(text: str) -> bool:
    """Returns True if text contains a smart card name keyword (case-insensitive)."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in C.SMART_CARD_NAME_KEYWORDS)

def any_id_contains_vid_096e(id_list: list | None) -> bool:
    """Returns True if any string in the list contains VID_096E."""
    if not id_list:
        return False
    for id_str in id_list:
        if C.FEITIAN_VID in id_str.upper():
            return True
    return False

def any_id_contains_ccid(id_list: list | None) -> bool:
    """Returns True if any string in the list contains a CCID identifier."""
    if not id_list:
        return False
    for id_str in id_list:
        if contains_ccid_identifier(id_str):
            return True
    return False

def any_id_contains_smart_card(id_list: list | None) -> bool:
    """Returns True if any string in the list contains a smart card keyword."""
    if not id_list:
        return False
    for id_str in id_list:
        if contains_smart_card_keyword(id_str):
            return True
    return False

def device_matches_acceptance_criteria(
    pnp_id: str,
    name: str = "",
    hardware_ids: list | None = None,
    compatible_ids: list | None = None,
) -> bool:
    """
    Checks if a device meets content-based criteria for smart cards/tokens.
    """
    all_ids = (hardware_ids or []) + (compatible_ids or [])

    if contains_vid_096e(pnp_id):
        return True
    if any_id_contains_vid_096e(hardware_ids):
        return True
    if any_id_contains_vid_096e(compatible_ids):
        return True

    if contains_ccid_identifier(pnp_id):
        return True
    if contains_ccid_identifier(name):
        return True
    if any_id_contains_ccid(all_ids):
        return True

    if contains_smart_card_keyword(name):
        return True
    if any_id_contains_smart_card(all_ids):
        return True

    return False

def is_protected_token_str(pnp_id: str, name: str) -> bool:
    """Returns True if the device is a known security token that should bypass infrastructure exclusions."""
    pnp_upper  = pnp_id.upper()
    name_lower = name.lower()

    if C.FEITIAN_VID in pnp_upper:
        return True

    if any(kw in name_lower for kw in C.SMART_CARD_NAME_KEYWORDS):
        return True

    combined = name_lower + " " + pnp_upper.lower()
    if any(kw in combined for kw in C.CCID_IDENTIFIERS):
        return True

    if any(pnp_upper.startswith(pfx) for pfx in ("SCFILTER\\", "SMARTCARD\\", "USBCCID\\")):
        return True

    return False

def is_usb_infrastructure(entity) -> bool:
    """Returns True if the Win32_PnPEntity is USB infrastructure that should be skipped."""
    name_lower = (getattr(entity, "Name", None) or "").lower()
    pnp_id     = (getattr(entity, "PNPDeviceID", None) or "").upper()

    full_name = getattr(entity, "Name", None) or ""
    if is_protected_token_str(pnp_id, full_name):
        return False

    if "usb composite device" in name_lower:
        return False

    if name_lower == "generic usb device" or name_lower == "usb device":
        return False

    return any(kw in name_lower for kw in C.USB_INFRA_KEYWORDS)

def is_usb_infrastructure_str(name: str, pnp_id: str = "") -> bool:
    """String-based version of is_usb_infrastructure."""
    if is_protected_token_str(pnp_id, name):
        return False

    name_lower = name.lower()
    if "usb composite device" in name_lower:
        return False

    if name_lower == "generic usb device" or name_lower == "usb device":
        return False

    return any(kw in name_lower for kw in C.USB_INFRA_KEYWORDS)

def extract_pnp_serial(pnp_id: str) -> str:
    """Extract the instance identifier from the PNP Device ID."""
    parts = pnp_id.rsplit("\\", 1)
    if len(parts) == 2:
        instance       = parts[1]
        instance_clean = re.sub(r"&\d+$", "", instance)
        return instance_clean
    return ""

def is_smart_card_by_keywords(name: str, manufacturer: str) -> bool:
    """Returns True if the name or manufacturer matches smart card / crypto token keywords."""
    name_lower = name.lower()
    mfr_lower  = manufacturer.lower()
    name_match = any(kw in name_lower for kw in C.SMART_CARD_NAME_KEYWORDS)
    mfr_match  = any(kw in mfr_lower  for kw in C.SMART_CARD_MFR_KEYWORDS)
    return name_match or mfr_match

def is_epass2003(
    pnp_id: str,
    name: str,
    hardware_ids: list | None = None,
    compatible_ids: list | None = None,
) -> bool:
    """Returns True if the device is an ePass2003 or Feitian token."""
    pnp_upper  = pnp_id.upper()
    name_lower = name.lower()

    if C.FEITIAN_VID in pnp_upper:
        return True

    if any(kw in name_lower for kw in C.EPASS_NAME_KEYWORDS):
        return True

    if hardware_ids:
        for hw_id in hardware_ids:
            if C.FEITIAN_VID in hw_id.upper():
                return True

    if compatible_ids:
        for compat_id in compatible_ids:
            if C.FEITIAN_VID in compat_id.upper():
                return True

    all_ids = (hardware_ids or []) + (compatible_ids or [])
    has_ccid = any(
        any(ccid_kw in id_str.lower() for ccid_kw in C.CCID_IDENTIFIERS)
        for id_str in all_ids
    )
    if has_ccid and any(kw in name_lower for kw in ("epass", "feitian", "096e")):
        return True

    return False

def setupapi_get_instance_id(dll, h_dev_info, dev_info_ptr) -> str:
    """Retrieve the device instance ID for a device in a SetupAPI device info set."""
    req = ctypes.c_ulong(0)
    dll.SetupDiGetDeviceInstanceIdW(h_dev_info, dev_info_ptr, None, 0, ctypes.byref(req))
    if req.value == 0:
        return ""
    buf = ctypes.create_unicode_buffer(req.value)
    if dll.SetupDiGetDeviceInstanceIdW(
        h_dev_info, dev_info_ptr,
        ctypes.cast(buf, ctypes.c_void_p), req.value, None
    ):
        return buf.value
    return ""

def setupapi_get_property_str(dll, h_dev_info, dev_info_ptr, prop_id: int) -> str:
    """Retrieve a REG_SZ (string) device registry property."""
    reg_type = ctypes.c_ulong(0)
    req      = ctypes.c_ulong(0)

    dll.SetupDiGetDeviceRegistryPropertyW(
        h_dev_info, dev_info_ptr, prop_id,
        ctypes.byref(reg_type), None, 0, ctypes.byref(req)
    )
    size = req.value
    if size == 0:
        return ""

    buf = ctypes.create_string_buffer(size)
    ok  = dll.SetupDiGetDeviceRegistryPropertyW(
        h_dev_info, dev_info_ptr, prop_id,
        ctypes.byref(reg_type), buf, size, ctypes.byref(req)
    )
    if not ok:
        return ""
    try:
        raw  = bytes(buf)[:size]
        text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return text.strip()
    except Exception:
        return ""

def setupapi_get_property_multi(dll, h_dev_info, dev_info_ptr, prop_id: int) -> list[str]:
    """Retrieve a REG_MULTI_SZ (multi-string) device registry property."""
    reg_type = ctypes.c_ulong(0)
    req      = ctypes.c_ulong(0)

    dll.SetupDiGetDeviceRegistryPropertyW(
        h_dev_info, dev_info_ptr, prop_id,
        ctypes.byref(reg_type), None, 0, ctypes.byref(req)
    )
    size = req.value
    if size == 0:
        return []

    buf = ctypes.create_string_buffer(size)
    ok  = dll.SetupDiGetDeviceRegistryPropertyW(
        h_dev_info, dev_info_ptr, prop_id,
        ctypes.byref(reg_type), buf, size, ctypes.byref(req)
    )
    if not ok:
        return []
    try:
        raw  = bytes(buf)[:size]
        text = raw.decode("utf-16-le", errors="replace")
        return [s for s in text.split("\x00") if s]
    except Exception:
        return []
