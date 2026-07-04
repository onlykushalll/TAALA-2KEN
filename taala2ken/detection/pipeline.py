"""
TAALA-2KEN — Device detection pipeline implementation.

Coordinates the 6 stages of device enumeration:
  Stage 1: WMI Physical Disk Drives
  Stage 2: WMI PnP Entities
  Stage 3: WMI Smart Card Readers
  Stage 4: WMI USB Controller associations
  Stage 5: Windows SetupAPI ctypes deep scan
  Stage 6: Emergency SetupAPI full device class dump
"""

import sys
import ctypes
from taala2ken import constants as C
from taala2ken.log import log
from taala2ken.models import USBDevice, GenericUSBDevice, SmartCardDevice
from taala2ken.detection import helpers as H

# Import wmi conditionally
try:
    import wmi
except ImportError:
    wmi = None

# Statistics tracker
_debug_stats: dict = {
    "total_scanned": 0,
    "total_accepted": 0,
    "rejected": [],
}

def _stats_reset() -> None:
    _debug_stats["total_scanned"] = 0
    _debug_stats["total_accepted"] = 0
    _debug_stats["rejected"] = []

def _stats_scanned(count: int = 1) -> None:
    _debug_stats["total_scanned"] += count

def _stats_accepted(count: int = 1) -> None:
    _debug_stats["total_accepted"] += count

def _stats_rejected(pnp_id: str, reason: str) -> None:
    _debug_stats["rejected"].append((pnp_id, reason))

def _stats_print() -> None:
    if not C.DEBUG_MODE:
        return
    log.debug("=" * 74)
    log.debug("[DEBUG STATS] ENUMERATION STATISTICS")
    log.debug(f"[DEBUG STATS]   Total devices scanned (before filtering) : {_debug_stats['total_scanned']}")
    log.debug(f"[DEBUG STATS]   Total devices accepted (after filtering)  : {_debug_stats['total_accepted']}")
    log.debug(f"[DEBUG STATS]   Total devices rejected                    : {len(_debug_stats['rejected'])}")
    if _debug_stats["rejected"]:
        log.debug("[DEBUG STATS]   Rejected devices:")
        for pnp_id, reason in _debug_stats["rejected"]:
            log.debug(f"[DEBUG STATS]     REJECTED: {pnp_id[:65]}  - {reason}")
    log.debug("=" * 74)

def _build_token_device(
    pnp_device_id:    str,
    name:             str,
    description:      str,
    manufacturer:     str,
    device_id:        str,
    status:           str,
    detection_source: str,
    hardware_ids:     list | None = None,
    compatible_ids:   list | None = None,
) -> GenericUSBDevice:
    """Factory to build SmartCardDevice or GenericUSBDevice based on content/attributes."""
    if H.is_epass2003(pnp_device_id, name, hardware_ids, compatible_ids) or \
       H.is_smart_card_by_keywords(name, manufacturer):
        return SmartCardDevice(
            pnp_device_id    = pnp_device_id,
            name             = name or "Crypto Token",
            description      = description,
            manufacturer     = manufacturer,
            device_id        = device_id,
            status           = status,
            detection_source = detection_source,
        )

    pnp_upper = pnp_device_id.upper()
    if any(pnp_upper.startswith(pfx) for pfx in ("SCFILTER\\", "SMARTCARD\\", "USBCCID\\", "ROOT\\SMARTCARDREADER")):
        return SmartCardDevice(
            pnp_device_id    = pnp_device_id,
            name             = name or "Smart Card Device",
            description      = description,
            manufacturer     = manufacturer,
            device_id        = device_id,
            status           = status,
            detection_source = detection_source,
        )

    all_ids = (hardware_ids or []) + (compatible_ids or [])
    for id_str in all_ids:
        if H.contains_ccid_identifier(id_str):
            return SmartCardDevice(
                pnp_device_id    = pnp_device_id,
                name             = name or "CCID Device",
                description      = description,
                manufacturer     = manufacturer,
                device_id        = device_id,
                status           = status,
                detection_source = detection_source,
            )

    return GenericUSBDevice(
        pnp_device_id    = pnp_device_id,
        name             = name or "USB Device",
        description      = description,
        manufacturer     = manufacturer,
        device_id        = device_id,
        status           = status,
        detection_source = detection_source,
    )

# -- STAGE 1: WMI Storage Devices ---------------------------------------------
def _enumerate_storage_devices() -> list:
    devices: list = []
    if wmi is None:
        return devices
    try:
        wmi_conn    = wmi.WMI()
        disk_drives = wmi_conn.Win32_DiskDrive(InterfaceType="USB")
        log.debug(f"[WMI][STORAGE] Win32_DiskDrive returned {len(disk_drives)} USB disk(s).")

        for disk in disk_drives:
            _stats_scanned()
            media_type = (disk.MediaType or "").lower()
            if "removable" not in media_type and "external" not in media_type:
                if disk.MediaType is not None:
                    log.debug(f"  Skipping non-removable USB: {disk.DeviceID} ({disk.MediaType})")
                    _stats_rejected(disk.DeviceID or "", "non-removable media type")
                    continue

            pnp_id       = disk.PNPDeviceID or ""
            model        = (disk.Model or "").strip()
            drive_letter = H.map_disk_to_drive_letter(wmi_conn, disk.DeviceID)
            vol_serial   = H.get_volume_serial(drive_letter) if drive_letter else ""
            label        = ""
            if drive_letter:
                try:
                    import win32api
                    info  = win32api.GetVolumeInformation(drive_letter + "\\")
                    label = info[0] or ""
                except Exception:
                    pass

            device = USBDevice(
                device_id     = disk.DeviceID or "",
                pnp_device_id = pnp_id,
                volume_serial = vol_serial,
                label         = label,
                drive_letter  = drive_letter,
                model         = model,
            )
            devices.append(device)
            _stats_accepted()
            log.debug(f"  [WMI][STORAGE] Enumerated: {device}")
    except Exception as e:
        log.error(f"_enumerate_storage_devices() WMI error: {e}")
    return devices

# -- STAGE 2: WMI Generic USB Devices (PnPEntity) -----------------------------
def _enumerate_generic_usb_devices(exclude_pnp_serials: set | None = None) -> list:
    devices: list = []
    if wmi is None:
        return devices
    if exclude_pnp_serials is None:
        exclude_pnp_serials = set()

    seen_pnp_ids: set = set()
    try:
        wmi_conn = wmi.WMI()
        pnp_queries: list[str] = [
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB\\\\%'",
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'SCFILTER\\\\%'",
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'SMARTCARD\\\\%'",
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USBCCID\\\\%'",
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'ROOT\\\\SMARTCARDREADER\\\\%'",
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'ROOT\\\\USB\\\\%'",
        ]

        for query in pnp_queries:
            try:
                entities = wmi_conn.query(query)
            except Exception as e:
                log.debug(f"[WMI][TOKEN] PnP query failed - skipping: {e}")
                continue

            for entity in entities:
                try:
                    _stats_scanned()
                    pnp_id = (getattr(entity, "PNPDeviceID", None) or "").strip()
                    if not pnp_id:
                        _stats_rejected("(empty)", "empty PNP ID")
                        continue
                    if pnp_id in seen_pnp_ids:
                        continue
                    seen_pnp_ids.add(pnp_id)

                    pnp_upper = pnp_id.upper()
                    has_feitian_vid = C.FEITIAN_VID in pnp_upper

                    if not has_feitian_vid and H.is_usb_infrastructure(entity):
                        log.debug(f"  [WMI][TOKEN] Skipping infrastructure: {pnp_id}")
                        _stats_rejected(pnp_id, "USB infrastructure (prefix pass)")
                        continue

                    instance_serial = H.extract_pnp_serial(pnp_id).upper()
                    if instance_serial and instance_serial in exclude_pnp_serials:
                        log.debug(f"  [WMI][TOKEN] Skip (already STORAGE): {pnp_id}")
                        _stats_rejected(pnp_id, "already listed as STORAGE")
                        continue

                    name = (
                        getattr(entity, "Name",        None) or
                        getattr(entity, "Description", None) or
                        "Unknown USB Device"
                    ).strip()

                    description  = (getattr(entity, "Description", None) or
                                    getattr(entity, "Name",        None) or "").strip()
                    manufacturer = (getattr(entity, "Manufacturer", None) or "").strip()
                    device_id    = (getattr(entity, "DeviceID",     None) or pnp_id).strip()
                    status       = (getattr(entity, "Status",       None) or "").strip()

                    device = GenericUSBDevice(
                        pnp_device_id    = pnp_id,
                        name             = name,
                        description      = description,
                        manufacturer     = manufacturer,
                        device_id        = device_id,
                        status           = status,
                        detection_source = "WMI",
                    )
                    devices.append(device)
                    _stats_accepted()
                    log.debug(f"  [WMI][TOKEN] Enumerated: {device}")
                except Exception as e:
                    log.debug(f"  [WMI][TOKEN] Skipping entity due to error: {e}")
                    continue

        log.debug("[WMI][TOKEN] Running full PnPEntity content-based scan...")
        try:
            all_pnp = wmi_conn.query(
                "SELECT DeviceID, Name, Description, Manufacturer, "
                "PNPDeviceID, Status, HardwareID, CompatibleID FROM Win32_PnPEntity"
            )
            _stats_scanned(len(all_pnp))

            for entity in all_pnp:
                try:
                    pnp_id = (getattr(entity, "PNPDeviceID", None) or "").strip()
                    if not pnp_id or pnp_id in seen_pnp_ids:
                        continue

                    name         = (getattr(entity, "Name",         None) or "").strip()
                    description  = (getattr(entity, "Description",  None) or "").strip()
                    manufacturer = (getattr(entity, "Manufacturer", None) or "").strip()
                    device_id_v  = (getattr(entity, "DeviceID",     None) or "").strip()
                    status       = (getattr(entity, "Status",       None) or "").strip()

                    hw_ids_raw     = getattr(entity, "HardwareID",   None) or []
                    compat_ids_raw = getattr(entity, "CompatibleID", None) or []
                    if isinstance(hw_ids_raw, str):
                        hw_ids_raw = [hw_ids_raw]
                    if isinstance(compat_ids_raw, str):
                        compat_ids_raw = [compat_ids_raw]

                    if not H.device_matches_acceptance_criteria(
                        pnp_id, name, hw_ids_raw, compat_ids_raw
                    ):
                        continue

                    seen_pnp_ids.add(pnp_id)

                    if not H.is_protected_token_str(pnp_id, name) and H.is_usb_infrastructure(entity):
                        _stats_rejected(pnp_id, "USB infrastructure (content pass)")
                        continue

                    instance_serial = H.extract_pnp_serial(pnp_id).upper()
                    if instance_serial and instance_serial in exclude_pnp_serials:
                        _stats_rejected(pnp_id, "already listed as STORAGE (content pass)")
                        continue

                    display_name = name or description or "Unknown USB Device"

                    device = _build_token_device(
                        pnp_device_id    = pnp_id,
                        name             = display_name,
                        description      = description,
                        manufacturer     = manufacturer,
                        device_id        = device_id_v or pnp_id,
                        status           = status,
                        detection_source = "WMI",
                        hardware_ids     = hw_ids_raw,
                        compatible_ids   = compat_ids_raw,
                    )
                    devices.append(device)
                    _stats_accepted()
                    log.debug(f"  [WMI][TOKEN][CONTENT] Enumerated: {device}")
                except Exception as e:
                    log.debug(f"  [WMI][TOKEN][CONTENT] Error: {e}")
                    continue
        except Exception as e:
            log.debug(f"[WMI][TOKEN] Full PnPEntity content scan error: {e}")
    except Exception as e:
        log.error(f"_enumerate_generic_usb_devices() WMI error: {e}")
    return devices

# -- STAGE 3: WMI Smart Card Readers ------------------------------------------
def _enumerate_smart_card_devices(exclude_pnp_serials: set | None = None) -> list:
    devices: list = []
    if wmi is None:
        return devices
    if exclude_pnp_serials is None:
        exclude_pnp_serials = set()

    seen_pnp_ids: set = set()
    try:
        wmi_conn   = wmi.WMI()
        try:
            sc_readers = wmi_conn.Win32_SmartCardReader()
            for reader in sc_readers:
                try:
                    _stats_scanned()
                    name         = (getattr(reader, "Name",         None) or "").strip()
                    device_id    = (getattr(reader, "DeviceID",     None) or "").strip()
                    manufacturer = (getattr(reader, "Manufacturer", None) or "").strip()
                    pnp_id       = (getattr(reader, "PNPDeviceID",  None) or "").strip()
                    if not pnp_id:
                        pnp_id = device_id
                    if not pnp_id:
                        _stats_rejected("(no-pnp)", f"no PNP ID for reader '{name}'")
                        continue
                    if pnp_id in seen_pnp_ids:
                        continue
                    seen_pnp_ids.add(pnp_id)

                    instance_serial = H.extract_pnp_serial(pnp_id).upper()
                    if instance_serial and instance_serial in exclude_pnp_serials:
                        _stats_rejected(pnp_id, "already listed (SC stage 1)")
                        continue

                    device = SmartCardDevice(
                        pnp_device_id    = pnp_id,
                        name             = name or "Smart Card Reader",
                        description      = name or "Smart Card Reader",
                        manufacturer     = manufacturer,
                        device_id        = device_id,
                        status           = "",
                        detection_source = "WMI",
                    )
                    devices.append(device)
                    _stats_accepted()
                    log.debug(f"[WMI][SC] Enumerated (primary): {device}")
                except Exception as e:
                    log.debug(f"[WMI][SC] Error processing reader: {e}")
                    continue
        except AttributeError:
            log.debug("[WMI][SC] Win32_SmartCardReader not available — keyword fallback only.")

        # Keyword Fallback
        all_pnp = wmi_conn.query("SELECT DeviceID, Name, Description, Manufacturer, PNPDeviceID, Status FROM Win32_PnPEntity")
        for entity in all_pnp:
            try:
                _stats_scanned()
                pnp_id = (getattr(entity, "PNPDeviceID", None) or "").strip()
                if not pnp_id or pnp_id in seen_pnp_ids:
                    continue

                name         = (getattr(entity, "Name",         None) or "").strip()
                description  = (getattr(entity, "Description",  None) or "").strip()
                manufacturer = (getattr(entity, "Manufacturer", None) or "").strip()
                device_id    = (getattr(entity, "DeviceID",     None) or "").strip()
                status       = (getattr(entity, "Status",       None) or "").strip()

                name_lower = name.lower()
                mfr_lower  = manufacturer.lower()

                is_feitian_vid = C.FEITIAN_VID in pnp_id.upper()
                name_match     = any(kw in name_lower for kw in C.SMART_CARD_NAME_KEYWORDS)
                mfr_match      = any(kw in mfr_lower  for kw in C.SMART_CARD_MFR_KEYWORDS)

                if not (name_match or mfr_match or is_feitian_vid):
                    continue

                if not is_feitian_vid and not H.is_protected_token_str(pnp_id, name):
                    if H.is_usb_infrastructure(entity):
                        _stats_rejected(pnp_id, "USB infrastructure (SC fallback)")
                        continue

                instance_serial = H.extract_pnp_serial(pnp_id).upper()
                if instance_serial and instance_serial in exclude_pnp_serials:
                    _stats_rejected(pnp_id, "already listed (SC fallback)")
                    continue

                seen_pnp_ids.add(pnp_id)
                device = SmartCardDevice(
                    pnp_device_id    = pnp_id,
                    name             = name or description or "Smart Card Device",
                    description      = description or name or "",
                    manufacturer     = manufacturer,
                    device_id        = device_id or pnp_id,
                    status           = status,
                    detection_source = "WMI",
                )
                devices.append(device)
                _stats_accepted()
                log.debug(f"[WMI][SC] Enumerated (fallback): {device}")
            except Exception as e:
                continue
    except Exception as e:
        log.error(f"[WMI][SC] Smart card detection error: {e}")
    return devices

# -- STAGE 4: WMI USB Controller Devices --------------------------------------
def _enumerate_usb_controller_devices(
    exclude_pnp_serials: set | None = None,
    seen_pnp_ids_global: set | None = None,
) -> list:
    devices: list = []
    if wmi is None:
        return devices
    if exclude_pnp_serials is None:
        exclude_pnp_serials = set()
    if seen_pnp_ids_global is None:
        seen_pnp_ids_global = set()

    seen_local: set = set()
    try:
        wmi_conn    = wmi.WMI()
        ctrl_assocs = wmi_conn.query("SELECT * FROM Win32_USBControllerDevice")

        for assoc in ctrl_assocs:
            try:
                _stats_scanned()
                dependent = getattr(assoc, "Dependent", None)
                if dependent is None:
                    continue
                dependent_str = str(dependent)
                import re
                match = re.search(r'DeviceID="([^"]+)"', dependent_str, re.IGNORECASE)
                pnp_id = match.group(1).replace("\\\\", "\\") if match else ""
                if not pnp_id:
                    continue

                pnp_id_upper = pnp_id.upper()
                is_feitian = C.FEITIAN_VID in pnp_id_upper

                if pnp_id_upper in seen_pnp_ids_global and not is_feitian:
                    continue
                if pnp_id_upper in seen_local:
                    continue
                seen_local.add(pnp_id_upper)

                if pnp_id_upper.startswith("USBSTOR\\") and not is_feitian:
                    _stats_rejected(pnp_id, "USBSTOR handled by storage path")
                    continue

                instance_serial = H.extract_pnp_serial(pnp_id).upper()
                if instance_serial and instance_serial in exclude_pnp_serials:
                    _stats_rejected(pnp_id, "serial already listed (USBCTRL)")
                    continue

                name         = ""
                description  = ""
                manufacturer = ""
                status       = ""
                hw_ids_raw: list   = []
                compat_ids_raw: list = []
                try:
                    safe_pnp_id  = pnp_id.replace("\\", "\\\\")
                    pnp_entities = wmi_conn.query(
                        f"SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID='{safe_pnp_id}'"
                    )
                    if pnp_entities:
                        ent          = pnp_entities[0]
                        name         = (getattr(ent, "Name",         None) or "").strip()
                        description  = (getattr(ent, "Description",  None) or "").strip()
                        manufacturer = (getattr(ent, "Manufacturer", None) or "").strip()
                        status       = (getattr(ent, "Status",       None) or "").strip()
                        hw_ids_raw   = getattr(ent, "HardwareID",    None) or []
                        compat_ids_raw = getattr(ent, "CompatibleID", None) or []
                        if isinstance(hw_ids_raw, str):
                            hw_ids_raw = [hw_ids_raw]
                        if isinstance(compat_ids_raw, str):
                            compat_ids_raw = [compat_ids_raw]

                        if not H.is_protected_token_str(pnp_id, name) and H.is_usb_infrastructure(ent):
                            _stats_rejected(pnp_id, "USB infrastructure (USBCTRL enrichment)")
                            continue
                except Exception:
                    pass

                if not name:
                    parts = pnp_id.split("\\")
                    name  = parts[1] if len(parts) > 1 else pnp_id

                if not H.is_protected_token_str(pnp_id, name) and H.is_usb_infrastructure_str(name, pnp_id):
                    _stats_rejected(pnp_id, "USB infrastructure by name (USBCTRL)")
                    continue

                device = _build_token_device(
                    pnp_device_id    = pnp_id,
                    name             = name,
                    description      = description,
                    manufacturer     = manufacturer,
                    device_id        = pnp_id,
                    status           = status,
                    detection_source = "USBCTRL",
                    hardware_ids     = hw_ids_raw,
                    compatible_ids   = compat_ids_raw,
                )
                devices.append(device)
                _stats_accepted()
                log.debug(f"  [USBCTRL] Enumerated: {device}")
            except Exception:
                continue
    except Exception as e:
        log.error(f"_enumerate_usb_controller_devices() WMI error: {e}")
    return devices

# -- STAGE 5: Windows SetupAPI ctypes -----------------------------------------
def _enumerate_setupapi_devices(
    exclude_pnp_serials:   set | None = None,
    seen_pnp_ids_global:   set | None = None,
) -> list:
    devices: list = []
    dll = H.load_setupapi()
    if dll is None:
        return devices

    if exclude_pnp_serials is None:
        exclude_pnp_serials = set()
    if seen_pnp_ids_global is None:
        seen_pnp_ids_global = set()

    seen_local: set = set()

    scan_passes = [
        (C.DIGCF_PRESENT | C.DIGCF_ALLCLASSES, "USB",  "present-usb"),
        (C.DIGCF_ALLCLASSES,                  "USB",  "all+hidden-usb"),
        (C.DIGCF_ALLCLASSES,                  None,   "global-all-NO-present"),
        (C.DIGCF_PRESENT | C.DIGCF_ALLCLASSES, None,   "global-all-present"),
    ]

    for flags, enumerator, pass_name in scan_passes:
        h_dev_info = None
        try:
            h_dev_info = dll.SetupDiGetClassDevsW(None, enumerator, None, flags)
            if h_dev_info == C.INVALID_HANDLE_VALUE or h_dev_info is None:
                continue

            index = 0
            while True:
                dev_info        = C.SP_DEVINFO_DATA()
                dev_info.cbSize = ctypes.sizeof(dev_info)

                ok = dll.SetupDiEnumDeviceInfo(h_dev_info, index, ctypes.byref(dev_info))
                if not ok:
                    break
                index += 1
                _stats_scanned()
                dev_info_ptr = ctypes.byref(dev_info)

                instance_id = H.setupapi_get_instance_id(dll, h_dev_info, dev_info_ptr)
                if not instance_id:
                    continue

                instance_id_upper = instance_id.upper()
                hardware_ids_raw  = H.setupapi_get_property_multi(dll, h_dev_info, dev_info_ptr, C.SPDRP_HARDWAREID)
                compat_ids_raw    = H.setupapi_get_property_multi(dll, h_dev_info, dev_info_ptr, C.SPDRP_COMPATIBLEIDS)
                friendly_name     = H.setupapi_get_property_str(dll, h_dev_info, dev_info_ptr, C.SPDRP_FRIENDLYNAME)
                device_desc       = H.setupapi_get_property_str(dll, h_dev_info, dev_info_ptr, C.SPDRP_DEVICEDESC)
                early_name        = friendly_name or device_desc or ""

                # Content check + prefix optimization
                accepted = H.device_matches_acceptance_criteria(instance_id, early_name, hardware_ids_raw, compat_ids_raw)
                if not accepted:
                    instance_upper = instance_id.upper()
                    for pfx in ("USB\\", "USBCCID\\", "SCFILTER\\", "SMARTCARD\\", "ROOT\\SMARTCARDREADER", "ROOT\\USB", "ROOT\\SYSTEM"):
                        if instance_upper.startswith(pfx):
                            accepted = True
                            break

                if not accepted:
                    _stats_rejected(instance_id, f"no acceptance criteria match ({pass_name})")
                    continue

                is_feitian = H.contains_vid_096e(instance_id) or H.any_id_contains_vid_096e(hardware_ids_raw) or H.any_id_contains_vid_096e(compat_ids_raw)
                if instance_id_upper.startswith("USBSTOR\\") and not is_feitian:
                    _stats_rejected(instance_id, "USBSTOR handled by storage path")
                    continue

                if instance_id_upper in seen_pnp_ids_global or instance_id_upper in seen_local:
                    continue
                seen_local.add(instance_id_upper)

                instance_serial = H.extract_pnp_serial(instance_id).upper()
                if instance_serial and instance_serial in exclude_pnp_serials:
                    _stats_rejected(instance_id, "serial duplicate (SETUPAPI)")
                    continue

                manufacturer = H.setupapi_get_property_str(dll, h_dev_info, dev_info_ptr, C.SPDRP_MFG)
                name         = friendly_name or device_desc
                if not name:
                    parts = instance_id.split("\\")
                    name  = parts[1] if len(parts) > 1 else instance_id

                if not H.is_protected_token_str(instance_id, name) and H.is_usb_infrastructure_str(name, instance_id):
                    _stats_rejected(instance_id, "USB infrastructure (SETUPAPI)")
                    continue

                device = _build_token_device(
                    pnp_device_id    = instance_id,
                    name             = name,
                    description      = device_desc,
                    manufacturer     = manufacturer,
                    device_id        = instance_id,
                    status           = "",
                    detection_source = "SETUPAPI",
                    hardware_ids     = hardware_ids_raw,
                    compatible_ids   = compat_ids_raw,
                )
                devices.append(device)
                _stats_accepted()
                seen_pnp_ids_global.add(instance_id_upper)
                if instance_serial:
                    exclude_pnp_serials.add(instance_serial)
        except Exception as e:
            log.debug(f"[SETUPAPI] Scan error ({pass_name}): {e}")
        finally:
            if h_dev_info is not None and h_dev_info != C.INVALID_HANDLE_VALUE:
                dll.SetupDiDestroyDeviceInfoList(h_dev_info)
    return devices

# -- STAGE 6: Last Resort SetupAPI Dump ---------------------------------------
def _last_resort_setupapi_dump(
    seen_pnp_ids_global: set,
    exclude_pnp_serials: set,
) -> list:
    devices: list = []
    dll = H.load_setupapi()
    if dll is None:
        return devices

    log.warning("[LAST RESORT] No devices found — performing FULL device dump...")
    h_dev_info = None
    try:
        h_dev_info = dll.SetupDiGetClassDevsW(None, None, None, C.DIGCF_ALLCLASSES)
        if h_dev_info == C.INVALID_HANDLE_VALUE or h_dev_info is None:
            return []

        index = 0
        while True:
            dev_info        = C.SP_DEVINFO_DATA()
            dev_info.cbSize = ctypes.sizeof(dev_info)

            ok = dll.SetupDiEnumDeviceInfo(h_dev_info, index, ctypes.byref(dev_info))
            if not ok:
                break
            index += 1
            _stats_scanned()
            dev_info_ptr = ctypes.byref(dev_info)

            instance_id = H.setupapi_get_instance_id(dll, h_dev_info, dev_info_ptr)
            if not instance_id:
                continue

            instance_id_upper = instance_id.upper()
            if instance_id_upper in seen_pnp_ids_global:
                continue

            hardware_ids_raw = H.setupapi_get_property_multi(dll, h_dev_info, dev_info_ptr, C.SPDRP_HARDWAREID)
            compat_ids_raw   = H.setupapi_get_property_multi(dll, h_dev_info, dev_info_ptr, C.SPDRP_COMPATIBLEIDS)
            friendly_name    = H.setupapi_get_property_str(dll, h_dev_info, dev_info_ptr, C.SPDRP_FRIENDLYNAME)
            device_desc      = H.setupapi_get_property_str(dll, h_dev_info, dev_info_ptr, C.SPDRP_DEVICEDESC)
            name             = friendly_name or device_desc or ""

            if not H.device_matches_acceptance_criteria(instance_id, name, hardware_ids_raw, compat_ids_raw):
                continue

            if not H.is_protected_token_str(instance_id, name) and H.is_usb_infrastructure_str(name, instance_id):
                continue

            instance_serial = H.extract_pnp_serial(instance_id).upper()
            if instance_serial and instance_serial in exclude_pnp_serials:
                continue

            manufacturer = H.setupapi_get_property_str(dll, h_dev_info, dev_info_ptr, C.SPDRP_MFG)
            if not name:
                parts = instance_id.split("\\")
                name  = parts[1] if len(parts) > 1 else instance_id

            device = _build_token_device(
                pnp_device_id    = instance_id,
                name             = name,
                description      = device_desc or "",
                manufacturer     = manufacturer,
                device_id        = instance_id,
                status           = "",
                detection_source = "SETUPAPI",
                hardware_ids     = hardware_ids_raw,
                compatible_ids   = compat_ids_raw,
            )
            devices.append(device)
            _stats_accepted()
            seen_pnp_ids_global.add(instance_id_upper)
            if instance_serial:
                exclude_pnp_serials.add(instance_serial)
    except Exception as e:
        log.error(f"[LAST RESORT] Scan error: {e}")
    finally:
        if h_dev_info is not None and h_dev_info != C.INVALID_HANDLE_VALUE:
            dll.SetupDiDestroyDeviceInfoList(h_dev_info)
    return devices

# Deduplication logic
def _deduplicate_by_priority(all_devices: list) -> list:
    pnp_best: dict = {}
    for dev in all_devices:
        pnp_upper = dev.pnp_device_id.upper()
        src       = getattr(dev, "detection_source", "WMI")
        priority  = C.SOURCE_PRIORITY.get(src, 0)

        existing = pnp_best.get(pnp_upper)
        if existing is None or priority > existing[0]:
            pnp_best[pnp_upper] = (priority, dev)

    fp_best: dict = {}
    for _priority, dev in pnp_best.values():
        fp  = dev.fingerprint
        src = getattr(dev, "detection_source", "WMI")
        pri = C.SOURCE_PRIORITY.get(src, 0)

        existing = fp_best.get(fp)
        if existing is None or pri > existing[0]:
            fp_best[fp] = (pri, dev)

    return [dev for (_pri, dev) in fp_best.values()]

def _print_final_verification(all_devices: list) -> None:
    src_counts: dict = {"WMI": 0, "USBCTRL": 0, "SETUPAPI": 0}
    token_count = 0
    token_details: list = []

    for dev in all_devices:
        src = getattr(dev, "detection_source", "WMI")
        src_counts[src] = src_counts.get(src, 0) + 1
        if isinstance(dev, SmartCardDevice):
            token_count += 1
            token_details.append(f"    * [{src}] {dev.name}  (pnp={dev.pnp_device_id[:55]})")

    log.info("-" * 70)
    log.info("[VERIFICATION] Enumeration complete.")
    log.info(f"[VERIFICATION] Total devices detected: {len(all_devices)}")
    log.info(f"[VERIFICATION] By source: WMI={src_counts.get('WMI',0)} | USBCTRL={src_counts.get('USBCTRL',0)} | SETUPAPI={src_counts.get('SETUPAPI',0)}")
    if token_count > 0:
        log.info(f"[VERIFICATION] Detected crypto tokens/smart cards: {token_count}")
        for detail in token_details:
            log.info(f"[VERIFICATION] {detail}")
    else:
        log.info("[VERIFICATION] No crypto tokens/smart cards detected.")
    log.info("-" * 70)

def enumerate_usb_devices() -> list:
    """Run full 6-stage detection pipeline."""
    _stats_reset()

    # 1. WMI Storage
    storage_devices = _enumerate_storage_devices()
    storage_serials: set = set()
    seen_pnp_upper:  set = set()
    for dev in storage_devices:
        s = H.extract_pnp_serial(dev.pnp_device_id).upper()
        if s:
            storage_serials.add(s)
        seen_pnp_upper.add(dev.pnp_device_id.upper())

    # 2. WMI Generic USB PnPEntity
    generic_devices = _enumerate_generic_usb_devices(exclude_pnp_serials=storage_serials)
    combined_serials: set = set(storage_serials)
    for dev in generic_devices:
        s = H.extract_pnp_serial(dev.pnp_device_id).upper()
        if s:
            combined_serials.add(s)
        seen_pnp_upper.add(dev.pnp_device_id.upper())

    # 3. WMI Smart Cards
    sc_devices = _enumerate_smart_card_devices(exclude_pnp_serials=combined_serials)
    for dev in sc_devices:
        s = H.extract_pnp_serial(dev.pnp_device_id).upper()
        if s:
            combined_serials.add(s)
        seen_pnp_upper.add(dev.pnp_device_id.upper())

    # 4. WMI Controller-attached
    ctrl_devices = _enumerate_usb_controller_devices(exclude_pnp_serials=combined_serials, seen_pnp_ids_global=seen_pnp_upper)
    for dev in ctrl_devices:
        s = H.extract_pnp_serial(dev.pnp_device_id).upper()
        if s:
            combined_serials.add(s)
        seen_pnp_upper.add(dev.pnp_device_id.upper())

    # 5. SetupAPI deep scan
    setupapi_devices = _enumerate_setupapi_devices(exclude_pnp_serials=combined_serials, seen_pnp_ids_global=seen_pnp_upper)

    all_devices_raw = storage_devices + generic_devices + sc_devices + ctrl_devices + setupapi_devices

    # 6. Last resort
    if len(all_devices_raw) == 0:
        last_resort_devices = _last_resort_setupapi_dump(seen_pnp_ids_global=seen_pnp_upper, exclude_pnp_serials=combined_serials)
        all_devices_raw = last_resort_devices

    all_devices = _deduplicate_by_priority(all_devices_raw)
    _print_final_verification(all_devices)
    _stats_print()

    return all_devices

def print_detected_devices() -> None:
    """Print all connected USB devices with detection source details."""
    print("\n" + "=" * 74)
    print("  DETECTED USB DEVICES  (Storage + Tokens + Smart Cards + Hidden)  [v4.0]")
    print("=" * 74)

    devices = enumerate_usb_devices()
    if not devices:
        print("  [!] No USB devices found.")
        print("\n" + "=" * 74 + "\n")
        return

    storage_devs  = [d for d in devices if d.device_type == "STORAGE"]
    sc_devs       = [d for d in devices if d.device_type == "SMART CARD / TOKEN"]
    generic_devs  = [d for d in devices if d.device_type not in ("STORAGE", "SMART CARD / TOKEN")]

    wmi_generic   = [d for d in generic_devs if d.detection_source == "WMI"]
    ctrl_devs     = [d for d in devices if d.detection_source == "USBCTRL"]
    setupapi_devs = [d for d in devices if d.detection_source == "SETUPAPI"]

    if storage_devs:
        print(f"\n  +- [WMI] USB STORAGE DEVICES ({len(storage_devs)}) " + "-" * (42 - len(str(len(storage_devs)))))
        for i, dev in enumerate(storage_devs, 1):
            print(f"\n  |  [{i}] [WMI][STORAGE]")
            print(f"  |      Model        : {dev.model or 'Unknown'}")
            print(f"  |      Label        : {dev.label or '(no label)'}")
            print(f"  |      Drive Letter : {dev.drive_letter or '(not assigned)'}")
            print(f"  |      Vol. Serial  : {dev.volume_serial or '(n/a)'}")
            print(f"  |      PnP ID       : {dev.pnp_device_id[:60]}")
            print(f"  |      Fingerprint  : {dev.fingerprint}")
        print("  +-" + "-" * 71)

    if wmi_generic:
        print(f"\n  +- [WMI] TOKEN / GENERIC USB ({len(wmi_generic)}) " + "-" * (35 - len(str(len(wmi_generic)))))
        for i, dev in enumerate(wmi_generic, 1):
            print(f"\n  |  [{i}] [WMI][TOKEN / GENERIC]")
            print(f"  |      Name         : {dev.name}")
            print(f"  |      Manufacturer : {dev.manufacturer or '(unknown)'}")
            print(f"  |      PnP ID       : {dev.pnp_device_id[:60]}")
            print(f"  |      Fingerprint  : {dev.fingerprint}")
        print("  +-" + "-" * 71)

    if sc_devs:
        print(f"\n  +- [WMI] SMART CARD / TOKEN DEVICES ({len(sc_devs)}) " + "-" * (35 - len(str(len(sc_devs)))))
        for i, dev in enumerate(sc_devs, 1):
            print(f"\n  |  [{i}] [WMI][SMART CARD / TOKEN]")
            print(f"  |      Name         : {dev.name}")
            print(f"  |      Manufacturer : {dev.manufacturer or '(unknown)'}")
            print(f"  |      PnP ID       : {dev.pnp_device_id[:60]}")
            print(f"  |      Fingerprint  : {dev.fingerprint}")
        print("  +-" + "-" * 71)

    if ctrl_devs:
        print(f"\n  +- [USBCTRL] USB CONTROLLER-ATTACHED ({len(ctrl_devs)}) " + "-" * (22 - len(str(len(ctrl_devs)))))
        for i, dev in enumerate(ctrl_devs, 1):
            print(f"\n  |  [{i}] [USBCTRL][{dev.device_type}]")
            print(f"  |      Name         : {dev.name}")
            print(f"  |      Manufacturer : {dev.manufacturer or '(unknown)'}")
            print(f"  |      PnP ID       : {dev.pnp_device_id[:60]}")
            print(f"  |      Fingerprint  : {dev.fingerprint}")
        print("  +-" + "-" * 71)

    if setupapi_devs:
        print(f"\n  +- [SETUPAPI] DRIVER-LAYER / HIDDEN ({len(setupapi_devs)}) " + "-" * (21 - len(str(len(setupapi_devs)))))
        for i, dev in enumerate(setupapi_devs, 1):
            print(f"\n  |  [{i}] [SETUPAPI][{dev.device_type}]")
            print(f"  |      Name         : {dev.name}")
            print(f"  |      Manufacturer : {dev.manufacturer or '(unknown)'}")
            print(f"  |      PnP ID       : {dev.pnp_device_id[:60]}")
            print(f"  |      Fingerprint  : {dev.fingerprint}")
        print("  +-" + "-" * 71)

    print(f"\n  Total: {len(devices)} device(s) detected across all sources.")
    print("\n" + "=" * 74 + "\n")
