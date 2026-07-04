"""
TAALA-2KEN — Monitoring engine and event-driven watchers.

Tracks USB presence, counts grace period ticks, and triggers lock on removal.
"""

import time
import threading
from taala2ken import constants as C
from taala2ken.log import log
from taala2ken.config import AuthConfig
from taala2ken.lock import lock_workstation
from taala2ken.detection.pipeline import enumerate_usb_devices

try:
    import pythoncom
    _PYTHONCOM_AVAILABLE = True
except ImportError:
    _PYTHONCOM_AVAILABLE = False

try:
    import wmi
except ImportError:
    wmi = None

class WMIDeviceEventWatcher(threading.Thread):
    """
    Event-driven WMI device change watcher.
    """
    _TYPE_ARRIVAL = 2
    _TYPE_REMOVAL = 3
    _EVENT_NAMES  = {2: "DeviceArrival", 3: "DeviceRemoval"}

    def __init__(self, on_change_callback):
        super().__init__(daemon=True, name="WMI-DeviceEventWatcher")
        self._callback   = on_change_callback
        self._stop_event = threading.Event()

    def run(self) -> None:
        if not _PYTHONCOM_AVAILABLE or wmi is None:
            log.warning("[EVENT] pythoncom/wmi not available — polling-only mode active.")
            return
        try:
            pythoncom.CoInitialize()
            self._run_event_loop()
        except Exception as e:
            log.debug(f"[EVENT] Watcher thread fatal error: {e}")
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
            log.debug("[EVENT] WMI event watcher thread exited.")

    def _run_event_loop(self) -> None:
        try:
            wmi_conn = wmi.WMI()
            wql      = "SELECT * FROM Win32_DeviceChangeEvent"
            watcher  = wmi_conn.watch_for(raw_wql=wql)
            log.debug("[EVENT] WMI event watcher started (Win32_DeviceChangeEvent).")
        except Exception as e:
            log.warning(f"[EVENT] Could not create WMI event subscription: {e} — using polling only.")
            return

        while not self._stop_event.is_set():
            try:
                event = watcher(timeout_ms=2000)
                if event is not None:
                    etype     = getattr(event, "EventType", None)
                    etype_str = self._EVENT_NAMES.get(etype, f"type={etype}")
                    if etype in (self._TYPE_ARRIVAL, self._TYPE_REMOVAL):
                        log.debug(f"[EVENT] USB device change detected: {etype_str}")
                        try:
                            self._callback()
                        except Exception as cb_err:
                            log.debug(f"[EVENT] Callback error: {cb_err}")
            except wmi.x_wmi_timed_out:
                pass
            except Exception as e:
                if not self._stop_event.is_set():
                    log.debug(f"[EVENT] Watcher loop error: {e}")
                    time.sleep(1.0)

    def stop(self) -> None:
        self._stop_event.set()


class USBMonitor:
    """
    Main monitoring engine.
    """

    def __init__(self, config: AuthConfig):
        self.config          = config
        self._stop_event     = threading.Event()
        self._usb_present    = False
        self._removal_time: float | None = None
        self._lock_triggered = False
        self._immediate_check = threading.Event()
        self._event_watcher   = WMIDeviceEventWatcher(on_change_callback=self._on_device_event)
        self._status_listeners = []

    def register_status_listener(self, callback):
        """Register callbacks for tray UI or named pipe updates."""
        self._status_listeners.append(callback)

    def _notify_listeners(self, status: str, remaining_seconds: float = 0.0):
        for listener in self._status_listeners:
            try:
                listener(status, remaining_seconds)
            except Exception:
                pass

    def _on_device_event(self) -> None:
        self._immediate_check.set()

    def _is_authorized_usb_present(self) -> bool:
        try:
            devices = enumerate_usb_devices()
            for dev in devices:
                if dev.fingerprint == self.config.authorized_fingerprint:
                    # If PKCS#11 signature verification is configured, execute it
                    if self.config.public_key_der:
                        try:
                            from taala2ken.pkcs11_auth import verify_token_challenge
                            if not verify_token_challenge(self.config.public_key_der):
                                log.warning("[MONITOR] PKCS#11 challenge verification failed!")
                                return False
                        except ImportError:
                            log.warning("[MONITOR] pkcs11_auth.py not found, bypassing cryptographic challenge!")
                        except Exception as e:
                            log.error(f"[MONITOR] PKCS#11 error: {e}")
                            return False
                    return True
        except Exception as e:
            log.debug(f"USB check error (transient, continuing): {e}")
        return False

    def run(self) -> None:
        log.info("USB monitor started. Press Ctrl+C to stop.")
        log.info(f"  Authorized device : {self.config.describe()}")
        log.info(f"  Grace period      : {C.REMOVAL_GRACE_PERIOD_SECONDS}s")

        if C.ENABLE_WMI_EVENT_WATCHER and _PYTHONCOM_AVAILABLE:
            self._event_watcher.start()
            log.info("  Event watcher     : ✓ ENABLED")
        else:
            log.info("  Event watcher     : ✗ DISABLED — polling only")

        self._usb_present = self._is_authorized_usb_present()
        if self._usb_present:
            log.info("✓ Authorized USB is present. Monitoring active.")
            self._notify_listeners("PRESENT")
        else:
            log.warning("⚠ Authorized USB NOT present at startup.")
            self._removal_time   = time.monotonic()
            self._lock_triggered = False
            self._notify_listeners("ABSENT", C.REMOVAL_GRACE_PERIOD_SECONDS)

        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as e:
                log.error(f"Monitor tick error (recovering): {e}")
            finally:
                self._immediate_check.wait(timeout=C.CHECK_INTERVAL_SECONDS)
                self._immediate_check.clear()

        log.info("USB monitor stopped.")

    def _tick(self) -> None:
        now_present = self._is_authorized_usb_present()

        if now_present:
            if not self._usb_present:
                log.info("✓ USB detected — authorized device reinserted.")
            self._usb_present    = True
            self._removal_time   = None
            self._lock_triggered = False
            self._notify_listeners("PRESENT")
        else:
            if self._usb_present:
                log.warning(f"✗ USB removed — starting grace period ({C.REMOVAL_GRACE_PERIOD_SECONDS}s)...")
                self._removal_time   = time.monotonic()
                self._lock_triggered = False
            self._usb_present = False

            if self._removal_time is not None and not self._lock_triggered:
                elapsed   = time.monotonic() - self._removal_time
                remaining = C.REMOVAL_GRACE_PERIOD_SECONDS - elapsed
                self._notify_listeners("GRACE", max(remaining, 0.0))
                if elapsed >= C.REMOVAL_GRACE_PERIOD_SECONDS:
                    log.warning("USB removed — locking system")
                    lock_workstation()
                    self._lock_triggered = True
                    self._notify_listeners("LOCKED")

    def stop(self) -> None:
        self._stop_event.set()
        self._immediate_check.set()
        self._event_watcher.stop()
