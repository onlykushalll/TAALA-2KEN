"""
TAALA-2KEN — CLI argument handler and entry point.

Handles setup wizard, status reporting, debug logs, and runs the monitor loop.
"""

import sys
import ctypes
from taala2ken import constants as C
from taala2ken.log import log, reconfigure
from taala2ken.config import AuthConfig
from taala2ken.detection.pipeline import enumerate_usb_devices, print_detected_devices
from taala2ken.monitor import USBMonitor

def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _warn_if_not_admin() -> None:
    if not _is_admin():
        log.warning("============================================================")
        log.warning(" NOT running as Administrator!")
        log.warning(" Some USB detection features may be limited.")
        log.warning(" SetupAPI deep scan requires admin for hidden devices.")
        log.warning(" Global device class scan may miss driver-layer tokens.")
        log.warning(" LAST RESORT fallback needs admin for full device dump.")
        log.warning(" Restart this script with 'Run as Administrator'")
        log.warning(" for full functionality.")
        log.warning("============================================================")

def first_run_setup(config: AuthConfig) -> bool:
    """Interactive setup wizard for registering an authorized USB key."""
    print("\n" + "*" * 74)
    print("  USB AUTH GUARD — SETUP WIZARD  (v4.0)")
    print("*" * 74)
    print("\n  Insert the USB device (drive OR token) to use as your security key,")
    print("  then press Enter to scan.\n")

    input("  [Press Enter to scan for USB devices...] ")

    devices = enumerate_usb_devices()
    if not devices:
        print("\n  [!] No USB devices detected.")
        print("      Make sure a USB device is inserted and try again.\n")
        return False

    print("\n  Detected USB devices:\n")
    for i, dev in enumerate(devices, 1):
        src = getattr(dev, "detection_source", "WMI")
        if dev.device_type == "STORAGE":
            drive = dev.drive_letter or "no drive letter"
            label = dev.label or "(no label)"
            model = dev.model or "Unknown model"
            print(f"    [{i}] [{src}][STORAGE]             {model}  /  {label}  ({drive})")
        elif dev.device_type == "SMART CARD / TOKEN":
            mfr     = dev.manufacturer or ""
            name    = getattr(dev, "name", None) or dev.model or "Unknown device"
            mfr_str = f"  -  {mfr}" if mfr else ""
            print(f"    [{i}] [{src}][SMART CARD / TOKEN]   {name}{mfr_str}")
        else:
            mfr     = dev.manufacturer or ""
            name    = getattr(dev, "name", None) or dev.model or "Unknown device"
            mfr_str = f"  -  {mfr}" if mfr else ""
            print(f"    [{i}] [{src}][TOKEN / GENERIC USB]  {name}{mfr_str}")

        print(f"         PnP ID      : {dev.pnp_device_id[:62]}")
        print(f"         Fingerprint : {dev.fingerprint[:32]}...")
        print()

    while True:
        try:
            choice_str = input(f"  Select device [1-{len(devices)}] (or 'q' to quit): ").strip()
            if choice_str.lower() == "q":
                print("  Setup aborted.\n")
                return False
            choice = int(choice_str)
            if 1 <= choice <= len(devices):
                selected = devices[choice - 1]
                break
            print(f"  Please enter a number between 1 and {len(devices)}.")
        except ValueError:
            print("  Invalid input — enter a number.")

    sel_type  = selected.device_type
    sel_src   = getattr(selected, "detection_source", "WMI")
    sel_label = selected.label or selected.model or "(unnamed)"
    print(f"\n  You selected  : '{sel_label}'  [{sel_type}][{sel_src}]")
    print(f"  PnP ID        : {selected.pnp_device_id}")

    public_key_der = ""
    if sel_type in ("SMART CARD / TOKEN", "TOKEN"):
        try:
            from taala2ken.pkcs11_auth import enroll_token
            confirm_crypt = input("\n  Enroll device with PKCS#11 challenge-response authentication? [y/N]: ").strip().lower()
            if confirm_crypt == "y":
                print("  Initializing PKCS#11 session, please ensure middleware drivers are installed...")
                public_key_der = enroll_token()
                if public_key_der:
                    print("  [+] Token enrolled cryptographically.")
                else:
                    print("  [-] PKCS#11 enrollment failed. Reverting to presence-only fingerprinting.")
        except Exception as e:
            print(f"  PKCS#11 enrollment error: {e}. Reverting to presence-only.")

    confirm = input("\n  Register this device as your security USB? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Registration cancelled.\n")
        return False

    config.register_device(selected, public_key_der=public_key_der)
    print("\n  [+] Device registered successfully!")
    print(f"  Config saved to: {config.path}")
    print("\n" + "*" * 74 + "\n")
    return True

def print_help() -> None:
    print("""
TAALA-2KEN USB Auth Guard -- Windows Security Manager
-----------------------------------------------------------------
Options:
  python -m taala2ken             Run the monitor (setup if first time)
  python -m taala2ken --setup     Force setup wizard to re-register USB key
  python -m taala2ken --list      List all connected USB storage, tokens & hidden keys
  python -m taala2ken --status    Show current authorization status and connection state
  python -m taala2ken --reset     Clear registered USB configuration
  python -m taala2ken --debug     Run with verbose debug logs
  python -m taala2ken --dry-run   Run monitor in dry-run mode (detection only, no lock)
  python -m taala2ken --help      Show this help message
""")

def main() -> None:
    args = set(sys.argv[1:])

    if "--help" in args or "-h" in args:
        print_help()
        sys.exit(0)

    if "--debug" in args:
        C.DEBUG_MODE = True
        reconfigure()
        log.debug("Debug mode enabled via CLI.")

    if "--dry-run" in args:
        C.DRY_RUN = True
        log.info("Dry-run mode enabled. Detection only, system will not be locked.")

    _warn_if_not_admin()
    config = AuthConfig()

    if "--list" in args:
        print_detected_devices()
        sys.exit(0)

    if "--status" in args:
        print("\n  TAALA-2KEN Status Summary")
        print("  " + "-" * 44)
        if config.is_configured:
            print(f"  Authorized Key: {config.describe()}")
            devices = enumerate_usb_devices()
            match = any(d.fingerprint == config.authorized_fingerprint for d in devices)
            print(f"  Key Status: {'[+] PRESENT' if match else '[-] NOT DETECTED'}")
        else:
            print("  No authorized USB registered. Run --setup first.")
        print()
        sys.exit(0)

    if "--reset" in args:
        if config.is_configured:
            confirm = input(f"  Remove registration for {config.describe()}? [y/N]: ").strip().lower()
            if confirm == "y":
                config.clear()
                print("  [+] Configuration reset.")
        else:
            print("  No device registered.")
        sys.exit(0)

    if "--setup" in args:
        if config.is_configured:
            print(f"  Currently authorized: {config.describe()}")
            confirm = input("  Overwrite with a new device? [y/N]: ").strip().lower()
            if confirm != "y":
                sys.exit(0)
        if not first_run_setup(config):
            sys.exit(1)

    if not config.is_configured:
        if not first_run_setup(config):
            sys.exit(1)

    try:
        from taala2ken.pipe_server import NamedPipeServer
        pipe_server = NamedPipeServer(config)
        pipe_server.start()
    except Exception as e:
        log.error(f"Could not start named pipe server (IPC disabled): {e}")
        pipe_server = None

    monitor = USBMonitor(config)

    if pipe_server:
        monitor.register_status_listener(pipe_server.broadcast_status)

    try:
        monitor.run()
    except KeyboardInterrupt:
        log.info("Shutdown requested.")
        monitor.stop()
        if pipe_server:
            pipe_server.stop()
    except Exception as e:
        log.critical(f"Fatal error in monitor loop: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
