"""
TAALA-2KEN — Workstation lock trigger.

Immediately locks the Windows user session.
Tries ctypes LockWorkStation, then falls back to rundll32 or TS disconnect.
"""

import subprocess
import ctypes
from taala2ken import constants as C
from taala2ken.log import log

# Import TS APIs conditionally
try:
    import win32ts
except ImportError:
    win32ts = None

def _lock_via_rundll32() -> bool:
    try:
        result = subprocess.run(
            ["rundll32.exe", "user32.dll,LockWorkStation"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            log.debug("rundll32 lock: success (returncode 0)")
            return True
        log.debug(f"rundll32 lock: returncode={result.returncode}")
        return False
    except Exception as e:
        log.debug(f"rundll32 lock exception: {e}")
        return False

def _lock_via_win32ts() -> bool:
    try:
        result = ctypes.windll.user32.LockWorkStation()
        if result:
            log.debug("ctypes LockWorkStation: success")
            return True
        log.debug("ctypes LockWorkStation returned 0 (failure)")
    except Exception as e:
        log.debug(f"ctypes LockWorkStation exception: {e}")

    if win32ts is not None:
        try:
            session_id = win32ts.WTSGetActiveConsoleSessionId()
            win32ts.WTSDisconnectSession(
                win32ts.WTS_CURRENT_SERVER_HANDLE,
                session_id,
                False,
            )
            log.debug(f"win32ts WTSDisconnectSession on session {session_id}: success")
            return True
        except Exception as e:
            log.debug(f"win32ts disconnect exception: {e}")

    return False

def lock_workstation() -> bool:
    """
    Immediately locks the Windows user session.
    Tries the configured lock method first, then falls back.
    """
    log.warning("[!] LOCKING WORKSTATION -- USB removed or not authorized!")
    if C.DRY_RUN:
        log.info("[DRY-RUN] Bypassing lock action (C.DRY_RUN is enabled).")
        return True

    success = False
    if C.LOCK_METHOD == "win32ts":
        success = _lock_via_win32ts()
        if not success:
            log.debug("win32ts lock failed, falling back to rundll32...")
            success = _lock_via_rundll32()
    else:
        success = _lock_via_rundll32()
        if not success:
            log.debug("rundll32 lock failed, falling back to win32ts...")
            success = _lock_via_win32ts()

    if success:
        log.info("[+] Workstation locked successfully.")
    else:
        log.error("[-] All lock methods failed. Check permissions / Run as Administrator.")

    return success
