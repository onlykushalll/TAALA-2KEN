"""
TAALA-2KEN — Named Pipe IPC Server.

Enables communication between the Python background monitor and the C++
Credential Provider DLL loaded at the Windows Logon/Lock screen.
Uses standard Windows Named Pipes API via pywin32.
"""

import json
import time
import threading
import win32pipe
import win32file
import pywintypes
import winerror
from taala2ken import constants as C
from taala2ken.log import log
from taala2ken.config import AuthConfig


class NamedPipeServer(threading.Thread):
    """
    Named Pipe IPC Server listening on \\\\.\\pipe\\Taala2KenAuth.
    """

    def __init__(self, config: AuthConfig):
        super().__init__(daemon=True, name="NamedPipeServer")
        self.config = config
        self._stop_event = threading.Event()
        self._current_status = "ABSENT"
        self._remaining_seconds = 0.0
        self._lock = threading.Lock()

    def broadcast_status(self, status: str, remaining_seconds: float = 0.0):
        """Called by the monitor loop to update current status state."""
        with self._lock:
            self._current_status = status
            self._remaining_seconds = remaining_seconds

    def run(self) -> None:
        log.info(f"[PIPE] Named Pipe Server starting on {C.PIPE_NAME}...")
        
        while not self._stop_event.is_set():
            try:
                pipe_handle = win32pipe.CreateNamedPipe(
                    C.PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    C.PIPE_BUFFER_SIZE,
                    C.PIPE_BUFFER_SIZE,
                    0,
                    None
                )

                if pipe_handle == win32file.INVALID_HANDLE_VALUE:
                    log.error("[PIPE] CreateNamedPipe failed.")
                    time.sleep(2.0)
                    continue

                try:
                    win32pipe.ConnectNamedPipe(pipe_handle, None)
                    log.debug("[PIPE] Client connected to named pipe.")
                    
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(pipe_handle,),
                        daemon=True
                    )
                    t.start()
                except pywintypes.error as e:
                    if e.winerror == winerror.ERROR_PIPE_CONNECTED:
                        self._handle_client(pipe_handle)
                    else:
                        win32file.CloseHandle(pipe_handle)

            except Exception as e:
                log.error(f"[PIPE] Exception in server loop: {e}")
                time.sleep(1.0)

    def _handle_client(self, pipe_handle):
        try:
            while not self._stop_event.is_set():
                hr, data = win32file.ReadFile(pipe_handle, C.PIPE_BUFFER_SIZE)
                if hr != 0 or not data:
                    break

                try:
                    request = json.loads(data.decode("utf-8"))
                    response = self._process_request(request)
                    response_data = json.dumps(response).encode("utf-8")
                    
                    win32file.WriteFile(pipe_handle, response_data)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    log.warning("[PIPE] Received malformed non-JSON data from client.")
                    break
        except pywintypes.error as e:
            log.debug(f"[PIPE] Client disconnected: {e.strerror}")
        finally:
            try:
                win32file.CloseHandle(pipe_handle)
            except Exception:
                pass

    def _process_request(self, request: dict) -> dict:
        action = request.get("action")
        log.debug(f"[PIPE] Received action: {action}")

        if action == "query_status":
            with self._lock:
                return {
                    "status": self._current_status,
                    "remaining_seconds": self._remaining_seconds,
                    "is_configured": self.config.is_configured,
                    "device_type": self.config.registered_device_type,
                    "requires_challenge": bool(self.config.public_key_der)
                }

        elif action == "pkcs11_challenge":
            nonce_hex = request.get("nonce", "")
            if not nonce_hex:
                return {"status": "error", "message": "missing challenge nonce"}

            if not self.config.public_key_der:
                return {"status": "error", "message": "no public key registered for challenge"}

            try:
                from taala2ken.pkcs11_auth import find_middleware_dll
                import PyKCS11
                from PyKCS11 import LowLevel as KCS

                dll_path = find_middleware_dll()
                if not dll_path:
                    return {"status": "failed", "reason": "middleware missing"}

                pkcs11 = PyKCS11.PyKCS11Lib()
                pkcs11.load(dll_path)
                slots = pkcs11.getSlotList(tokenPresent=True)
                if not slots:
                    return {"status": "failed", "reason": "token not present"}

                session = pkcs11.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)
                private_keys = session.findObjects([(KCS.CKA_CLASS, KCS.CKO_PRIVATE_KEY)])
                if not private_keys:
                    session.closeSession()
                    return {"status": "failed", "reason": "private key missing"}

                mechanism = PyKCS11.Mechanism(KCS.CKM_SHA256_RSA_PKCS, None)
                signature = bytes(session.sign(private_keys[0], bytes.fromhex(nonce_hex), mechanism))
                session.closeSession()

                return {
                    "status": "success",
                    "signature": signature.hex()
                }
            except Exception as e:
                log.error(f"[PIPE] PKCS#11 challenge signing failed: {e}")
                return {"status": "failed", "reason": str(e)}

        return {"status": "error", "message": f"unknown action: {action}"}

    def stop(self) -> None:
        self._stop_event.set()
        try:
            handle = win32file.CreateFile(
                C.PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None
            )
            win32file.CloseHandle(handle)
        except Exception:
            pass
