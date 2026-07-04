"""
TAALA-2KEN — System Tray Application.

Exposes status reporting, device configuration, logs, and monitoring control
via a native Windows taskbar notification tray icon.
"""

import threading
import time
from taala2ken import constants as C
from taala2ken import __app_name__ as APP_NAME
from taala2ken.log import log
from taala2ken.config import AuthConfig
from taala2ken.monitor import USBMonitor

try:
    from PIL import Image, ImageDraw
    import pystray
    _TRAY_AVAILABLE = True
except ImportError:
    _TRAY_AVAILABLE = False


class SystemTrayApp:
    """System Tray wrapper for the background USB monitoring service."""

    def __init__(self, monitor: USBMonitor):
        self.monitor = monitor
        self.config = monitor.config
        self.icon = None
        self._status = "UNKNOWN"
        self._remaining = 0.0

    def _create_image(self, color: str) -> "Image.Image":
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse([4, 4, 60, 60], fill="black")
        if color == "green":
            d.ellipse([16, 16, 48, 48], fill="#4CAF50")
        elif color == "red":
            d.ellipse([16, 16, 48, 48], fill="#F44336")
        elif color == "yellow":
            d.ellipse([16, 16, 48, 48], fill="#FFEB3B")
        else:
            d.ellipse([16, 16, 48, 48], fill="#9E9E9E")
        return img

    def update_state(self, status: str, remaining_seconds: float = 0.0):
        self._status = status
        self._remaining = remaining_seconds
        if not self.icon:
            return

        if status == "PRESENT":
            self.icon.icon = self._create_image("green")
            self.icon.title = f"{APP_NAME}: Secure"
        elif status == "ABSENT":
            self.icon.icon = self._create_image("red")
            self.icon.title = f"{APP_NAME}: Absent (Locked)"
        elif status == "GRACE":
            self.icon.icon = self._create_image("yellow")
            self.icon.title = f"{APP_NAME}: Locking in {remaining_seconds:.1f}s"
        else:
            self.icon.icon = self._create_image("grey")
            self.icon.title = APP_NAME

    def _on_status(self):
        desc = self.config.describe() if self.config.is_configured else "No Key Registered"
        try:
            import winotify
            toast = winotify.Notification(
                app_id=APP_NAME,
                title="TAALA-2KEN Status",
                msg=f"State: {self._status}\nDevice: {desc}",
                duration="short"
            )
            toast.show()
        except ImportError:
            log.info(f"[TRAY] Status: {self._status} | Device: {desc}")

    def _on_reset(self):
        if self.config.is_configured:
            self.config.clear()
            log.info("[TRAY] Device reset completed from tray.")
            self._on_status()

    def _on_quit(self):
        log.info("[TRAY] Exiting tray app and monitor service...")
        self.monitor.stop()
        if self.icon:
            self.icon.stop()

    def run(self):
        if not _TRAY_AVAILABLE:
            log.warning("[TRAY] pystray/pillow libraries missing. Tray icon disabled.")
            return

        menu = pystray.Menu(
            pystray.MenuItem("Show Status", self._on_status),
            pystray.MenuItem("Clear Registered Key", self._on_reset),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit Guard", self._on_quit)
        )

        self.icon = pystray.Icon(
            name="Taala2Ken",
            icon=self._create_image("grey"),
            title=APP_NAME,
            menu=menu
        )

        self.monitor.register_status_listener(self.update_state)
        self.icon.run()


def launch_tray_and_monitor(config: AuthConfig):
    """Launches the monitor service in a thread and runs the tray loop in the main thread."""
    monitor = USBMonitor(config)
    
    try:
        from taala2ken.pipe_server import NamedPipeServer
        pipe_server = NamedPipeServer(config)
        pipe_server.start()
        monitor.register_status_listener(pipe_server.broadcast_status)
    except Exception as e:
        log.error(f"Pipe server failed: {e}")
        pipe_server = None

    monitor_thread = threading.Thread(target=monitor.run, daemon=True, name="MonitorService")
    monitor_thread.start()

    if _TRAY_AVAILABLE:
        app = SystemTrayApp(monitor)
        app.run()
    else:
        try:
            while monitor_thread.is_alive():
                time.sleep(1.0)
        except KeyboardInterrupt:
            log.info("Shutdown requested.")
            monitor.stop()
            if pipe_server:
                pipe_server.stop()
