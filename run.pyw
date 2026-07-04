# Windowless entry point for TAALA-2KEN.
# Spawns the monitor and system tray with no console window.
# Launch with pythonw.exe (no console).

from taala2ken.config import AuthConfig
from taala2ken.tray_app import launch_tray_and_monitor

if __name__ == "__main__":
    config = AuthConfig()
    if not config.is_configured:
        # Cannot run setup wizard in windowless mode.
        # Run  python -m taala2ken --setup  first.
        import sys
        sys.exit(1)
    launch_tray_and_monitor(config)
