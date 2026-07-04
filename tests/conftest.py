"""
TAALA-2KEN Test Configuration.

Adds the project root to sys.path so tests can import
top-level modules like pipe_server and pkcs11_auth.
"""

import sys
from pathlib import Path

# Ensure project root is on the import path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
