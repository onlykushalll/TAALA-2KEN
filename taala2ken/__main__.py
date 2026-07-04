"""
TAALA-2KEN — Package entry point.

Allows running the guard via:  python -m taala2ken [--setup|--list|--status|--debug|--help]
"""

from taala2ken.cli import main

if __name__ == "__main__":
    main()
