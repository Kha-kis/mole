#!/usr/bin/env python3
"""
MOLE - Entry Point
Run with: python -m mole_pkg
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
