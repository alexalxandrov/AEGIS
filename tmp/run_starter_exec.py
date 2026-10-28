#!/usr/bin/env python3
"""Executes :mod:`starter` using the stubs.

This is a small helper script used only for this exercise – it manually sets up
``PATH`` and ``sys.path`` before importing the original starter module.
"""

import os
import sys
from pathlib import Path

# Add the stub binaries directory to PATH.
stub_bin = Path(__file__).resolve().parent / "bin"
os.environ["PATH"] = f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}"

# Ensure the project root is importable.
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Import the starter module and run it with the example arguments.
from starter import main, parser

if __name__ == "__main__":
    args = parser.parse_args(["--org", "default", "192.168.0.1"])
    main(args)