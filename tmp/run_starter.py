import traceback
import sys
from pathlib import Path
import os

# Ensure our stub binaries are on PATH before importing starter.
stub_bin = Path(__file__).parent / "bin"
os.environ["PATH"] = f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}"

import sys
from pathlib import Path
# Ensure the project root is on sys.path so that the ``starter`` module can be
# imported.  The script is executed from the ``tmp`` directory.
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))
from starter import main
import argparse
args = argparse.Namespace(
    org='default',
    target='192.168.0.1',
    nick=None,
    company=None,
    limit=None,
    no_wayback=False,
    verbose=False,
    output_dir=None
)
try:
    main(args)
except Exception as e:
    traceback.print_exc()
    sys.exit(1)