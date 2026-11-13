#!/usr/bin/env python3
"""Generic trusted command: report delegation, then wait for a disposable gate."""
import json
import os
from pathlib import Path
import sys
import time

report = Path(sys.argv[1])
fds = {}
for name in os.listdir('/proc/self/fd'):
    try:
        fds[name] = os.readlink('/proc/self/fd/' + name)
    except FileNotFoundError:
        pass
report.write_text(json.dumps({
    'pid': os.getpid(), 'uid': os.getuid(), 'fds': fds,
    'env': dict(os.environ),
}))
for _ in range(6000):
    if Path(str(report) + '.exit').exists():
        break
    time.sleep(0.01)
else:
    raise SystemExit('entry gate timed out')
