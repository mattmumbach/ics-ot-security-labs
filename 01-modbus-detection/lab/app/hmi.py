"""Simulated HMI: polls the setpoint (FC 3, register 0) every 2 seconds over one connection."""
import os
import sys
import time

import modbus as mb

host = sys.argv[1]
port = int(os.environ.get("PLC_PORT", "502"))
while True:
    try:
        c = mb.Client(host, port)
        while True:
            print(f"setpoint {c.read_holding(0, 1)[0]}", flush=True)
            time.sleep(2)
    except OSError as e:  # PLC not up yet, or restarted: retry
        print(f"HMI: {e}; retrying", flush=True)
        time.sleep(2)
