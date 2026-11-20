"""Command-line Modbus client, used by the EWS and the attacker.

  python mbcli.py HOST read ADDR [COUNT]      FC 3
  python mbcli.py HOST write ADDR VALUE       FC 6
  python mbcli.py HOST writem ADDR V1 V2 ...  FC 16
  python mbcli.py HOST devid                  FC 43 / MEI 14
"""
import os
import sys

import modbus as mb

host, cmd, args = sys.argv[1], sys.argv[2], [int(a) for a in sys.argv[3:]]
c = mb.Client(host, int(os.environ.get("PLC_PORT", "502")))
if cmd == "read":
    print(c.read_holding(args[0], args[1] if len(args) > 1 else 1))
elif cmd == "write":
    c.write_single(args[0], args[1])
    print(f"wrote {args[1]} to register {args[0]}")
elif cmd == "writem":
    c.write_multiple(args[0], args[1:])
    print(f"wrote {args[1:]} starting at register {args[0]}")
elif cmd == "devid":
    print(c.read_device_id())
else:
    sys.exit(__doc__)
c.close()
