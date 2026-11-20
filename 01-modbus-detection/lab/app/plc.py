"""Simulated PLC: a Modbus/TCP server with 10 holding registers.

Holding register 0 is the process setpoint (safe range 40-60, starts at 50).
The PLC itself enforces nothing - like many real PLCs, it accepts any write
from anyone who can reach TCP 502. That is the gap the detections cover.
"""
import os
import socketserver
import struct
import threading

import modbus as mb

PORT = int(os.environ.get("PLC_PORT", "502"))
registers = [0] * 10
registers[0] = 50
lock = threading.Lock()

DEVICE_ID = {0: "LabVendor", 1: "LP-100", 2: "1.0"}  # vendor, product code, revision


def exception(fc, code):
    return fc | 0x80, struct.pack(">B", code)


def handle_pdu(fc, data):
    """Return (response fc, response data) for one request."""
    if fc == mb.READ_HOLDING_REGISTERS:
        addr, count = struct.unpack(">HH", data[:4])
        if addr + count > len(registers):
            return exception(fc, mb.ILLEGAL_DATA_ADDRESS)
        with lock:
            vals = registers[addr:addr + count]
        return fc, struct.pack(">B", 2 * count) + struct.pack(f">{count}H", *vals)

    if fc == mb.WRITE_SINGLE_REGISTER:
        addr, value = struct.unpack(">HH", data[:4])
        if addr >= len(registers):
            return exception(fc, mb.ILLEGAL_DATA_ADDRESS)
        with lock:
            registers[addr] = value
        return fc, data[:4]  # FC 6 response echoes the request

    if fc == mb.WRITE_MULTIPLE_REGISTERS:
        addr, count, _nbytes = struct.unpack(">HHB", data[:5])
        if addr + count > len(registers):
            return exception(fc, mb.ILLEGAL_DATA_ADDRESS)
        vals = struct.unpack(f">{count}H", data[5:5 + 2 * count])
        with lock:
            registers[addr:addr + count] = vals
        return fc, struct.pack(">HH", addr, count)

    if fc == mb.ENCAP_INTERFACE and data[:1] == bytes([mb.MEI_READ_DEVICE_ID]):
        body = struct.pack(">BBBBBB", mb.MEI_READ_DEVICE_ID, 1, 0x01, 0, 0, len(DEVICE_ID))
        for oid, val in DEVICE_ID.items():
            body += struct.pack(">BB", oid, len(val)) + val.encode()
        return fc, body

    return exception(fc, mb.ILLEGAL_FUNCTION)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.client_address[0]
        try:
            while True:
                tid, unit, fc, data = mb.recv_frame(self.request)
                rfc, rdata = handle_pdu(fc, data)
                self.request.sendall(mb.build_frame(tid, unit, rfc, rdata))
                if fc != mb.READ_HOLDING_REGISTERS:  # keep the log readable: skip HMI polls
                    print(f"{peer} FC {fc} -> FC {rfc}; setpoint now {registers[0]}", flush=True)
        except ConnectionError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(f"PLC listening on TCP {PORT}; setpoint {registers[0]}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
