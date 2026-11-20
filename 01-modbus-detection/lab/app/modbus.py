"""Minimal Modbus/TCP framing, standard library only.

A Modbus/TCP frame is a 7-byte MBAP header followed by a PDU:

    MBAP:  transaction id (2) | protocol id (2, always 0) | length (2) | unit id (1)
    PDU:   function code (1) | data (n)

"length" counts the unit id + PDU, so it is len(PDU) + 1.
All multi-byte numbers are big-endian ("network order", struct format ">").
Reference: Modbus Messaging on TCP/IP Implementation Guide v1.0b, section 3.1.3.
"""
import socket
import struct

# Function codes used in this lab (Modbus Application Protocol Spec v1.1b3, section 6)
READ_HOLDING_REGISTERS = 3      # FC 3
WRITE_SINGLE_REGISTER = 6       # FC 6
WRITE_MULTIPLE_REGISTERS = 16   # FC 16
ENCAP_INTERFACE = 43            # FC 43, with MEI type 14 = Read Device Identification
MEI_READ_DEVICE_ID = 14

# Exception codes (spec section 7)
ILLEGAL_FUNCTION = 1
ILLEGAL_DATA_ADDRESS = 2


def build_frame(tid, unit, fc, data=b""):
    pdu = struct.pack(">B", fc) + data
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit)
    return mbap + pdu


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf += chunk
    return buf


def recv_frame(sock):
    """Read one frame. Returns (tid, unit, fc, data)."""
    tid, proto, length, unit = struct.unpack(">HHHB", recv_exact(sock, 7))
    pdu = recv_exact(sock, length - 1)
    return tid, unit, pdu[0], pdu[1:]


class Client:
    """One TCP connection to a PLC; one request/response at a time."""

    def __init__(self, host, port=502, unit=1, timeout=5):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.unit = unit
        self.tid = 0

    def _call(self, fc, data):
        self.tid = (self.tid + 1) & 0xFFFF
        self.sock.sendall(build_frame(self.tid, self.unit, fc, data))
        tid, unit, rfc, rdata = recv_frame(self.sock)
        if rfc == fc | 0x80:  # exception responses set the high bit of the function code
            raise RuntimeError(f"Modbus exception {rdata[0]} for FC {fc}")
        return rdata

    def read_holding(self, addr, count=1):
        rdata = self._call(READ_HOLDING_REGISTERS, struct.pack(">HH", addr, count))
        nbytes = rdata[0]
        return list(struct.unpack(f">{nbytes // 2}H", rdata[1:1 + nbytes]))

    def write_single(self, addr, value):
        self._call(WRITE_SINGLE_REGISTER, struct.pack(">HH", addr, value))

    def write_multiple(self, addr, values):
        data = struct.pack(">HHB", addr, len(values), 2 * len(values))
        data += struct.pack(f">{len(values)}H", *values)
        self._call(WRITE_MULTIPLE_REGISTERS, data)

    def read_device_id(self):
        # MEI 14, read code 1 (basic objects), start at object 0
        rdata = self._call(ENCAP_INTERFACE, struct.pack(">BBB", MEI_READ_DEVICE_ID, 1, 0))
        count = rdata[5]
        objs, i = {}, 6
        for _ in range(count):
            oid, olen = rdata[i], rdata[i + 1]
            objs[oid] = rdata[i + 2:i + 2 + olen].decode()
            i += 2 + olen
        return objs

    def close(self):
        self.sock.close()
