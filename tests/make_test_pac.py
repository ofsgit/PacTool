#!/usr/bin/env python3
"""Independent PAC generator used to test pactool.

Written from the layout of the official Unisoc unpac.pl and shares no code with
pactool.c, so a mistake in one is unlikely to be mirrored in the other.

usage: make_test_pac.py good|evil <out.pac>
"""
import os
import random
import struct
import sys

HDR, ENT = 2124, 2580
MAGIC = 0xFFFAFFFA

_T = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    _T.append(c)


def crc16(data, crc=0):
    for b in data:
        crc = (crc >> 8) ^ _T[(crc ^ b) & 0xFF]
    return crc


def u16(s, nbytes):
    b = s.encode("utf-16-le")
    assert len(b) < nbytes
    return b + b"\0" * (nbytes - len(b))


def build(entries, path, prd="TestProd", prdver="TestProd_W26.43", alias="alias", version="BP_R1.0.0"):
    n = len(entries)
    data_start = HDR + ENT * n
    pos = data_start
    table = b""
    blobs = b""
    for e in entries:
        d = e.get("data")
        size = len(d) if d else 0
        off = pos if size else e.get("raw_offset", 0)
        addrs = (e.get("addrs", []) + [0] * 5)[:5]
        t = struct.pack("<I", ENT)
        t += u16(e["id"], 512) + u16(e.get("name", ""), 512) + u16(e.get("version", ""), 504)
        t += struct.pack("<8I", size >> 32, off >> 32, size & 0xFFFFFFFF,
                         e.get("flag", 1 if size else 0), e.get("check", 0),
                         off & 0xFFFFFFFF, e.get("omit", 0), len(e.get("addrs", [])))
        t += struct.pack("<5I", *addrs)
        t += b"\0" * (ENT - len(t))
        assert len(t) == ENT, len(t)
        table += t
        if size:
            blobs += d
            pos += size
    total = pos
    h = u16(version, 44)
    h += struct.pack("<II", total >> 32, total & 0xFFFFFFFF)
    h += u16(prd, 512) + u16(prdver, 512)
    h += struct.pack("<7I", n, HDR, 1, 2, 3, 1, 4)
    h += u16(alias, 200)
    h += struct.pack("<3I", 5, 6, 7)
    h += b"\0" * 800
    h += struct.pack("<I", MAGIC)
    assert len(h) == HDR - 4, len(h)
    crc1 = crc16(h)
    crc2 = crc16(table + blobs)
    h += struct.pack("<HH", crc1, crc2)
    assert len(h) == HDR
    with open(path, "wb") as f:
        f.write(h + table + blobs)


def rnd(n, seed):
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(n))


def good(path):
    build([
        {"id": "FDL", "name": "fdl1-sign.bin", "data": rnd(9000, 1), "addrs": [0x5000], "check": 1},
        {"id": "FDL2", "name": "fdl2-sign.bin", "data": rnd(70000, 2), "addrs": [0x9EFFFE00], "check": 1},
        {"id": "EraseUBOOT", "name": "", "flag": 1},                      # operation, flag 1, no data
        {"id": "FLASH", "name": "", "flag": 0, "raw_offset": 12345},      # operation, odd offset kept
        {"id": "Userdata", "name": "ünïcødé_固件_😀.img", "data": rnd(5000, 3), "addrs": [0, 0x10], "omit": 1},
        {"id": "System", "name": "system.img", "data": rnd(700_000, 4), "check": 1, "version": "v1.2"},
        {"id": "System2", "name": "system.img", "data": rnd(1000, 5)},   # duplicate disk name
        {"id": "OnlyID", "name": "", "data": rnd(777, 6)},               # empty name, has data
    ], path)


def evil(path):
    build([
        {"id": "A", "name": "../../evil_a.txt", "data": b"AAAA"},
        {"id": "B", "name": "/tmp/pactool_evil_b.txt", "data": b"BBBB"},
        {"id": "C", "name": "x\\y\\..\\evil_c.txt", "data": b"CCCC"},
        {"id": "D", "name": "..", "data": b"DDDD"},
        {"id": "E", "name": "pac.manifest", "data": b"EEEE"},            # must not clobber manifest
    ], path)


if __name__ == "__main__":
    {"good": good, "evil": evil}[sys.argv[1]](sys.argv[2])
