#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibo-dump.py - tool for making dumps or scanning amiibo with pyscard (NOT pisscard)

import argparse
import json
import re
import sys
import time
import urllib.request
from typing import Optional, Tuple

try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False

print("👾  Amiibo Hardware Dumper v1.5.3 by CheatFreak  👾\n"
      "---------------------------------------------------\n"
      "Dumper for NTAG215, NT3H2111, and NT3H2211 amiibo tags.\n"
      "Only tested against the ACS ACR1252U Smart Card Reader. Other readers ymmv.\n"
      "Run with -h for help on available options.\n")

try:
    from smartcard.System import readers
except ImportError:
    print("Error: The 'pyscard' library is required but not installed.")
    print("Please install it via your terminal: pip install pyscard")
    sys.exit(1)


# Exit & Logging Helpers

def abort(msg: str) -> None:
    print(msg)
    input("\nPress Enter to exit...")
    sys.exit(1)


def dbg(debug: bool, msg: str) -> None:
    if debug:
        print(f"   🐛  [DEBUG] {msg}")


# Low-Level Tag & Crypto Utilities

def crc16_mcrf4xx(data: bytes, crc_init: int = 0xFFFF) -> int:
    crc = crc_init & 0xFFFF
    for byte in data:
        crc ^= (byte & 0xFF)
        for _ in range(8):
            if (crc & 1) != 0:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            crc &= 0xFFFF
    return crc & 0xFFFF


def send_direct_transceive(connection, data_bytes: list) -> Tuple[list, int, int]:
    apdu = [0xFF, 0x00, 0x00, 0x00, len(data_bytes)] + list(data_bytes)
    response, sw1, sw2 = connection.transmit(apdu)
    return response, sw1, sw2


def read_binary_pages(connection, start_page: int, num_pages: int = 4, debug: bool = False) -> Optional[bytes]:
    # Reads contiguous 4-byte pages via standard PC/SC READ BINARY (FF B0)
    length = num_pages * 4
    apdu = [0xFF, 0xB0, 0x00, start_page & 0xFF, length]
    try:
        resp, sw1, sw2 = connection.transmit(apdu)
        dbg(debug, f"READ_BINARY page {hex(start_page)} (len {length}) -> sw1={hex(sw1)} sw2={hex(sw2)} got={len(resp)} data={bytes(resp).hex().upper()}")
        if sw1 == 0x90 and sw2 == 0x00 and len(resp) == length:
            return bytes(resp)
    except Exception as e:
        dbg(debug, f"READ_BINARY page {hex(start_page)} exception: {e}")
    return None


def derive_ntag_pwd(uid: bytes) -> bytes:
    pwd0 = 0xAA ^ uid[1] ^ uid[3]
    pwd1 = 0x55 ^ uid[2] ^ uid[4]
    pwd2 = 0xAA ^ uid[3] ^ uid[5]
    pwd3 = 0x55 ^ uid[4] ^ uid[6]
    return bytes([pwd0, pwd1, pwd2, pwd3])


def unlock_tag(connection, uid: bytes, debug: bool = False) -> None:
    pwd = derive_ntag_pwd(uid)
    auth_cmd = [0x1B, pwd[0], pwd[1], pwd[2], pwd[3]]
    dbg(debug, f"Sending PWD auth: {[hex(b) for b in auth_cmd]}")
    try:
        resp, sw1, sw2 = send_direct_transceive(connection, auth_cmd)
        dbg(debug, f"PWD auth response: sw1={hex(sw1)} sw2={hex(sw2)} len={len(resp)} data={bytes(resp).hex().upper()}")
    except Exception as e:
        dbg(debug, f"PWD auth exception: {e}")


def select_sector(connection, sector: int, uid: bytes, debug: bool = False) -> None:
    try:
        send_direct_transceive(connection, [0xC2, 0xFF])
    except Exception:
        pass

    try:
        send_direct_transceive(connection, [sector & 0xFF, 0x00, 0x00, 0x00])
    except Exception:
        pass

    time.sleep(0.05)
    unlock_tag(connection, uid, debug=debug)
    time.sleep(0.03)


def reconnect_reader(reader, connection, debug: bool = False):
    try:
        connection.disconnect()
    except Exception as e:
        dbg(debug, f"Disconnect before reconnect ignored: {e}")
    time.sleep(0.05)
    conn = reader.createConnection()
    conn.connect()
    return conn


def fast_read(connection, start_page: int, end_page: int, debug: bool = False) -> Optional[bytearray]:
    cmd = [0x3A, start_page & 0xFF, end_page & 0xFF]
    resp, sw1, sw2 = send_direct_transceive(connection, cmd)
    expected_bytes = (end_page - start_page + 1) * 4
    dbg(debug, f"FAST_READ {hex(start_page)}..{hex(end_page)} -> sw1={hex(sw1)} sw2={hex(sw2)} got={len(resp)}/{expected_bytes} data={bytes(resp).hex().upper()}")
    if len(resp) == expected_bytes and (sw1 == 0x90 or sw1 == 0x00):
        return bytearray(resp)
    return None


def read_ecc_signature(connection, debug: bool = False) -> bytes:
    # Reads the 32-byte NXP ECC originality signature via native 0x3C (READ_SIG) command
    try:
        resp, sw1, sw2 = send_direct_transceive(connection, [0x3C, 0x00])
        dbg(debug, f"READ_SIG [0x3C, 0x00] -> sw1={hex(sw1)} sw2={hex(sw2)} len={len(resp)}")
        if sw1 == 0x90 and len(resp) >= 32:
            return bytes(resp[:32])
    except Exception as e:
        dbg(debug, f"READ_SIG exception: {e}")
    return b'\x00' * 32


def fetch_sig_for_nfc(reader, debug: bool = False) -> bytes:
    # Attempts to read the 32-byte ECC signature over a fresh connection if needed
    conn = None
    try:
        conn = reader.createConnection()
        conn.connect()
        return read_ecc_signature(conn, debug=debug)
    except Exception as e:
        dbg(debug, f"fetch_sig_for_nfc exception: {e}")
        return b'\x00' * 32
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception as e:
                dbg(debug, f"fetch_sig_for_nfc disconnect ignored: {e}")


def request_sram(connection, debug: bool = False) -> None:
    buffer = bytearray(64)
    buffer[0] = 0x01
    crc = crc16_mcrf4xx(buffer[:62])
    buffer[62] = (crc >> 8) & 0xFF
    buffer[63] = crc & 0xFF
    dbg(debug, "Requesting SRAM pass-through/write...")
    try:
        resp, sw1, sw2 = send_direct_transceive(connection, [0xA6, 0xF0, 0xFF] + list(buffer))
        dbg(debug, f"SRAM write response: sw1={hex(sw1)} sw2={hex(sw2)} len={len(resp)} data={bytes(resp).hex().upper()}")
    except Exception as e:
        dbg(debug, f"SRAM write exception: {e}")


def read_i2c_sram(connection, debug: bool = False) -> bytes:
    # Reads the 64-byte SRAM window (pages 0xF0..0xFF) via READ_BINARY in 16-byte chunks, falling back to FAST_READ
    request_sram(connection, debug=debug)
    time.sleep(0.05)

    sram = bytearray()
    for page in range(0xF0, 0x100, 4):
        chunk = read_binary_pages(connection, page, 4, debug=debug)
        sram.extend(chunk if chunk is not None else b'\x00' * 16)

    if any(b != 0 for b in sram):
        return bytes(sram[:64])

    fr_sram = fast_read(connection, 0xF0, 0xFF, debug=debug)
    if fr_sram and len(fr_sram) >= 64:
        return bytes(fr_sram[:64])

    return bytes(sram[:64])


def detect_tag_type(connection, uid: bytes, debug: bool = False) -> Tuple[str, bytes]:
    # Determines physical tag type (ntag215, i2c_1k, i2c_2k) from hardware memory layout rather than ID bytes
    id_bytes = b'\x00' * 8

    # Read pages 0x14..0x17 (16 bytes); Amiibo ID sits at offset 4..12 (file offset 0x54..0x5C)
    id_block = read_binary_pages(connection, 0x14, 4, debug=debug)
    if id_block and len(id_block) >= 12:
        id_bytes = id_block[4:12]

    id_hex = id_bytes.hex().upper()
    dbg(debug, f"Parsed Amiibo ID from page 0x15..0x16: {id_hex}")

    # Page 0xE0 (224) is beyond NTAG215 (0x00..0x86), indicating an I2C chip (NT3H2111 or NT3H2211)
    pe0 = read_binary_pages(connection, 0xE0, 4, debug=debug)
    if pe0 is not None:
        sec0_p0 = read_binary_pages(connection, 0x00, 4, debug=debug)
        select_sector(connection, 1, uid, debug=debug)
        sec1_p0 = read_binary_pages(connection, 0x00, 4, debug=debug)
        select_sector(connection, 0, uid, debug=debug)

        if sec1_p0 is not None and sec1_p0 != sec0_p0:
            dbg(debug, "Identified NT3H2211 (i2c_2k) via distinct Sector 1 memory")
            return "i2c_2k", id_bytes

        dbg(debug, "Identified NT3H2111 (i2c_1k) via page 0xE0 and single-sector layout")
        return "i2c_1k", id_bytes

    dbg(debug, "Defaulting tag_type = 'ntag215'")
    return "ntag215", id_bytes


def patch_ntag215_auth(raw_bin: bytearray, uid: bytes, pwd_skip: bool = False, debug: bool = False) -> None:
    if pwd_skip:
        dbg(debug, "Skipping NTAG215 PWD/PACK/RFUI patch (--pwd-skip active)")
        return
    if len(raw_bin) >= 540 and len(uid) >= 7:
        pwd = derive_ntag_pwd(uid)
        raw_bin[532:536] = pwd
        raw_bin[536:538] = b'\x80\x80'
        raw_bin[538:540] = b'\x00\x00'
        dbg(debug, f"Patched NTAG215 auth at 0x214 (PWD={pwd.hex().upper()}) and 0x218 (PACK/RFUI=80800000)")


def patch_ntag_i2c_auth(raw_bin: bytearray, uid: bytes, pwd_skip: bool = False, debug: bool = False) -> None:
    if pwd_skip:
        dbg(debug, "Skipping I2C PWD/PACK/RFUI patch (--pwd-skip active)")
        return
    if len(raw_bin) >= 0x39C and len(uid) >= 7:
        pwd = derive_ntag_pwd(uid)
        raw_bin[0x394:0x398] = pwd
        raw_bin[0x398:0x39A] = b'\x80\x80'
        raw_bin[0x39A:0x39C] = b'\x00\x00'
        dbg(debug, f"Patched I2C auth at 0x394 (PWD={pwd.hex().upper()}) and 0x398 (PACK/RFUI=80800000)")


def reproduce_i2c_reg(raw_bin: bytearray, reg_bytes: bytes, reproduce_reg: bool = False, debug: bool = False) -> None:
    if not reproduce_reg:
        return
    if len(raw_bin) >= 0x3B0 and len(reg_bytes) == 8:
        raw_bin[0x3A8:0x3B0] = reg_bytes
        dbg(debug, f"Reproduced I2C register bytes at 0x3A8..0x3B0: {reg_bytes.hex().upper()}")


# Flipper NFC Formatting

def fmt_hex_bytes(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def fmt_pages_lines(data: bytes, page_count: int) -> list:
    total_bytes = page_count * 4
    buf = data[:total_bytes]
    if len(buf) < total_bytes:
        buf = buf + (b'\x00' * (total_bytes - len(buf)))
    return [
        f"Page {page_idx}: {fmt_hex_bytes(buf[page_idx * 4:(page_idx + 1) * 4])}"
        for page_idx in range(page_count)
    ]


def build_i2c_nfc_lines(
    uid_str: str,
    sig_str: str,
    chip_label: str,
    mifare_ver_tail: str,
    page_count: int,
    page_source_bin: bytes,
) -> list:
    lines = [
        "Filetype: Flipper NFC device",
        "Version: 4",
        "# Device type can be ISO14443-3A, ISO14443-3B, ISO14443-4A, ISO14443-4B, ISO15693-3, FeliCa, NTAG/Ultralight, Mifare Classic, Mifare Plus, Mifare DESFire, SLIX, ST25TB",
        "Device type: NTAG/Ultralight",
        "# UID is common for all formats",
        f"UID: {uid_str}",
        "# ISO14443-3A specific data",
        "ATQA: 00 44",
        "SAK: 00",
        "# NTAG/Ultralight specific data",
        "Data format version: 2",
        f"NTAG/Ultralight type: {chip_label}",
        f"Signature: {sig_str}",
        f"Mifare version: 00 04 04 05 02 02 {mifare_ver_tail}",
        "Counter 0: 0",
        "Tearing 0: 00",
        "Counter 1: 0",
        "Tearing 1: 00",
        "Counter 2: 0",
        "Tearing 2: 00",
        f"Pages total: {page_count}",
        f"Pages read: {page_count}",
    ]
    lines.extend(fmt_pages_lines(page_source_bin, page_count))
    lines.append("Failed authentication attempts: 0")
    return lines


def build_flipper_nfc_text(
    tag_type: str,
    uid: bytes,
    page_source_bin: bytes,
    sig_bytes: bytes,
    debug: bool = False,
) -> str:
    uid_str = fmt_hex_bytes(uid[:7])
    sig_str = fmt_hex_bytes((sig_bytes + (b'\x00' * 32))[:32])
    nfc_buf = bytearray(page_source_bin)

    if tag_type == "ntag215":
        page_count = 135
        lines = [
            "Filetype: Flipper NFC device",
            "Version: 2",
            "# Nfc device type can be UID, Mifare Ultralight, Bank card",
            "Device type: NTAG215",
            "# UID, ATQA and SAK are common for all formats",
            f"UID: {uid_str}",
            "ATQA: 44 00",
            "SAK: 00",
            "# Mifare Ultralight specific data",
            f"Signature: {sig_str}",
            "Mifare version: 00 04 04 02 01 00 11 03",
            "Counter 0: 0",
            "Tearing 0: 00",
            "Counter 1: 0",
            "Tearing 1: 00",
            "Counter 2: 0",
            "Tearing 2: 00",
            f"Pages total: {page_count}",
        ]
        lines.extend(fmt_pages_lines(bytes(nfc_buf), page_count))
        return "\n".join(lines) + "\n"

    if tag_type == "i2c_1k":
        reg_bytes_1k = bytes.fromhex("0100F84808010100")
        reproduce_i2c_reg(nfc_buf, reg_bytes_1k, reproduce_reg=True, debug=debug)
        lines = build_i2c_nfc_lines(
            uid_str=uid_str,
            sig_str=sig_str,
            chip_label="NTAG I2C Plus 1K",
            mifare_ver_tail="13 03",
            page_count=236,
            page_source_bin=bytes(nfc_buf),
        )
        return "\n".join(lines) + "\n"

    if tag_type == "i2c_2k":
        reg_bytes_2k = bytes.fromhex("4100F84808012100")
        reproduce_i2c_reg(nfc_buf, reg_bytes_2k, reproduce_reg=True, debug=debug)
        lines = build_i2c_nfc_lines(
            uid_str=uid_str,
            sig_str=sig_str,
            chip_label="NTAG I2C Plus 2K",
            mifare_ver_tail="15 03",
            page_count=492,
            page_source_bin=bytes(nfc_buf),
        )
        return "\n".join(lines) + "\n"

    raise ValueError(f"Unsupported tag type for Flipper NFC export: {tag_type}")


# Dump Operations

def dump_ntag215(reader, connection, uid: bytes, target_size: int, pwd_skip: bool = False, debug: bool = False) -> Tuple[bytes, Optional[bytes], bytes]:
    print(f"   ℹ️  Detected standard NTAG215 (amiibo v2) tag. Reconnecting and reading for target size ({target_size}B)...")
    connection = reconnect_reader(reader, connection, debug=debug)

    dump_data = bytearray()
    for page in range(0, 136, 4):
        if page > 132:
            break
        apdu = [0xFF, 0xB0, 0x00, page, 0x10]
        response, sw1, sw2 = connection.transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            dump_data.extend(response)
        else:
            dbg(debug, f"Failed NTAG215 read at page {page}: sw1={hex(sw1)} sw2={hex(sw2)} len={len(response)}")
            raise Exception(f"Failed to read NTAG215 around page {page}: SW={hex(sw1)} {hex(sw2)}")

    ecc_sig = read_ecc_signature(connection, debug=debug)
    try:
        connection.disconnect()
    except Exception as e:
        dbg(debug, f"NTAG215 disconnect ignored: {e}")

    raw_bin = bytearray(dump_data[:540])
    patch_ntag215_auth(raw_bin, uid, pwd_skip=pwd_skip, debug=debug)
    full_540_bin = bytes(raw_bin)

    if target_size == 532:
        return bytes(raw_bin[:532]), None, full_540_bin
    if target_size == 572:
        return bytes(raw_bin) + ecc_sig, None, full_540_bin
    return full_540_bin, None, full_540_bin


def dump_ntag_i2c_sector0(reader, connection, debug: bool = False):
    connection = reconnect_reader(reader, connection, debug=debug)
    dump = bytearray()
    for page in range(0x00, 0xEC, 4):
        chunk = read_binary_pages(connection, page, 4, debug=debug)
        if chunk is not None:
            dump.extend(chunk)
        else:
            dbg(debug, f"READ_BINARY failed at page {hex(page)}; padding 16 bytes with 0x00")
            dump.extend(b'\x00' * 16)
    return dump[:944], connection


def dump_ntag_1k(reader, connection, uid: bytes, pwd_skip: bool = False, reproduce_reg: bool = False, debug: bool = False) -> Tuple[bytes, Optional[bytes], bytes]:
    print("   ℹ️  Detected NT3H2111 (SNW Band). Dumping 944 bytes (236 pages)...")
    reg_bytes_1k = bytes.fromhex("0100F84808010100")
    dump, connection = dump_ntag_i2c_sector0(reader, connection, debug=debug)
    patch_ntag_i2c_auth(dump, uid, pwd_skip=pwd_skip, debug=debug)
    reproduce_i2c_reg(dump, reg_bytes_1k, reproduce_reg=reproduce_reg, debug=debug)
    ecc_sig = read_ecc_signature(connection, debug=debug)
    try:
        connection.disconnect()
    except Exception as e:
        dbg(debug, f"NT3H2111 disconnect ignored: {e}")
    return bytes(dump), None, ecc_sig


def dump_ntag_v3(reader, connection, uid: bytes, pwd_skip: bool = False, reproduce_reg: bool = False, debug: bool = False) -> Tuple[bytes, bytes, bytes]:
    print("   ℹ️  Detected NT3H2211 (amiibo v3) tag. Dumping full 2048 bytes...")
    reg_bytes_2k = bytes.fromhex("4100F84808012100")
    dump, connection = dump_ntag_i2c_sector0(reader, connection, debug=debug)
    if len(dump) < 0x3C0:
        dump.extend(b'\x00' * (0x3C0 - len(dump)))

    # Read pages 0xEC..0xEF (0x3B0..0x3BF) right before SRAM at 0x3C0..0x3FF
    pre_sram = read_binary_pages(connection, 0xEC, 4, debug=debug)
    if pre_sram is not None and len(pre_sram) == 16:
        dump[0x3B0:0x3C0] = pre_sram
        dbg(debug, f"Read 0x3B0..0x3BF (pages 0xEC..0xEF): {pre_sram.hex().upper()}")

    sram_bytes = read_i2c_sram(connection, debug=debug)
    dbg(debug, f"v3 SRAM dump ({len(sram_bytes)}B): {sram_bytes.hex().upper()}")
    dump[0x3C0:0x400] = sram_bytes

    sec0_ref = bytes(dump[:1024])
    select_sector(connection, 1, uid, debug=debug)

    sec1_ranges = [(0x00, 0x1F), (0x20, 0x3F), (0x40, 0x5F), (0x60, 0x7F),
                   (0x80, 0x9F), (0xA0, 0xBF), (0xC0, 0xDF), (0xE0, 0xFF)]

    for start, end in sec1_ranges:
        chunk = fast_read(connection, start, end, debug=debug)
        if chunk is None:
            chunk = bytearray((end - start + 1) * 4)
        expected_sec0_chunk = sec0_ref[start * 4 : (end + 1) * 4]

        if bytes(chunk) == expected_sec0_chunk and any(b != 0 for b in chunk):
            select_sector(connection, 1, uid, debug=debug)
            chunk = fast_read(connection, start, end, debug=debug) or bytearray((end - start + 1) * 4)
            if bytes(chunk) == expected_sec0_chunk:
                chunk = bytearray((end - start + 1) * 4)
        dump += chunk

    select_sector(connection, 0, uid, debug=debug)
    ecc_sig = read_ecc_signature(connection, debug=debug)
    try:
        connection.disconnect()
    except Exception as e:
        dbg(debug, f"NT3H2211 disconnect ignored: {e}")

    patch_ntag_i2c_auth(dump, uid, pwd_skip=pwd_skip, debug=debug)
    reproduce_i2c_reg(dump, reg_bytes_2k, reproduce_reg=reproduce_reg, debug=debug)
    return bytes(dump), sram_bytes, ecc_sig


def fetch_character_name(amiibo_id_hex: str, debug: bool = False) -> Optional[str]:
    if len(amiibo_id_hex) < 16:
        return None

    head = amiibo_id_hex[:8].lower()
    tail = amiibo_id_hex[8:16].lower()
    url = f"https://amiiboapi.org/api/amiibo/?head={head}&tail={tail}"
    dbg(debug, f"Requesting AmiiboAPI: {url}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AmiiboHardwareDumper/1.5.3"})
        with urllib.request.urlopen(req, timeout=3) as response:
            dbg(debug, f"AmiiboAPI HTTP status: {response.status}")
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                amiibos = data.get("amiibo", [])
                if amiibos and "name" in amiibos[0]:
                    name = amiibos[0]["name"]
                    return re.sub(r'[<>:"/\\|?*]', '', name).strip()
    except Exception as e:
        dbg(debug, f"AmiiboAPI error: {e}")

    return None


def process_tag(
    reader,
    connection,
    uid: bytes,
    force: bool = False,
    target_size: int = 540,
    pwd_skip: bool = False,
    reproduce_reg: bool = False,
    nfc_flipper: bool = False,
    debug: bool = False,
) -> None:
    uid_hex = "".join(f"{b:02X}" for b in uid)
    print(f"🏷️  Tag UID: {' '.join(f'{b:02X}' for b in uid)}")

    tag_type, id_bytes = detect_tag_type(connection, uid, debug=debug)
    dbg(debug, f"Detected tag_type = {tag_type}")

    amiibo_id_str = "".join(f"{b:02X}" for b in id_bytes[:8])
    dbg(debug, f"Pre-dump ID string: {amiibo_id_str}")

    is_v3_id = len(id_bytes) >= 8 and id_bytes[7] == 0x03 and tag_type == "ntag215"
    is_band_id = len(id_bytes) >= 4 and id_bytes[3] == 0x03 and tag_type == "ntag215"

    if not force:
        if is_v3_id:
            raise ValueError(
                f"Tag ID {amiibo_id_str} indicates NT3H2211 (amiibo v3), but physical tag is NTAG215 (amiibo v2).\n"
                "   ⚠️  Skipping. Use -f / --force to override."
            )
        if is_band_id:
            raise ValueError(
                f"Tag ID {amiibo_id_str} indicates NT3H2111 (SNW Band) (4th byte is 03), but physical tag is NTAG215 (amiibo v2).\n"
                "   ⚠️  Skipping. Use -f / --force to override."
            )
    elif is_v3_id or is_band_id:
        print("   ⚠️  FORCE ACTIVE: Bypassing ID/hardware mismatch check and proceeding with dump...")

    sram_bytes = None
    if tag_type == "ntag215":
        raw_bin, _, sig_bytes = dump_ntag215(reader, connection, uid, target_size, pwd_skip=pwd_skip, debug=debug)
    elif tag_type == "i2c_1k":
        raw_bin, _, sig_bytes = dump_ntag_1k(reader, connection, uid, pwd_skip=pwd_skip, reproduce_reg=reproduce_reg, debug=debug)
    else:
        raw_bin, sram_bytes, sig_bytes = dump_ntag_v3(reader, connection, uid, pwd_skip=pwd_skip, reproduce_reg=reproduce_reg, debug=debug)

    amiibo_id_bytes = raw_bin[0x54 : 0x5C]
    if all(b == 0 for b in amiibo_id_bytes):
        print("❌  Bad dump detected. Please re-place the tag on the scanner to try again.")
        time.sleep(3.0)
        return

    amiibo_id_str = "".join(f"{b:02X}" for b in amiibo_id_bytes)

    print("🌐  Querying AmiiboAPI for character name...")
    char_name = fetch_character_name(amiibo_id_str, debug=debug)

    if char_name:
        print(f"   ℹ️  Resolved character name: {char_name}")
        identifier_part = char_name
    else:
        print("   ⚠️  API lookup failed or timed out. Falling back to ID identifier.")
        identifier_part = amiibo_id_str

    base_filename = f"{identifier_part} [{uid_hex}]"
    bin_filename = f"{base_filename}.bin"

    with open(bin_filename, "wb") as f:
        f.write(raw_bin)
    print(f"   ✅  Successfully saved main dump ({len(raw_bin)} bytes) to '{bin_filename}'.")

    if sram_bytes is not None:
        ext_filename = f"{base_filename}.ext"
        with open(ext_filename, "wb") as f:
            f.write(sram_bytes)
        print(f"   ✅  Successfully saved SRAM extension ({len(sram_bytes)} bytes) to '{ext_filename}'.")

    if nfc_flipper:
        if tag_type == "i2c_2k" and not force:
            print("   ⚠️  Flipper NFC export skipped for v3 amiibo (NT3H2211): pass -f / --force to force export (won't scan on real Flipper hardware).")
        else:
            if not any(b != 0 for b in sig_bytes):
                sig_bytes = fetch_sig_for_nfc(reader, debug=debug)
            nfc_text = build_flipper_nfc_text(
                tag_type=tag_type,
                uid=uid,
                page_source_bin=raw_bin,
                sig_bytes=sig_bytes,
                debug=debug,
            )
            nfc_filename = f"{base_filename}.nfc"
            with open(nfc_filename, "w", encoding="utf-8", newline="\n") as f:
                f.write(nfc_text)
            print(f"   ✅  Successfully saved Flipper NFC dump to '{nfc_filename}'.")

    print()


def check_exit_keypress() -> bool:
    if HAS_MSVCRT and msvcrt.kbhit():
        ch = msvcrt.getch()
        if ch in (b'\r', b'\n'):
            return True
    return False


def wait_for_tag_removal(reader, debug: bool = False) -> None:
    print("⏳  Please remove the tag...")
    while True:
        if check_exit_keypress():
            print("\n👋 Exiting dumper. Goodbye!")
            sys.exit(0)

        try:
            test_conn = reader.createConnection()
            test_conn.connect()
            test_resp, test_sw1, _ = test_conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            test_conn.disconnect()

            if test_sw1 == 0x90 and len(test_resp) >= 7:
                time.sleep(0.3)
                continue
        except Exception as e:
            dbg(debug, f"Tag removal check ended on exception: {e}")
            break
        time.sleep(0.3)


def run_live_loop(
    reader,
    force: bool = False,
    target_size: int = 540,
    pwd_skip: bool = False,
    reproduce_reg: bool = False,
    nfc_flipper: bool = False,
    debug: bool = False,
) -> None:
    print(f"📦  Target NTAG215 size : {target_size} bytes")
    if pwd_skip:
        print("🔓  PWD/PACK/RFUI patch : skipped (--pwd-skip)")
    if reproduce_reg:
        print("🧬  I2C register patch  : enabled (--reproduce-reg)")
    if nfc_flipper:
        print("🐬  Flipper NFC output  : enabled (--nfc-flipper)")
    if debug:
        print("🐛  Debug logging       : enabled")
    print("🔄  Waiting for tags... (Press Enter to exit)\n")
    try:
        while True:
            connection = None
            uid = None
            while True:
                if check_exit_keypress():
                    print("\n👋 Exiting dumper. Goodbye!")
                    sys.exit(0)

                try:
                    connection = reader.createConnection()
                    connection.connect()
                    uid_resp, sw1, _ = connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                    if sw1 == 0x90 and len(uid_resp) >= 7:
                        uid = uid_resp[:7]
                        break
                    else:
                        connection.disconnect()
                except Exception:
                    if connection:
                        try:
                            connection.disconnect()
                        except Exception as e:
                            dbg(debug, f"Poll disconnect ignored: {e}")
                time.sleep(0.3)

            print("⚡  Tag detected!")
            time.sleep(1.0)

            try:
                process_tag(
                    reader,
                    connection,
                    uid,
                    force=force,
                    target_size=target_size,
                    pwd_skip=pwd_skip,
                    reproduce_reg=reproduce_reg,
                    nfc_flipper=nfc_flipper,
                    debug=debug,
                )
            except Exception as e:
                print(f"   ❌  Error dumping tag: {e}\n")
                try:
                    connection.disconnect()
                except Exception as e:
                    dbg(debug, f"Error cleanup disconnect ignored: {e}")

            wait_for_tag_removal(reader, debug=debug)
            time.sleep(1.0)
            print("⏳  Ready for next tag... (Press Enter to exit)\n")

    except KeyboardInterrupt:
        print("\n👋 Exiting dumper. Goodbye!")
        sys.exit(0)


# Main Entry Point

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Amiibo hardware dumper via Pyscard / PC/SC."
    )
    parser.add_argument("-f", "--force", action="store_true", help="Bypass ID/version safety checks and dump anyway")
    parser.add_argument("-s", "--size", type=int, choices=[532, 540, 572], default=540, help="Output bin size for NTAG215 (532, 540 [default], or 572 with ECC signature)")
    parser.add_argument("-p", "--pwd-skip", action="store_true", help="Skip inserting derived PWD, PACK, and RFUI bytes on all dumps")
    parser.add_argument("-r", "--reproduce-reg", action="store_true", help="Write hardcoded session/config register bytes for I2C 1K/2K dumps")
    parser.add_argument("-n", "--nfc-flipper", action="store_true", help="Also write a Flipper Zero .nfc file alongside binary dumps")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable verbose debug logging")
    args = parser.parse_args()

    r = readers()
    if not r:
        abort("❌  Error: No smart card readers found.")

    reader = r[0]
    print(f"🔌  Using reader: {reader}")

    run_live_loop(
        reader,
        force=args.force,
        target_size=args.size,
        pwd_skip=args.pwd_skip,
        reproduce_reg=args.reproduce_reg,
        nfc_flipper=args.nfc_flipper,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()

################################################################################
#                                                                              #
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE                       #
#                    Version 2, December 2004                                  #
#                                                                              #
# Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>                             #
#                                                                              #
# Everyone is permitted to copy and distribute verbatim or modified            #
# copies of this license document, and changing it is allowed as long          #
# as the name is changed.                                                      #
#                                                                              #
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE                       #
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION            #
#                                                                              #
#  0. You just DO WHAT THE FUCK YOU WANT TO.                                   #
#                                                                              #
################################################################################
