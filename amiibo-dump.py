#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Amiibo Hardware Dumper via Pyscard / PC/SC

import argparse
import json
import os
import re
import urllib.request
import sys
import time
from typing import Optional, Tuple

try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False

print("👾  Amiibo Hardware Dumper v1.3.1 by CheatFreak  👾\n"
      "---------------------------------------------------\n"
      "Universal NFC dumper for NTAG215, NT3H2111, and NT3H2211 amiibo tags.\n"
      "Only tested with an ACR1252U NFC Smart Card reader. Other readers, ymmv.\n"
      "Run with -h for help on available options.\n")

try:
    from smartcard.System import readers
    from smartcard.Exceptions import NoCardException
except ImportError:
    print("Error: The 'pyscard' library is missing.")
    print("Please install it using your terminal: pip install pyscard")
    sys.exit(1)


# Exit Helpers

def abort(msg: str) -> None:
    print(msg)
    input("\nPress Enter to exit...")
    sys.exit(1)


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


def unlock_tag(connection, uid: bytes) -> None:
    pwd0 = uid[1] ^ uid[3] ^ 0xAA
    pwd1 = uid[2] ^ uid[4] ^ 0x55
    pwd2 = uid[3] ^ uid[5] ^ 0xAA
    pwd3 = uid[4] ^ uid[6] ^ 0x55
    auth_cmd = [0x1B, pwd0, pwd1, pwd2, pwd3]
    try:
        send_direct_transceive(connection, auth_cmd)
    except Exception:
        pass


def select_sector(connection, sector: int, uid: bytes) -> None:
    try:
        send_direct_transceive(connection, [0xC2, 0xFF])
    except Exception:
        pass

    try:
        send_direct_transceive(connection, [sector & 0xFF, 0x00, 0x00, 0x00])
    except Exception:
        pass

    time.sleep(0.05)
    unlock_tag(connection, uid)
    time.sleep(0.03)


def reset_connection(reader, connection, uid: bytes):
    try:
        connection.disconnect()
    except Exception:
        pass
    time.sleep(0.05)
    connection = reader.createConnection()
    connection.connect()
    unlock_tag(connection, uid)
    time.sleep(0.03)
    return connection


def fast_read(connection, start_page: int, end_page: int) -> bytearray:
    cmd = [0x3A, start_page & 0xFF, end_page & 0xFF]
    resp, sw1, sw2 = send_direct_transceive(connection, cmd)
    expected_bytes = (end_page - start_page + 1) * 4
    if len(resp) == expected_bytes and (sw1 == 0x90 or sw1 == 0x00):
        return bytearray(resp)
    else:
        return bytearray(expected_bytes)


def read_ecc_signature(connection) -> bytes:
    # Reads the 32-byte NXP ECC originality signature via native 0x3C (READ_SIG) command
    try:
        resp, sw1, sw2 = send_direct_transceive(connection, [0x3C, 0x00])
        if sw1 == 0x90 and len(resp) >= 32:
            return bytes(resp[:32])
    except Exception:
        pass
    return b'\x00' * 32


def fast_write_sram(connection, buffer: bytearray) -> None:
    assert len(buffer) == 64
    cmd = [0xA6, 0xF0, 0xFF] + list(buffer)
    send_direct_transceive(connection, cmd)


def request_sram(connection) -> None:
    buffer = bytearray(64)
    buffer[0] = 0x01
    crc = crc16_mcrf4xx(buffer[:62])
    buffer[62] = (crc >> 8) & 0xFF
    buffer[63] = crc & 0xFF
    fast_write_sram(connection, buffer)


def poll_sram_ready(connection) -> None:
    attempts = 0
    while attempts < 25:
        try:
            regs = fast_read(connection, 0xED, 0xED)
            if len(regs) >= 3 and (regs[2] & 0x08) != 0:
                return
        except Exception:
            pass
        attempts += 1
        time.sleep(0.02)


def detect_tag_type(connection) -> str:
    # Distinguishes between NTAG215 (amiibo v2), NT3H2111 (SNW Band), and NT3H2211 (amiibo v3).
    try:
        resp, sw1, _ = send_direct_transceive(connection, [0x3A, 0xF0, 0xF0])
        if sw1 == 0x90 and len(resp) == 4:
            version_resp, v_sw1, _ = send_direct_transceive(connection, [0x11])
            if v_sw1 == 0x90 and len(version_resp) >= 8:
                storage_byte = version_resp[6]
                if storage_byte == 0x1E:
                    return "i2c_1k"
            return "i2c_2k"
    except Exception:
        pass
    return "ntag215"


def patch_ntag215_auth(raw_bin: bytearray, uid: bytes) -> None:
    # Inserts mathematically derived PWD and standard PACK/RFUI bytes into NTAG215 binary at correct page offsets.
    if len(raw_bin) >= 540 and len(uid) >= 7:
        pwd0 = 0xAA ^ uid[1] ^ uid[3]
        pwd1 = 0x55 ^ uid[2] ^ uid[4]
        pwd2 = 0xAA ^ uid[3] ^ uid[5]
        pwd3 = 0x55 ^ uid[4] ^ uid[6]
        
        # Page 133 (offset 532 / 0x214): PWD
        raw_bin[532:536] = bytes([pwd0, pwd1, pwd2, pwd3])
        # Page 134 (offset 536 / 0x218): PACK (80 80) + RFUI/Access (00 00)
        raw_bin[536:538] = b'\x80\x80'
        raw_bin[538:540] = b'\x00\x00'


# Dump Operations

def dump_ntag215(reader, connection, uid: bytes, target_size: int) -> Tuple[bytes, Optional[bytes]]:
    print(f"   ℹ️  Detected standard NTAG215 (amiibo v2) tag. Reconnecting and reading for target size ({target_size}B)...")
    try:
        connection.disconnect()
    except Exception:
        pass
    time.sleep(0.05)
    connection = reader.createConnection()
    connection.connect()

    dump_data = bytearray()
    for page in range(0, 136, 4):
        if page > 132:
            break
        apdu = [0xFF, 0xB0, 0x00, page, 0x10]
        response, sw1, sw2 = connection.transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            dump_data.extend(response)
        else:
            raise Exception(f"Failed to read NTAG215 around page {page}: SW={hex(sw1)} {hex(sw2)}")
    
    ecc_sig = b''
    if target_size == 572:
        ecc_sig = read_ecc_signature(connection)

    connection.disconnect()
    
    raw_bin = bytearray(dump_data[:540])
    patch_ntag215_auth(raw_bin, uid)

    if target_size == 532:
        final_bin = bytes(raw_bin[:532])
    elif target_size == 572:
        final_bin = bytes(raw_bin) + ecc_sig
    else:
        final_bin = bytes(raw_bin)

    return final_bin, None


def dump_ntag_i2c_sector0(reader, connection, uid: bytes):
    connection = reset_connection(reader, connection, uid)
    
    request_sram(connection)
    poll_sram_ready(connection)
    sram = fast_read(connection, 0xF0, 0xFF)

    dump = bytearray()
    for start, end in [(0x00, 0x1F), (0x20, 0x3F), (0x40, 0x5F), (0x60, 0x7F),
                       (0x80, 0x9F), (0xA0, 0xBF), (0xC0, 0xDF), (0xE0, 0xE9)]:
        dump += fast_read(connection, start, end)
    dump += bytearray(8)
    dump += fast_read(connection, 0xEC, 0xED)
    dump += bytearray(8)
    dump += sram
    
    return dump, connection


def dump_ntag_1k(reader, connection, uid: bytes, target_size: int) -> Tuple[bytes, Optional[bytes]]:
    print("   ℹ️  Detected NT3H2111 (SNW Band). Dumping 924 bytes...")
    dump, connection = dump_ntag_i2c_sector0(reader, connection, uid)
    connection.disconnect()
    return bytes(dump), None


def dump_ntag_v3(reader, connection, uid: bytes, target_size: int) -> Tuple[bytes, bytes]:
    print("   ℹ️  Detected NT3H2211 (amiibo v3) tag. Dumping full 2048 bytes...")
    dump, connection = dump_ntag_i2c_sector0(reader, connection, uid)
    sec0_ref = bytes(dump[:1024])

    select_sector(connection, 1, uid)

    sec1_ranges = [(0x00, 0x1F), (0x20, 0x3F), (0x40, 0x5F), (0x60, 0x7F),
                   (0x80, 0x9F), (0xA0, 0xBF), (0xC0, 0xDF), (0xE0, 0xFF)]
    
    for start, end in sec1_ranges:
        chunk = fast_read(connection, start, end)
        expected_sec0_chunk = sec0_ref[start * 4 : (end + 1) * 4]
        
        if bytes(chunk) == expected_sec0_chunk and any(b != 0 for b in chunk):
            select_sector(connection, 1, uid)
            chunk = fast_read(connection, start, end)
            if bytes(chunk) == expected_sec0_chunk:
                chunk = bytearray((end - start + 1) * 4)
        dump += chunk

    select_sector(connection, 0, uid)
    connection.disconnect()
    
    sram_bytes = bytes(dump[0x3C0:0x400])
    return bytes(dump), sram_bytes


def fetch_character_name(amiibo_id_hex: str) -> Optional[str]:
    # Queries amiiboapi.org using head and tail hex to resolve the character name.
    if len(amiibo_id_hex) < 16:
        return None
    
    head = amiibo_id_hex[:8].lower()
    tail = amiibo_id_hex[8:16].lower()
    url = f"https://amiiboapi.org/api/amiibo/?head={head}&tail={tail}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AmiiboHardwareDumper/1.3"})
        with urllib.request.urlopen(req, timeout=3) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                amiibos = data.get("amiibo", [])
                if amiibos and "name" in amiibos[0]:
                    name = amiibos[0]["name"]
                    # Sanitize name for filesystem safety
                    return re.sub(r'[<>:"/\\|?*]', '', name).strip()
    except Exception:
        pass
    
    return None


def process_tag(reader, connection, uid: bytes, force: bool = False, target_size: int = 540) -> None:
    uid_hex = "".join(f"{b:02X}" for b in uid)
    print(f"🏷️  Tag UID: {' '.join(f'{b:02X}' for b in uid)}")

    tag_type = detect_tag_type(connection)

    try:
        if tag_type == "ntag215":
            apdu = [0xFF, 0xB0, 0x00, 0x15, 0x08]
            resp, sw1, _ = connection.transmit(apdu)
            id_bytes = bytes(resp) if sw1 == 0x90 and len(resp) >= 8 else b'\x00' * 8
        else:
            id_bytes = bytes(fast_read(connection, 0x15, 0x16))
    except Exception:
        id_bytes = b'\x00' * 8

    amiibo_id_str = "".join(f"{b:02X}" for b in id_bytes[:8])

    if not force:
        if tag_type == "ntag215" and amiibo_id_str.endswith("03"):
            raise ValueError(
                f"Tag ID {amiibo_id_str} indicates NT3H2211 (amiibo v3), but was misdetected as NTAG215 (amiibo v2).\n"
                "   ⚠️  Skipping. Use -f / --force to override."
            )

        if len(id_bytes) >= 4 and id_bytes[3] == 0x03 and tag_type == "ntag215":
            raise ValueError(
                f"Tag ID {amiibo_id_str} indicates NT3H2111 (SNW Band) (4th byte is 03), but was misdetected as NTAG215 (amiibo v2).\n"
                "   ⚠️  Skipping. Use -f / --force to override."
            )
    else:
        if (tag_type == "ntag215" and amiibo_id_str.endswith("03")) or (len(id_bytes) >= 4 and id_bytes[3] == 0x03 and tag_type == "ntag215"):
            print("   ⚠️  FORCE ACTIVE: Bypassing safety check and proceeding with dump...")

    sram_bytes = None
    if tag_type == "ntag215":
        raw_bin, _ = dump_ntag215(reader, connection, uid, target_size)
    elif tag_type == "i2c_1k":
        raw_bin, _ = dump_ntag_1k(reader, connection, uid, target_size)
    else:
        raw_bin, sram_bytes = dump_ntag_v3(reader, connection, uid, target_size)

    # BAD DUMP CHECK: Verify parsed ID bytes from the raw dump aren't all 00s (bypasses force mode)
    amiibo_id_bytes = raw_bin[0x54 : 0x5C]
    if all(b == 0 for b in amiibo_id_bytes):
        print("❌  Bad dump detected. Please re-place the tag on the scanner to try again.")
        time.sleep(3.0)
        return

    amiibo_id_str = "".join(f"{b:02X}" for b in amiibo_id_bytes)
    
    print("🌐  Querying AmiiboAPI for character name...")
    char_name = fetch_character_name(amiibo_id_str)
    
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
    print()


def check_exit_keypress() -> bool:
    # Checks if Enter was pressed to exit live mode.
    if HAS_MSVCRT and msvcrt.kbhit():
        ch = msvcrt.getch()
        if ch in (b'\r', b'\n'):
            return True
    return False


def run_live_loop(reader, force: bool = False, target_size: int = 540) -> None:
    print(f"📦  Target NTAG215 size : {target_size} bytes")
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
                        except:
                            pass
                time.sleep(0.3)

            print("⚡  Tag detected!")
            time.sleep(1.0)

            try:
                process_tag(reader, connection, uid, force=force, target_size=target_size)
            except Exception as e:
                print(f"   ❌  Error dumping tag: {e}\n")
                try:
                    connection.disconnect()
                except:
                    pass

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
                except Exception:
                    break
                time.sleep(0.3)

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
    args = parser.parse_args()

    r = readers()
    if not r:
        abort("❌  Error: No smart card readers found.")
    
    reader = r[0]
    print(f"🔌  Using reader: {reader}")

    run_live_loop(reader, force=args.force, target_size=args.size)


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
