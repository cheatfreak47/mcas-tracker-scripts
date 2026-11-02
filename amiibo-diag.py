#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibo diag - Comprehensive diagnostic and metadata extraction utility for Amiibo bin/dec dumps.

import argparse
import os
import sys
from typing import Optional, Tuple

print("👾  amiibo diag v2.4.7 by CheatFreak  👾\n"
      "---------------------------------------\n"
      "Extracts full diagnostic information, ID metadata, and save details from Amiibo dumps.\n"
      "Run with -h for helpful information on all functions.\n")

try:
    from amiibo import AmiiboDump, AmiiboMasterKey
except ImportError:
    print("Error: The 'pyamiibo' package is required but not installed.")
    print("Please install it via your terminal: pip install pyamiibo")
    sys.exit(1)


# Exit and Error Helpers

def abort(msg: str, no_pause: bool = False) -> None:
    print(msg)
    if not no_pause:
        input("\nPress Enter to exit...")
    sys.exit(1)


# Master Key Loading

def load_master_keys(no_pause: bool = False) -> AmiiboMasterKey:
    candidates = ["key_retail.bin", os.path.join("..", "keys", "key_retail.bin")]

    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    return AmiiboMasterKey.from_combined_bin(f.read())
            except Exception as e:
                abort(f"Error reading '{path}': {e}", no_pause)

    abort("Error: Master key file 'key_retail.bin' not found in the current directory or in '../keys/'.", no_pause)


# BCC and Crypto Validation Helpers

def compute_bcc0(uid_prefix: bytes) -> int:
    return 0x88 ^ uid_prefix[0] ^ uid_prefix[1] ^ uid_prefix[2]


def compute_bcc1(uid_suffix: bytes) -> int:
    return uid_suffix[0] ^ uid_suffix[1] ^ uid_suffix[2] ^ uid_suffix[3]


def generate_expected_pwd(raw_data: bytes) -> Optional[bytes]:
    if len(raw_data) < 8:
        return None
    uid = raw_data[0:3] + raw_data[4:8]
    if len(uid) < 7:
        return None
    pwd0 = 0xAA ^ uid[1] ^ uid[3]
    pwd1 = 0x55 ^ uid[2] ^ uid[4]
    pwd2 = 0xAA ^ uid[3] ^ uid[5]
    pwd3 = 0x55 ^ uid[4] ^ uid[6]
    return bytes([pwd0, pwd1, pwd2, pwd3])


def parse_packed_date(val: int) -> Optional[str]:
    if not val or val == 0:
        return None
    year = (val >> 9) & 0x7F
    month = (val >> 5) & 0x0F
    day = val & 0x1F
    if month < 1 or month > 12 or day < 1 or day > 31:
        return None
    return f"20{year:02d}-{month:02d}-{day:02d}"


# Form Factor Mapping via Byte 0x57

FORM_MAPPING = {
    0x00: "Figure",
    0x01: "Card",
    0x02: "Plush",
    0x03: "Band",
    0x04: "Block"
}

def get_form_factor(raw_data: bytes) -> str:
    if len(raw_data) > 0x57:
        form_byte = raw_data[0x57]
        return FORM_MAPPING.get(form_byte, "Unknown")
    return "Unknown"


# Diagnostic Parsing and Extraction

def parse_amiibo_diag(file_path: str, master_key: AmiiboMasterKey, debug: bool) -> Optional[dict]:
    diag = {}
    filename = os.path.basename(file_path)
    diag["filename"] = filename
    is_dec = filename.lower().endswith(".dec")

    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()

        file_size = len(raw_data)
        diag["file_size"] = file_size

        # Strict NTAG215 size validation (532, 540, or 572 bytes) and byte 0x09 check
        VALID_SIZES = {532, 540, 572}
        if not debug:
            if file_size not in VALID_SIZES or file_size < 10 or raw_data[0x09] != 0x48:
                return None  # Skip non-NTAG215 files completely

        # Normalize size container for pyamiibo parsing
        if file_size == 572:
            parse_data = raw_data[:540]
        elif file_size == 532:
            parse_data = raw_data + b"\x00" * (540 - file_size)
        else:
            parse_data = raw_data

        dump = AmiiboDump(master_key, parse_data)
        if not is_dec:
            dump.unlock()

        # Amiibo ID from plaintext bytes 0x54 to 0x5C (84 to 92)
        if len(raw_data) >= 92:
            diag["amiibo_id"] = raw_data[84:92].hex().upper()
        else:
            diag["amiibo_id"] = "Unknown"

        diag["form"] = get_form_factor(raw_data)
        diag["tag_type"] = "NTAG215"

        # UID and BCC checks (strictly no spaces)
        uid_hex = dump.uid_hex.upper().replace(" ", "") if hasattr(dump, "uid_hex") else ""
        diag["uid"] = uid_hex

        if len(raw_data) >= 9:
            uid_prefix = raw_data[0:3]
            bcc0_val = raw_data[3]
            uid_suffix = raw_data[4:8]
            bcc1_val = raw_data[8]

            calc_bcc0 = compute_bcc0(uid_prefix)
            calc_bcc1 = compute_bcc1(uid_suffix)

            diag["bcc0"] = f"Good ({bcc0_val:02X})" if bcc0_val == calc_bcc0 else f"Bad ({bcc0_val:02X} != {calc_bcc0:02X})"
            diag["bcc1"] = f"Good ({bcc1_val:02X})" if bcc1_val == calc_bcc1 else f"Bad ({bcc1_val:02X} != {calc_bcc1:02X})"
        else:
            diag["bcc0"] = "??"
            diag["bcc1"] = "??"

        # PWD check (Page 133 / bytes 532 to 535) with correct fallback PWD in parenthesis
        expected_pwd_bytes = generate_expected_pwd(raw_data)
        expected_pwd_str = expected_pwd_bytes.hex().upper() if expected_pwd_bytes else "00000000"

        if len(raw_data) >= 536:
            pwd_bytes = raw_data[532:536]
            if pwd_bytes == b"\x00\x00\x00\x00":
                diag["pwd"] = f"Missing ({expected_pwd_str})"
            else:
                if expected_pwd_bytes and pwd_bytes == expected_pwd_bytes:
                    diag["pwd"] = pwd_bytes.hex().upper()
                else:
                    diag["pwd"] = f"Invalid ({expected_pwd_str})"
        else:
            diag["pwd"] = f"Missing ({expected_pwd_str})"

        # Write counter offset (0x108 to 0x10A)
        write_count = int.from_bytes(dump.data[0x108:0x10A], "big") if len(dump.data) > 0x10A else 0
        diag["write_count"] = write_count

        reg_flag = dump.data[0x14] if len(dump.data) > 0x14 else 0
        diag["save_present"] = reg_flag != 0
        diag["reg_flag_hex"] = f"{reg_flag:02X}"

        # Initialize optional fields
        diag["reg_date"] = None
        diag["write_date"] = None
        diag["nickname"] = None
        diag["mii_name"] = None
        diag["mii_author"] = None
        diag["save_tid"] = None

        # Parse dates if save/owner present or debug
        if debug or reg_flag != 0:
            if len(dump.data) >= 0x1A:
                reg_val = int.from_bytes(dump.data[0x18:0x1A], "big")
                diag["reg_date"] = parse_packed_date(reg_val)

            if len(dump.data) >= 0x1C:
                write_val = int.from_bytes(dump.data[0x1A:0x1C], "big")
                diag["write_date"] = parse_packed_date(write_val)

        # Gating based on Settings byte 0x14:
        # 00 = Uninit, 10 = Owner Present, 20 = Save Present, 30 = Owner and Save Present
        show_owner = debug or (reg_flag in (0x10, 0x30))
        show_tid = debug or (reg_flag in (0x20, 0x30))

        # Nickname extraction (0x20 to 0x34) requires owner present (10 or 30)
        if show_owner:
            try:
                nick_bytes = dump.data[0x20:0x34] if len(dump.data) >= 0x34 else b""
                decoded_nick = nick_bytes.decode("utf-16-be", errors="ignore").split("\x00")[0].strip()
                if decoded_nick:
                    diag["nickname"] = decoded_nick
            except Exception:
                pass

        # Mii data extraction (0xA0 to 0x100) if owner present
        if show_owner and len(dump.data) >= 0x100:
            mii_block = dump.data[0xA0:0x100]
            try:
                name_bytes = mii_block[0x1A:0x28]
                decoded_mii_name = name_bytes.decode("utf-16-le", errors="ignore").split("\x00")[0].strip()
                if decoded_mii_name:
                    diag["mii_name"] = decoded_mii_name

                author_bytes = mii_block[0x48:0x60]
                if author_bytes != b"\x00" * len(author_bytes):
                    decoded_author = author_bytes.decode("utf-16-le", errors="ignore").split("\x00")[0].strip()
                    if decoded_author:
                        diag["mii_author"] = decoded_author
            except Exception:
                pass

        # Save TID extraction (0x100 to 0x108) if save present (20 or 30)
        if show_tid and len(dump.data) >= 0x108:
            tid_bytes = dump.data[0x100:0x108]
            if tid_bytes != b"\x00" * len(tid_bytes):
                diag["save_tid"] = tid_bytes.hex().upper()

    except Exception as e:
        diag["error"] = str(e)

    return diag


# Formatted Output Display

def print_diag_result(diag: dict) -> None:
    filename = diag.get("filename", "Unknown")
    file_size = diag.get("file_size", 0)

    if "error" in diag:
        print(f"📄  {filename} | Size: {file_size}B")
        print(f"  ❌ Error parsing dump: {diag['error']}\n")
        return

    # Line 1: Filename and Size
    print(f"📄  {filename} | Size: {file_size}B")

    # Line 2: AmiiboID, Form, Type
    amiibo_id = diag.get("amiibo_id", "Unknown")
    form = diag.get("form", "Unknown")
    tag_type = diag.get("tag_type", "NTAG215")
    print(f"  ℹ️ AmiiboID: {amiibo_id} | Form: {form} | Type: {tag_type}")

    # Line 3: UID, BCC0, BCC1, PWD
    uid = diag.get("uid", "Unknown")
    bcc0 = diag.get("bcc0", "??")
    bcc1 = diag.get("bcc1", "??")
    pwd = diag.get("pwd", "Missing")
    print(f"  ℹ️ UID: {uid} | BCC0: {bcc0} | BCC1: {bcc1} | PWD: {pwd}")

    # Line 4: Save state, Write Count, Dates
    save_present = diag.get("save_present", False)
    reg_hex = diag.get("reg_flag_hex", "00")
    write_count = diag.get("write_count", 0)

    save_str = f"Yes ({reg_hex})" if save_present else f"No ({reg_hex})"
    line4 = f"  ℹ️ Save: {save_str} | Write Count: {write_count}"

    reg_date = diag.get("reg_date")
    write_date = diag.get("write_date")
    if reg_date:
        line4 += f" | Reg Date: {reg_date}"
    if write_date:
        line4 += f" | Last Write Date: {write_date}"
    print(line4)

    # Line 5 (Optional): Nickname, Mii details, Save TID
    parts = []
    nickname = diag.get("nickname")
    mii_name = diag.get("mii_name")
    mii_author = diag.get("mii_author")
    save_tid = diag.get("save_tid")

    if nickname:
        parts.append(f"Nickname: {nickname}")
    if mii_name:
        parts.append(f"Mii: {mii_name}")
    if mii_author:
        parts.append(f"Mii Author: {mii_author}")
    if save_tid:
        parts.append(f"Save TID: {save_tid}")

    if parts:
        print(f"  💾 {' | '.join(parts)}")

    print()


# Filter Evaluation

def passes_filter(diag: dict, filter_mode: Optional[str]) -> bool:
    if not filter_mode:
        return True

    reg_hex = diag.get("reg_flag_hex", "00").lower()
    mode = filter_mode.lower()

    if mode == "n":
        return reg_hex == "00"
    elif mode == "s":
        return reg_hex != "00"
    elif mode == "s10":
        return reg_hex == "10"
    elif mode == "s20":
        return reg_hex == "20"
    elif mode == "s30":
        return reg_hex == "30"
    
    return True


# Path Processing and Routing

def process_path(target_path: str, master_key: AmiiboMasterKey, ignore_extension: bool, debug: bool, filter_mode: Optional[str]) -> None:
    if os.path.isfile(target_path):
        diag = parse_amiibo_diag(target_path, master_key, debug)
        if diag:
            if passes_filter(diag, filter_mode):
                print_diag_result(diag)
        else:
            print(f"📄  {os.path.basename(target_path)}")
            print("  ⏭️  Skipped: Not an NTAG215 Amiibo dump (invalid size or byte 0x09 != 0x48).\n")
    elif os.path.isdir(target_path):
        count = 0
        skipped_count = 0
        filtered_count = 0
        for root, _, files in os.walk(target_path):
            for file in files:
                ext = file.lower()
                if not (ignore_extension or ext.endswith(".bin") or ext.endswith(".dec")):
                    continue
                full_path = os.path.join(root, file)
                diag = parse_amiibo_diag(full_path, master_key, debug)
                if diag:
                    if passes_filter(diag, filter_mode):
                        print_diag_result(diag)
                        count += 1
                    else:
                        filtered_count += 1
                else:
                    skipped_count += 1
        print(f"Finished diagnosing {count} file(s) displayed ({filtered_count} filtered out, {skipped_count} non-NTAG215 file(s) skipped).\n")
    else:
        print(f"Error: Path '{target_path}' is not a valid file or directory.")


# CLI Arguments and Execution

def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Comprehensive diagnostic and metadata extraction utility for Amiibo bin/dec dumps."
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to a .bin/.dec file or directory (default: current directory)")
    parser.add_argument("-x", "--ignore-extension", action="store_true", help="Bypass the .bin/.dec extension filter when scanning directories")
    parser.add_argument("-d", "--debug", action="store_true", help="Bypass visibility checks and attempt to display all metadata regardless of state flags")
    parser.add_argument("-f", "--filter", choices=["n", "s", "s10", "s20", "s30"], help="Filter output: n (no save/00), s (any save), s10 (settings 10), s20 (settings 20), s30 (settings 30)")
    parser.add_argument("-p", "--no-pause", action="store_true", help="Do not pause on exit when run directly")
    args = parser.parse_args()

    master_key = load_master_keys(no_pause=args.no_pause)
    process_path(args.path, master_key, args.ignore_extension, args.debug, args.filter)
    return args.no_pause


if __name__ == "__main__":
    no_pause = main()
    if not no_pause:
        input("Press Enter to exit...")

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
