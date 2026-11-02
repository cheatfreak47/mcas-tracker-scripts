#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibo generator - Generate Amiibo v2 NTAG215 binaries from IDs or CSV/TXT, completely from scratch.

import argparse
import csv
import glob
import os
import random
import re
import sys
from typing import NamedTuple

print("👾  amiibo generator v1.4.5 by CheatFreak  👾\n"
      "---------------------------------------------\n"
      "A tool for casting dark magic to generate authentic looking amiibo bin files from keys and an ID."
      "Run with -h to for helpful information on all functions.\n")

try:
    from amiibo import AmiiboDump, AmiiboMasterKey
except ImportError:
    print("Error: The 'pyamiibo' package is required but not installed.")
    print("Please install it via your terminal: pip install pyamiibo")
    sys.exit(1)

# Generation Result

class AmiiboGenResult(NamedTuple):
    # Structured result from amiibo buffer generation.
    raw_data: bytes     # 540-byte NTAG215 layout
    uid_str: str        # Formatted UID string
    id_str: str         # Hex ID string
    var_str: str        # Hex Page 23 variant string
    is_wristband: bool  # Flag indicating wristband form type


# Exit & Error Helpers

def abort(msg: str) -> None:
    # Print error message and exit.
    print(msg)
    sys.exit(1)


# Master Key Loading

def load_master_keys() -> AmiiboMasterKey:
    # Load master keys from key_retail.bin in the current directory.
    if not os.path.exists("key_retail.bin"):
        abort("[!] Error: Master key file 'key_retail.bin' not found in current directory.")
    try:
        with open("key_retail.bin", "rb") as f:
            return AmiiboMasterKey.from_combined_bin(f.read())
    except Exception as e:
        abort(f"Error reading 'key_retail.bin': {e}")


# Amiibo Buffer Building

def build_amiibo_buffer(id_arg: str) -> AmiiboGenResult:
    # Build a 540-byte raw NTAG215 layout
    raw_data = bytearray(540)

    # 1. UID Generation & BCC Calculations
    uid0 = 0x04  # NXP manufacturer byte
    uid1 = random.randint(0, 255)
    uid2 = random.randint(0, 255)
    bcc0 = 0x88 ^ uid0 ^ uid1 ^ uid2  # BCC0 = 0x88 XOR UID[0:3]

    uid3 = (v := random.randint(0, 254)) + (v >= 0x88) # Cannot be 0x88 to prevent cascade conflicts
    uid4 = random.randint(0, 255)
    uid5 = random.randint(0, 255)
    uid6 = random.choice([0x80, 0x81, 0x90, 0x91])  # Retail batch byte
    bcc1 = uid3 ^ uid4 ^ uid5 ^ uid6

    raw_data[0x00:0x04] = bytes([uid0, uid1, uid2, bcc0])    # Page 0 (UID first half + BCC0)
    raw_data[0x04:0x08] = bytes([uid3, uid4, uid5, uid6])    # Page 1 (UID second half)
    raw_data[0x08:0x0C] = bytes([bcc1, 0x48, 0x0F, 0xE0])    # Page 2 (BCC1, INT, Internal)
    raw_data[0x0C:0x10] = bytes([0xF1, 0x10, 0xFF, 0xEE])    # Page 3 (Capability Container)
    raw_data[0x10:0x14] = bytes([0xA5, 0x00, 0x00, 0x00])    # Page 4 (Signature & Counter)

    # 2. Factory Reset / Initialization Zone Seeding (Random noise + zeroed config bits)
    raw_data[0x14:0x18] = b'\x00' * 4                # Wipe configuration/init bits through 0x17
    raw_data[0x11:0x13] = os.urandom(2)              # Random garbage in 0x11-0x12
    raw_data[0x18:0x34] = os.urandom(0x34 - 0x18)    # Random garbage in 0x18-0x33

    # 3. Layout Fill Zones
    raw_data[13 * 4 : 21 * 4] = b"\xFF" * ((21 - 13) * 4)  # Locked Hash placeholders
    raw_data[24 * 4 : 32 * 4] = os.urandom((32 - 24) * 4)  # Keygen Salt entropy
    raw_data[32 * 4 : 40 * 4] = b"\xFF" * ((40 - 32) * 4)  # Unfixed Hash placeholders

    # 4. Parse ID and Auto-Detect Form Type
    clean_id_arg = id_arg.strip()
    if len(clean_id_arg) not in (16, 24):
        raise ValueError(
            f"Invalid ID '{clean_id_arg}': Must be 16 hex chars (ID only) or "
            "24 hex chars (ID + Page 23 override)."
        )

    input_bytes = bytes.fromhex(clean_id_arg)
    id_bytes = input_bytes[0:8]

    # Validate Amiibo v2 (8th byte / index 7 must be 0x02)
    if len(id_bytes) >= 8 and id_bytes[7] != 0x02:
        raise ValueError("Error: Only Amiibo v2 is supported.")

    raw_data[21 * 4 : 21 * 4 + 8] = id_bytes

    form_byte = id_bytes[3]  # Form type extracted from ID byte index 3
    is_wristband = (form_byte == 0x03)
    
    # Page 23: Explicit override takes precedence, otherwise auto-generate inline via form byte
    if len(input_bytes) == 12:
        page23_data = input_bytes[8:12]
    else:
        if form_byte == 0x01:
            # Card form - randomized card number digits
            b0 = random.choices(
                [0x30, 0x31, 0x32, 0x33, 0x34, 0x38, 0x39],
                weights=[50, 15, 15, 15, 2, 2, 1],
            )[0]
            b1 = random.randint(0x30, 0x39)
            b2 = random.randint(0x30, 0x39)
            b3 = random.choices([0x31, 0x30, 0x32, 0x33], weights=[50, 30, 15, 5])[0]
            page23_data = bytes([b0, b1, b2, b3])
        elif form_byte == 0x03:
            # Wristband / Power-Up Band form - fixed SNW signature placeholder
            page23_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        else:
            # Figure (0x00), Plush/Yarn (0x02), Block (0x04), etc.
            b0 = random.choices([0x0D, 0x05, 0x0A, 0x04], weights=[75, 15, 9, 1])[0]
            b1 = random.choices([0x12, 0x11], weights=[99, 1])[0]
            x_nibble = random.randint(1, 12)
            y_nibble = random.randint(0, 9)
            b2 = (x_nibble << 4) | y_nibble
            b3 = random.randint(0x01, 0x1F)
            page23_data = bytes([b0, b1, b2, b3])

    raw_data[23 * 4 : 23 * 4 + 4] = page23_data

    # 5. Configuration Pages, Save Region Noise, and Password Derivation
    raw_data[0xA0:0x208] = os.urandom(0x208 - 0xA0)  # Random garbage in save data region (0xA0 to 0x207)
    raw_data[0x108:0x10A] = b'\x00' * 2              # Explicitly zero out app counters

    raw_data[130 * 4 : 130 * 4 + 4] = bytes([0x01, 0x00, 0x0F, 0xBD])
    raw_data[131 * 4 : 131 * 4 + 4] = bytes([0x00, 0x00, 0x00, 0x04])
    raw_data[132 * 4 : 132 * 4 + 4] = bytes([0x5F, 0x00, 0x00, 0x00])

    pwd0 = 0xAA ^ uid1 ^ uid3
    pwd1 = 0x55 ^ uid2 ^ uid4
    pwd2 = 0xAA ^ uid3 ^ uid5
    pwd3 = 0x55 ^ uid4 ^ uid6
    raw_data[133 * 4 : 133 * 4 + 4] = bytes([pwd0, pwd1, pwd2, pwd3])  # Password page
    raw_data[134 * 4 : 134 * 4 + 4] = bytes([0x80, 0x80, 0x00, 0x00])  # PACK page

    uid_str = f"{uid0:02X} {uid1:02X} {uid2:02X} {uid3:02X} {uid4:02X} {uid5:02X} {uid6:02X}"
    id_str = id_bytes.hex().upper()
    var_str = page23_data.hex().upper()

    return AmiiboGenResult(bytes(raw_data), uid_str, id_str, var_str, is_wristband)


# File Output

def process_and_save(raw_data: bytes, output_filename: str, *,
                     debug_mode: bool, master_keys: AmiiboMasterKey) -> str:
    # Encrypt, sign, and write output files (.bin and optional pre-lock .dec) with collision checking.
    base_name, _ = os.path.splitext(output_filename)
    if not base_name:
        base_name = "template"

    bin_filename = f"{base_name}.bin"
    dec_filename = f"{base_name}.dec" if debug_mode else None

    # Check for path collisions before any writes
    if os.path.exists(bin_filename):
        raise FileExistsError(f"Conflicting Path: '{bin_filename}' already exists")
    if dec_filename and os.path.exists(dec_filename):
        raise FileExistsError(f"Conflicting Path: '{dec_filename}' already exists")

    # Write pre-lock raw data as debug .dec if requested
    if debug_mode:
        with open(dec_filename, "wb") as fout:
            fout.write(raw_data)

    # Build and lock the encrypted .bin dump
    dump = AmiiboDump(master_keys, raw_data, is_locked=False)
    dump.lock()

    with open(bin_filename, "wb") as fout:
        fout.write(dump.data)

    return bin_filename


def sanitize_filename(name: str) -> str:
    # Sanitize a string for safe filename use, preserving spaces and common punctuation.
    sanitized = re.sub(r"[^\w\-_ \[\]\(\)'&+\.]", "_", name)
    return sanitized.strip("_ .")


# Batch CSV/TXT Processing

def process_csv(csv_path: str, *,
                debug_mode: bool, master_keys: AmiiboMasterKey) -> None:
    # Generate amiibo files from a CSV/TXT list with 'id' and 'name' columns.
    if not os.path.exists(csv_path):
        abort(f"[!] Error: Input list file '{csv_path}' not found.")

    with open(csv_path, mode="r", encoding="utf-8-sig") as csvfile:
        reader = csv.DictReader(csvfile)

        if not reader.fieldnames \
                or "id" not in [h.lower() for h in reader.fieldnames] \
                or "name" not in [h.lower() for h in reader.fieldnames]:
            abort("[!] Error: Input file must contain 'id' and 'name' header columns.")

        for row in reader:
            row_lower = {k.lower(): v for k, v in row.items()}
            raw_id = row_lower.get("id", "").strip()
            raw_name = row_lower.get("name", "").strip()

            if not raw_id or not raw_name:
                continue

            safe_name = sanitize_filename(raw_name)
            target_bin_display = f"{safe_name}.bin"

            try:
                result = build_amiibo_buffer(raw_id)
                bin_name = process_and_save(result.raw_data, f"{safe_name}.bin",
                                            debug_mode=debug_mode, master_keys=master_keys)
                print(f"📄  {bin_name}")
                if result.is_wristband:
                    print("  ℹ️  Notice: Wristband form detected. Generated tag uses NTAG215 format, not NT3H2111.")
                print(f"  ✅  UID: {result.uid_str} | ID: {result.id_str} | Var: {result.var_str}\n")
            except Exception as e:
                print(f"📄  {target_bin_display}")
                print(f"  ❌  Failed: {e}\n")


# CLI ID Processing

def process_cli_ids(ids: list, *,
                    outputs: list, count: int, debug_mode: bool, master_keys: AmiiboMasterKey) -> None:
    # Generate amiibo files from one or more ID strings provided via CLI, supporting paired outputs and multi-counts.
    for idx, raw_id in enumerate(ids):
        # Determine base root name based on provided outputs list or fallback indexing
        if outputs and idx < len(outputs):
            base_target = outputs[idx]
        else:
            base_target = f"amiibo_{idx + 1}" if len(ids) > 1 else (outputs[0] if outputs else "amiibo_output.bin")

        base_root, _ = os.path.splitext(base_target)
        if not base_root:
            base_root = "amiibo_output"

        for c in range(count):
            try:
                result = build_amiibo_buffer(raw_id)
                uid_clean_str = result.uid_str.replace(" ", "")

                # Append UID to filename if count > 1 or multiple inputs/outputs are used
                if count > 1 or len(ids) > 1 or outputs:
                    target_filename = f"{base_root}_{uid_clean_str}.bin"
                else:
                    target_filename = f"{base_root}.bin"

                bin_name = process_and_save(result.raw_data, target_filename,
                                            debug_mode=debug_mode, master_keys=master_keys)
                print(f"📄  {bin_name}")
                if result.is_wristband:
                    print("  ℹ️  Notice: Wristband form detected. Generated tag uses NTAG215 format, not NT3H2111.")
                print(f"  ✅  UID: {result.uid_str} | ID: {result.id_str} | Var: {result.var_str}\n")
            except Exception as e:
                print(f"📄  {base_root}_*.bin")
                print(f"  ❌  Failed: {e}\n")


# CLI

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Amiibo v2 NTAG215 binaries from IDs or CSV/TXT, completely from scratch."
    )
    parser.add_argument("input_file", nargs="?", default=None, help="Optional drag-and-drop CSV or TXT file positional argument")
    parser.add_argument("-i", "--id", nargs="+", default=None, help="Amiibo ID string(s): 16 hex chars (ID) or 24 hex chars (ID + Page 23)")
    parser.add_argument("-l", "--list", default=None, help="Path to a CSV or TXT file containing 'id,name' columns for batch generation")
    parser.add_argument("-o", "--output", nargs="+", default=None, help="Output filename(s) for generation (can pair multiple outputs with multiple IDs)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of multi-UID variants to generate for the given ID(s)")
    parser.add_argument("-d", "--debug", action="store_true", help="Export pre-lock decrypted (.dec) layout alongside signed .bin file")
    args = parser.parse_args()

    # Auto-detect CSV or TXT if neither -i nor -l were explicitly provided
    if not args.id and not args.list:
        if args.input_file:
            if not (args.input_file.lower().endswith(".csv") or args.input_file.lower().endswith(".txt")):
                parser.error(f"Unrecognized argument or non-CSV/TXT file: '{args.input_file}'")
            args.list = args.input_file
        else:
            files = sorted(glob.glob("*.csv"))
            file_type = "CSV"
            if not files:
                files = sorted(glob.glob("*.txt"))
                file_type = "TXT"

            if len(files) == 1:
                args.list = files[0]
                print(f"[*] Auto-detected single {file_type} file: {args.list}")
            elif len(files) > 1:
                abort(
                    f"[!] Error: Multiple {file_type} files found in current directory "
                    f"({', '.join(files)}).\n"
                    f"    Please specify which one to process explicitly using -l or drag-and-drop."
                )
            else:
                parser.print_help()
                sys.exit(1)

    master_keys = load_master_keys()

    if args.list:
        process_csv(args.list, debug_mode=args.debug, master_keys=master_keys)
    elif args.id:
        outputs = args.output if args.output else []
        process_cli_ids(args.id, outputs=outputs, count=args.count, debug_mode=args.debug, master_keys=master_keys)


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
