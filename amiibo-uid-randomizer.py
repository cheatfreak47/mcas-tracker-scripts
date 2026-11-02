#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibo uid randomizer - Generate multiple Amiibo copies with randomized UIDs.

import argparse
import os
import random
import sys
from typing import List, Optional

print("👾  amiibo uid randomizer v1.6.2 by CheatFreak  👾\n"
      "------------------------------------------------\n"
      "A tool for casting dark magic to create randomized UID copies of an amiibo.\n"
      "Run with -h to for helpful information on all functions.")

try:
    from amiibo import AmiiboDump, AmiiboMasterKey
except ImportError:
    print("❌  Error: 'pyamiibo' is not installed.\n"
          "Install it using: pip install pyamiibo\n")
    sys.exit(1)


# User-Editable Defaults

DEFAULT_QUANTITY = 5  # Default number of randomized copies to generate per file


# Exit & Error Helpers

def abort(msg: str, no_pause: bool = False) -> None:
    # Print error message and exit.
    print(msg)
    if not no_pause:
        input("\nPress Enter to exit...")
    sys.exit(1)


# Master Key Loading

def load_master_keys(explicit_key_path: Optional[str] = None, no_pause: bool = False) -> AmiiboMasterKey:
    # Load master keys from key_retail.bin, checking default locations.
    candidates = (
        [explicit_key_path] if explicit_key_path
        else ["key_retail.bin", os.path.join("..", "keys", "key_retail.bin")]
    )

    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    return AmiiboMasterKey.from_combined_bin(f.read())
            except Exception as e:
                abort(f"❌  Error reading '{path}': {e}", no_pause)

    if explicit_key_path:
        abort(f"❌  Error: Specified key file '{explicit_key_path}' not found.", no_pause)
    abort("❌  Error: Master key file 'key_retail.bin' not found in current directory or '../keys/'.", no_pause)


# UID Generation

def generate_random_uid(source_uid6: int) -> str:
    # Generate a random 7-byte NTAG215 UID, preserving the source UID6 byte.
    # UID layout:
    #    Byte 0:   0x04 (NXP manufacturer - always fixed)
    #    Byte 3: Random unique bytes except for 0x88
    #    Bytes 1,2,4,5: Random unique bytes
    #    Byte 6:   Source UID6 (preserved to maintain amiibo type/batch)
    uid0 = 0x04
    uid1 = random.randint(0, 255)
    uid2 = random.randint(0, 255)
    uid3 = (v := random.randint(0, 254)) + (v >= 0x88) # Cannot be 0x88 to prevent cascade conflicts
    uid4 = random.randint(0, 255)
    uid5 = random.randint(0, 255)

    return f"{uid0:02X}{uid1:02X}{uid2:02X}{uid3:02X}{uid4:02X}{uid5:02X}{source_uid6:02X}"


# Source File Analysis

def extract_source_uid6(filepath: str, master_keys: AmiiboMasterKey) -> int:
    # Extract and return the UID6 (retail batch) byte from an amiibo dump.
    with open(filepath, "rb") as f:
        dump = AmiiboDump(master_keys, f.read(), is_locked=True)

    # pyamiibo's uid_hex returns space-delimited hex bytes (e.g. "04 XX XX XX XX XX YY")
    uid_parts = dump.uid_hex.split()
    return int(uid_parts[6], 16)


# File Processing

def process_file(filepath: str, master_keys: AmiiboMasterKey, *,
                 quantity: int, output_base: Optional[str] = None) -> None:
    # Generate randomized UID copies of a single amiibo file.
    print(f"📄  {filepath}")

    try:
        source_uid6 = extract_source_uid6(filepath, master_keys)

        generated = 0
        for i in range(quantity):
            new_uid = generate_random_uid(source_uid6)

            # Load fresh, decrypt, inject new UID, re-encrypt
            with open(filepath, "rb") as f:
                dump = AmiiboDump(master_keys, f.read(), is_locked=True)

            dump.unlock()
            dump.uid_hex = new_uid
            dump.lock()

            # Determine output filename base
            if output_base:
                base_name = os.path.splitext(output_base)[0]
            else:
                base_name = os.path.splitext(filepath)[0]

            out_file = f"{base_name}_{new_uid}.bin"

            with open(out_file, "wb") as f:
                f.write(dump.data)

            print(f"   ✅  [{i + 1}/{quantity}] UID: {new_uid} -> {os.path.basename(out_file)}")
            generated += 1

        print(f"   📦  Generated {generated} randomized cop{'ies' if generated != 1 else 'y'}\n")

    except Exception as e:
        print(f"   ❌  Error: {e}\n")


def resolve_inputs(args) -> List[str]:
    # Merge positional and -i inputs into a single list.
    inputs = list(args.positional_inputs or [])
    inputs.extend(args.input or [])
    return inputs


# CLI

def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Generate Amiibo copies with randomized UIDs."
    )
    parser.add_argument("positional_inputs", nargs="*", help="Input file(s) - supports drag-and-drop")
    parser.add_argument("-i", "--input", nargs="+", help="Input file(s)")
    parser.add_argument("-o", "--output", default=None, help="Output base name (single input file only)")
    parser.add_argument("-c", "--count", type=int, default=DEFAULT_QUANTITY, help=f"Number of randomized copies per file (default: {DEFAULT_QUANTITY})")
    parser.add_argument("-p", "--no-pause", action="store_true", help="Skip exit pause")
    parser.add_argument("-k", "--key", default=None, help="Path to key_retail.bin")
    args = parser.parse_args()

    all_inputs = resolve_inputs(args)

    if not all_inputs:
        parser.print_help()
        abort("\n❌  Error: No input files specified. This tool requires explicit input files to run.", args.no_pause)

    if args.count < 1:
        abort("❌  Error: Number of copies must be at least 1.", args.no_pause)

    if args.output and len(all_inputs) > 1:
        abort("❌  Error: The -o / --output option can only be used when processing a single input file.", args.no_pause)

    master_keys = load_master_keys(args.key, no_pause=args.no_pause)

    for filepath in all_inputs:
        if not os.path.exists(filepath):
            print(f"📄  {filepath}")
            print(f"   ❌  Error: Input file not found.\n")
            continue
        process_file(filepath, master_keys, quantity=args.count, output_base=args.output)

    print("Finished!")
    return args.no_pause


if __name__ == "__main__":
    no_pause = main()
    if not no_pause:
        input("\nPress Enter to exit...")

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
