#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# gen amiibo csv - Scan directory for .bin amiibo files and export IDs and names to CSV.

import argparse
import csv
import glob
import os
import sys

print("👾  gen amiibo csv v1.6.4 by CheatFreak  👾\n"
      "-----------------------------------------\n"
      "Scan directory for .bin amiibo files and export IDs and names to CSV.\n"
      "Run with -h to for helpful information on all functions.")


# Constants

DEFAULT_OUTPUT = "extracted_amiibos.csv"
VALID_SIZES = {532, 540, 572}


# Exit & Error Helpers

def abort(msg: str, no_pause: bool = False) -> None:
    # Print error message and exit.
    print(msg)
    if not no_pause:
        input("\nPress Enter to exit...")
    sys.exit(1)


# Validation Helpers

def validate_ntag215_uid(raw_data: bytes) -> bool:
    # Validate NTAG215 7-byte UID and its BCC check bytes (BCC0 at 0x03, BCC1 at 0x08).
    if len(raw_data) < 9:
        return False

    uid = raw_data[0:3] + raw_data[4:8]
    bcc0 = raw_data[3]
    bcc1 = raw_data[8]

    expected_bcc0 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2]
    expected_bcc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]

    return bcc0 == expected_bcc0 and bcc1 == expected_bcc1


# Core Processing Functions

def process_directory(output_path: str, full_mode: bool, no_pause: bool) -> None:
    # Scan current directory for valid NTAG215 .bin files and export their IDs.
    bin_files = sorted([f for f in glob.glob("*.bin") if f.lower() != "key_retail.bin"])

    if not bin_files:
        abort("\n❌  Error: No .bin files found in the current directory.", no_pause)

    mode_desc = "full ID + Page 23 variant (24-char)" if full_mode else "standard ID (16-char)"
    print(f"📦  Scanning {len(bin_files)} .bin file(s) in {mode_desc} mode...\n")

    success_count = 0
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name"])

        for filename in bin_files:
            name_without_ext = os.path.splitext(filename)[0]
            try:
                with open(filename, "rb") as bf:
                    raw_data = bf.read()

                # 1. Validate file size (strict NTAG215 sizes only)
                if len(raw_data) not in VALID_SIZES:
                    print(f"📄  {filename}\n   ❌  Error: Invalid file size ({len(raw_data)}B). Expected one of {VALID_SIZES}.\n")
                    continue

                # 2. Validate NTAG215 UID & BCC structure
                if not validate_ntag215_uid(raw_data):
                    print(f"📄  {filename}\n   ❌  Error: Failed NTAG215 UID BCC checksum validation.\n")
                    continue

                # Amiibo ID lives at Pages 21-22 (Bytes 84 to 92 -> 8 bytes)
                # Page 23 variant data lives at Bytes 92 to 96 -> 4 bytes
                if len(raw_data) >= 96:
                    id_bytes = raw_data[84:92]
                    var_bytes = raw_data[92:96]

                    if full_mode:
                        export_id = (id_bytes + var_bytes).hex().upper()
                        print(f"📄  {filename} -> ID: {id_bytes.hex().upper()} | Var: {var_bytes.hex().upper()}")
                    else:
                        export_id = id_bytes.hex().upper()
                        print(f"📄  {filename} -> ID: {export_id}")

                    writer.writerow([export_id, name_without_ext])
                    success_count += 1
                else:
                    print(f"📄  {filename}\n   ❌  Error: File too short (< 96 bytes).\n")
            except Exception as e:
                print(f"📄  {filename}\n   ❌  Error reading file: {e}\n")

    print(f"\n   ✅  Successfully exported {success_count} entries to '{output_path}'!\n")


# CLI

def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Scan directory for .bin amiibo files and export IDs and names to CSV."
    )
    parser.add_argument("-f", "--full", action="store_true", help="Include 4-byte Page 23 variant data for a 24-char full payload")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"Output CSV filename (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-p", "--no-pause", action="store_true", help="Skip exit pause")
    args = parser.parse_args()

    try:
        process_directory(args.output, args.full, args.no_pause)
    except Exception as e:
        abort(f"\n❌  Error: {e}", args.no_pause)

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
