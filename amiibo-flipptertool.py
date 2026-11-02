#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibo-flipper-tool - Convert Amiibo dumps between binary and Flipper Zero NFC formats.

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

print("👾  amiibo flipper tool v2.11 by CheatFreak  👾\n"
      "---------------------------------------------\n"
      "A simple tool for converting back and forth between nfc format with amiibo bin files.\n"
      "Works going from nfc to bin for all amiibo, supports going back to NFC for NTAG215 and Power-Up Bands.\n"
      "Tries to convert files found in the folder if ran with no commands.\n"
      "Run with -h to for helpful information on all functions.")


# Exit & Error Helpers

def abort(msg: str) -> None:
    # Print error message and exit cleanly.
    print(msg)
    sys.exit(1)


# UID & Password Calculation Helpers

def verify_uid(data: bytes) -> bool:
    # Verify standard 7-byte NTAG UID checksums (BCC0 and BCC1).
    if len(data) < 9:
        return False
    uid0, uid1, uid2, bcc0 = data[0], data[1], data[2], data[3]
    uid3, uid4, uid5, uid6 = data[4], data[5], data[6], data[7]
    bcc1 = data[8]  # Page 2 byte 0

    expected_bcc0 = 0x88 ^ uid0 ^ uid1 ^ uid2
    expected_bcc1 = uid3 ^ uid4 ^ uid5 ^ uid6

    return (bcc0 == expected_bcc0) and (bcc1 == expected_bcc1)


def calculate_password(uid_bytes: bytes) -> str:
    # Calculate the NTAG password using UID XOR masks (0xAA / 0x55).[cite: 2]
    if len(uid_bytes) != 7:
        return "00 00 00 00"
    
    pwd = [
        uid_bytes[1] ^ uid_bytes[3] ^ 0xAA,
        uid_bytes[2] ^ uid_bytes[4] ^ 0x55,
        uid_bytes[3] ^ uid_bytes[5] ^ 0xAA,
        uid_bytes[4] ^ uid_bytes[6] ^ 0x55
    ]
    return " ".join(f"{b:02X}" for b in pwd)


# Binary -> NFC Conversion 

def bin_to_nfc(bin_path: Path, nfc_path: Path) -> bool:
    # Convert a raw NTAG215 or Power-Up Band binary dump to Flipper Zero .nfc format with LF line endings.
    try:
        with open(bin_path, "rb") as f:
            data = f.read()

        file_size = len(data)

        # Check if it's a Power-Up Band (944/1024 bytes) OR a truncated wristband dump (e.g. 540 bytes)
        is_power_up_band = (
            file_size in (944, 1024)
            or (file_size in (532, 540, 572) and not verify_uid(data) and len(data) >= 88 and data[0x57] == 0x03)
        )

        if is_power_up_band:
            if file_size not in (944, 1024):
                print("  ❓  This input looks like a truncated Power-Up Band. Padding to proper size.")

            # Ensure we have data up to the full 236 pages (944 bytes)[cite: 3]
            target_size = 236 * 4
            if len(data) >= target_size:
                data = data[:target_size]
            else:
                data = data + b"\x00" * (target_size - len(data))

            pages = [data[i:i + 4] for i in range(0, len(data), 4)]
            
            # NT3H2111 stores the 7-byte UID contiguously at the very beginning
            uid_bytes = data[:7]
            uid_str = " ".join(f"{b:02X}" for b in uid_bytes)
            pwd_str = calculate_password(uid_bytes)

            nfc_lines = [
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
                "NTAG/Ultralight type: NTAG I2C Plus 1K",
                "Signature: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "Mifare version: 00 04 04 05 02 02 13 03",
                "Counter 0: 0",
                "Tearing 0: 00",
                "Counter 1: 0",
                "Tearing 1: 00",
                "Counter 2: 0",
                "Tearing 2: 00",
                "Pages total: 236",
                "Pages read: 236",
            ]

            for idx, page in enumerate(pages):
                if idx == 229:
                    nfc_lines.append(f"Page 229: {pwd_str}")
                elif idx == 230:
                    nfc_lines.append("Page 230: 80 80 00 00")
                else:
                    page_hex = " ".join(f"{b:02X}" for b in page)
                    nfc_lines.append(f"Page {idx}: {page_hex}")

            # Append the required trailing authentication footer
            nfc_lines.append("Failed authentication attempts: 0")

            # Write out with strict Unix line endings (\n)
            with open(nfc_path, "w", encoding="utf-8", newline="\n") as out_f:
                out_f.write("\n".join(nfc_lines) + "\n")

            return True

        # Standard NTAG215 Handling
        if file_size == 532:
            data = data + b"\x00" * 8  # Pad missing 8 bytes
        elif file_size == 572:
            data = data[:540]  # Strip trailing 32 bytes
        elif file_size == 540:
            pass
        else:
            return False

        pages = [data[i:i + 4] for i in range(0, len(data), 4)]
        if len(pages) < 2:
            return False

        # NTAG215 splits UID across pages with BCC bytes embedded
        uid_bytes = pages[0][:3] + pages[1]
        uid_str = " ".join(f"{b:02X}" for b in uid_bytes)
        pwd_str = calculate_password(uid_bytes)
        
        nfc_lines = [
            "Filetype: Flipper NFC device",
            "Version: 2",
            "# Nfc device type can be UID, Mifare Ultralight, Bank card",
            "Device type: NTAG215",
            "# UID, ATQA and SAK are common for all formats",
            f"UID: {uid_str}",
            "ATQA: 44 00",
            "SAK: 00",
            "# Mifare Ultralight specific data",
            "Signature: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "Mifare version: 00 04 04 02 01 00 11 03",
            "Counter 0: 0",
            "Tearing 0: 00",
            "Counter 1: 0",
            "Tearing 1: 00",
            "Counter 2: 0",
            "Tearing 2: 00",
            f"Pages total: {len(pages)}",
        ]

        for idx, page in enumerate(pages):
            if idx == 133:
                nfc_lines.append(f"Page 133: {pwd_str}")
            elif idx == 134:
                nfc_lines.append("Page 134: 80 80 00 00")
            else:
                page_hex = " ".join(f"{b:02X}" for b in page)
                nfc_lines.append(f"Page {idx}: {page_hex}")

        # Write out with strict Unix line endings (\n)
        with open(nfc_path, "w", encoding="utf-8", newline="\n") as out_f:
            out_f.write("\n".join(nfc_lines) + "\n")

        return True

    except OSError as e:
        print(f"  ❌  Error: {e}\n")
        return False


# NFC -> Binary Conversion 

def nfc_to_bin(nfc_path: Path, out_path: Path) -> Tuple[bool, bool]:
    # Convert a Flipper Zero .nfc file to raw binary format. Returns (success, uid_valid).
    pages: Dict[int, bytes] = {}
    max_page = -1
    page_pattern = re.compile(r"^Page\s+(\d+):\s+(.*)", re.IGNORECASE)

    try:
        with open(nfc_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = page_pattern.match(line.strip())
                if not match:
                    continue

                page_num = int(match.group(1))
                data_str = match.group(2).strip()
                tokens = data_str.split()

                byte_list = []
                for token in tokens:
                    if token == "??" or len(token) != 2:
                        byte_list.append(b"\x00")
                    else:
                        try:
                            byte_list.append(bytes.fromhex(token))
                        except ValueError:
                            byte_list.append(b"\x00")

                pages[page_num] = b"".join(byte_list)
                max_page = max(max_page, page_num)

        if max_page == -1:
            print("  ❌  Error: No valid 'Page' entries found.\n")
            return False, False

        sample_size = len(next(iter(pages.values()))) if pages else 4
        if sample_size == 0:
            sample_size = 4

        full_data = bytearray()
        for i in range(max_page + 1):
            full_data.extend(pages.get(i, b"\x00" * sample_size))

        # Handle binary structuring based on tag layout bounds
        if len(full_data) == 540 or (max_page < 200 and len(full_data) >= 540):
            uid_bytes = bytes([full_data[0], full_data[1], full_data[2], full_data[4], full_data[5], full_data[6], full_data[7]])
            pwd_bytes = bytes.fromhex(calculate_password(uid_bytes))
            full_data[133 * 4 : 133 * 4 + 4] = pwd_bytes
            full_data[134 * 4 : 134 * 4 + 4] = bytes([0x80, 0x80, 0x00, 0x00])
            write_data = full_data[:540]
        else:
            # Power-Up Band / NT3H2111 sizing (contiguous 7-byte UID starting at offset 0, password at page 229)
            if len(full_data) >= 920:
                uid_bytes = bytes(full_data[:7])
                pwd_bytes = bytes.fromhex(calculate_password(uid_bytes))
                full_data[229 * 4 : 229 * 4 + 4] = pwd_bytes
                full_data[230 * 4 : 230 * 4 + 4] = bytes([0x80, 0x80, 0x00, 0x00])
            write_data = full_data

        with open(out_path, "wb") as out_f:
            out_f.write(write_data)

        uid_valid = verify_uid(bytes(full_data))
        return True, uid_valid

    except OSError as e:
        print(f"  ❌  Error: {e}\n")
        return False, False


# File Size Validation 

def categorize_bin_size(file_size: int) -> Optional[str]:
    # Categorize binary file size.
    if file_size in (532, 540, 572):
        return "valid"
    if file_size in (2048, 1968):
        return "v3"
    if file_size in (944, 1024) or file_size >= 540:
        return "snw"
    return None


# Single-File Processing 

def process_bin_to_nfc(bin_path: Path) -> None:
    # Validate and process a single binary file to NFC.
    print(f"📄  {bin_path.name}")

    try:
        file_size = bin_path.stat().st_size
    except OSError as e:
        print(f"  ❌  Error: {e}\n")
        return

    category = categorize_bin_size(file_size)

    if category == "v3":
        print("  ❌  Failed: Amiibo V3 (NT3H2211) are not supported.\n")
        return
    if category is None:
        return

    nfc_path = bin_path.with_suffix(".nfc")

    if nfc_path.exists():
        print("  ❌  Failed: Conflicting Path\n")
        return

    if bin_to_nfc(bin_path, nfc_path):
        print(f"  ✅  Created {nfc_path.name}!\n")
    else:
        print("  ❌  Failed: Invalid dump data\n")


def process_nfc_to_bin(nfc_path: Path, *, raw_output: bool = False) -> None:
    # Process a single NFC file to binary.
    print(f"📄  {nfc_path.name}")

    ext = ".raw" if raw_output else ".bin"
    out_path = nfc_path.with_suffix(ext)

    if out_path.exists():
        print("  ❌  Failed: Conflicting Path\n")
        return

    success, uid_valid = nfc_to_bin(nfc_path, out_path)
    if success:
        if not uid_valid:
            print("  ❓  UID Check failed on this NFC dump.")
        print(f"  ✅  Created {out_path.name}!\n")


# Directory Scanning 

def scan_directory(target_dir: Path, *, raw_output: bool = False) -> None:
    # Scan directory and batch convert files.
    bin_exts = ("*.bin", "*.BIN", "*.raw", "*.RAW")
    bin_files = sorted({f for pattern in bin_exts for f in target_dir.glob(pattern)})
    nfc_files = sorted({f for pattern in ("*.nfc", "*.NFC") for f in target_dir.glob(pattern)})

    if bin_files and nfc_files:
        abort(f"[!] Error: Found both binary (.bin/.raw) and Flipper (.nfc) files in '{target_dir.resolve()}'. I don't know what you want me to do.")

    valid_bins = [f for f in bin_files if categorize_bin_size(f.stat().st_size) in ("valid", "snw")]

    if not bin_files and not nfc_files:
        print(f"[-] No .bin, .raw, or .nfc files found in '{target_dir.resolve()}'.")
        return

    if valid_bins:
        print(f"Found {len(valid_bins)} convertible .bin/.raw file(s). Converting to NFC...\n")
        for f in bin_files:
            process_bin_to_nfc(f)

    if nfc_files:
        print(f"Found {len(nfc_files)} .nfc file(s). Converting to binary...\n")
        for f in nfc_files:
            process_nfc_to_bin(f, raw_output=raw_output)


# Input Resolution 

def resolve_inputs(args) -> List[Path]:
    # Resolve input paths from arguments.
    seen = set()
    result = []
    for inputs in (args.positional_inputs or [], args.input or []):
        for p in inputs:
            if p not in seen:
                seen.add(p)
                result.append(Path(p))
    return result


# CLI 

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Amiibo and Power-Up Band dumps between binary and Flipper Zero NFC formats."
    )
    parser.add_argument("positional_inputs", nargs="*", help="Input file(s) - direction auto-detected from extension")
    parser.add_argument("-i", "--input", nargs="+", help="Input file(s)")
    parser.add_argument("-d", "--directory", default=None, help="Directory to scan for convertible files (default: current directory)")
    parser.add_argument("-r", "--raw", action="store_true", help="Use .raw extension instead of .bin (NFC -> binary only)")
    args = parser.parse_args()

    explicit_inputs = resolve_inputs(args)
    target_dir = Path(args.directory) if args.directory else None

    if not explicit_inputs and not target_dir:
        target_dir = Path(".")

    if target_dir:
        if not target_dir.exists() or not target_dir.is_dir():
            print(f"[-] Error: Directory '{target_dir}' does not exist or is not a directory.")
            sys.exit(1)
        scan_directory(target_dir, raw_output=args.raw)
        return

    for filepath in explicit_inputs:
        if not filepath.exists():
            print(f"📄  {filepath.name}")
            print("  ❌  Error: File not found.\n")
            continue

        ext = filepath.suffix.lower()
        if ext in (".bin", ".raw"):
            process_bin_to_nfc(filepath)
        elif ext == ".nfc":
            process_nfc_to_bin(filepath, raw_output=args.raw)
        else:
            print(f"📄  {filepath.name}")
            print("  ❌  Error: Unrecognized file extension. Expected .bin, .raw, or .nfc\n")

    print("Finished!")


if __name__ == "__main__":
    main()
    if len(sys.argv) == 1:
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