#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibo trimpad - Amiibo binary size trimming, padding, and extension management utility.

import argparse
import gc
import os
from pathlib import Path
import sys

print("👾  amiibo trimpad v1.7.5 by CheatFreak  👾\n"
      "-----------------------------------------\n"
      "Amiibo binary size trimming, padding, and extension management utility.\n"
      "Run with -h to for helpful information on all functions.")


# Constants

VALID_SIZES = {532, 540, 572}


# Exit & Error Helpers

def abort(msg: str, no_pause: bool = False) -> None:
    # Print error message and exit.
    print(msg)
    if not no_pause:
        input("\nPress Enter to exit...")
    sys.exit(1)


# Validation & Crypto Helpers

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


def generate_pwd(raw_data: bytes) -> bytes:
    # Generate NTAG215 password bytes from 7-byte UID:
    # uid = [uid0, uid1, uid2, uid3, uid4, uid5, uid6]
    uid = raw_data[0:3] + raw_data[4:8]
    
    pwd0 = 0xAA ^ uid[1] ^ uid[3]
    pwd1 = 0x55 ^ uid[2] ^ uid[4]
    pwd2 = 0xAA ^ uid[3] ^ uid[5]
    pwd3 = 0x55 ^ uid[4] ^ uid[6]
    
    return bytes([pwd0, pwd1, pwd2, pwd3])


# Extension Helpers

def needs_extension_restore(file_path: Path) -> bool:
    # Returns True for files we should treat as extensionless
    return not file_path.suffix or len(file_path.suffix) != 4  # .bin is 4 (. + 3)


def safe_restore_extension(file_path: Path) -> Path:
    # Special handler for complex filenames with dots (e.g., "M.Bison" -> "M.Bison.bin")
    new_name = f"{file_path.name}.bin"
    return file_path.with_name(new_name)


# Target Detection & Extension Restoration

def detect_target_size(root_dir: str) -> Optional[int]:
    found_eligible = False
    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = Path(root) / file
            if needs_extension_restore(file_path) or file_path.suffix.lower() == '.bin':
                try:
                    with open(file_path, 'rb') as f:
                        raw_data = f.read()
                        if not validate_ntag215_uid(raw_data):
                            continue
                        file_size = len(raw_data)
                        if file_size in (540, 572):
                            print(f"   ℹ️  Auto-detected {file_size}B file: {file_path.name} (targeting 532B)")
                            found_eligible = True
                except Exception as e:
                    print(f"   ⚠️  Error reading {file_path.name}: {e}")

    if not found_eligible:
        print("   ❌  Error: No eligible files found to trim (looking for 540B or 572B files).")
        return None

    return 532


def restore_extensions(root_dir: str) -> bool:
    processed = 0
    print(f"🔧  Restoring missing .bin extensions in: {root_dir}\n")
    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = Path(root) / file
            if needs_extension_restore(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        raw_data = f.read()
                        if len(raw_data) not in (532, 540) or not validate_ntag215_uid(raw_data):
                            continue

                    new_path = safe_restore_extension(file_path)
                    if new_path.exists():
                        print(f"   ⚠️  Exists: {new_path.name} - Skipping")
                        continue

                    gc.collect()
                    file_path.replace(new_path)
                    print(f"   ✅  Fixed extension: {file_path.name} → {new_path.name}")
                    processed += 1
                except Exception as e:
                    print(f"   ❌  Error fixing {file_path.name}: {e}")
    return processed > 0


# File Processing

def process_file(file_path: Path, target_size: int, expand_flag: bool, strip_extension: bool) -> bool:
    # All file operations with proper handle management
    print(f"📄  {file_path.name}")
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            orig_size = len(data)
            if orig_size not in VALID_SIZES:
                print(f"   ❌  Error: Invalid file size ({orig_size}B). Skipping.\n")
                return False

            if not validate_ntag215_uid(data):
                print(f"   ❌  Error: Failed NTAG215 UID BCC checksum validation. Skipping.\n")
                return False

        needs_rename = strip_extension and file_path.suffix.lower() == '.bin'
        new_path = file_path.with_suffix('') if needs_rename else None

        # Trim if needed
        if orig_size != target_size:
            with open(file_path, 'rb+') as f:
                f.truncate(target_size)
            print(f"   ✂️  Trimmed to {target_size}B")

        # Expansion / Padding with UID-derived PWD and standard PACK
        if expand_flag and orig_size == 532:
            pwd_bytes = generate_pwd(data)
            pack_bytes = b'\x80\x80\x00\x00'  # Standard PACK + RFUI
            trailer = pwd_bytes + pack_bytes

            with open(file_path, 'ab') as f:
                f.write(trailer)
            print(f"   ➕  Expanded to 540B (with UID-derived PWD: {pwd_bytes.hex().upper()})")

        # Rename if needed
        if needs_rename:
            gc.collect()
            if not new_path.exists():
                file_path.replace(new_path)
                print(f"   🗑️  Removed .bin extension")
            else:
                print(f"   ⚠️  Exists: {new_path.name} - Skipping rename")

        print(f"   ✅  Successfully processed {file_path.name}\n")
        return True

    except Exception as e:
        print(f"   ❌  Failed processing {file_path.name}: {str(e)}\n")
        return False


# CLI

def main() -> bool:
    parser = argparse.ArgumentParser(description="Amiibo binary size trimming, padding, and extension management utility.")
    parser.add_argument("-s", "--size", type=int, choices=[532, 540], help="Target size (532 or 540 bytes)")
    parser.add_argument("-r", "--remove-extension", action="store_true", help="Remove .bin extensions")
    parser.add_argument("-e", "--expand", action="store_true", help="Expand 532B files to 540B")
    parser.add_argument("-a", "--add-extension", action="store_true", help="Add .bin to extensionless files")
    parser.add_argument("-p", "--no-pause", action="store_true", help="Skip exit pause")
    parser.add_argument("path", nargs="?", default=".", help="Directory to process")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        abort(f"❌  Error: Target directory '{args.path}' not found.", args.no_pause)

    if args.add_extension:
        restore_extensions(args.path)
    else:
        target_size = args.size or detect_target_size(args.path)
        if target_size:
            processed = 0
            file_list = []
            for root, _, files in os.walk(args.path):
                for file in files:
                    file_path = Path(root) / file
                    if file.lower().endswith('.bin') or needs_extension_restore(file_path):
                        if file_path.name.lower() != "key_retail.bin":
                            file_list.append(file_path)

            print(f"📦  Processing {len(file_list)} file(s) (target size: {target_size}B)...\n")
            for file_path in file_list:
                if process_file(file_path, target_size, args.expand, args.remove_extension):
                    processed += 1
            print(f"   ✅  Finished processing {processed} file(s)!")
        else:
            abort("", args.no_pause)

    print("\nFinished!")
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
