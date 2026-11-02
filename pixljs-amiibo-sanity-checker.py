#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pixljs checker - Sanity check amiibo folder structures for pixl.js device compatibility.

import argparse
import os
import sys
from typing import List, Tuple

print("👾  Pixljs amiibo directory sanity checker 1.8 by CheatFreak  👾\n"
      "----------------------------------------------------------------\n"
      "Sanity check amiibo folder structures for pixl.js device compatibility.\n"
      "Tries to check bins in the current folder or local mcas-tracker repo if ran with no commands.\n"
      "Run with -h to for helpful information on all functions.\n")

# User-Editable Defaults

DEFAULT_ADD_LEN = 5  # Extra path length for "_all/" folder (adjust as needed)
DEFAULT_DEVICE_LIMIT = 2 * 1024 * 1024  # 2 MiB default (Flashiibo Pro Gen3 is 16MB)

# Amiibo Data

VALID_AMIIBO_SIZES = {532, 540, 572, 2048, 64}  # Known valid amiibo file sizes


# Helpers

def format_size(bytes_value: int) -> str:
    # Convert bytes into human-readable KiB or MiB using binary units.
    if bytes_value >= 1024 ** 2:
        return f"{bytes_value / (1024 ** 2):.2f} MiB"
    if bytes_value >= 1024:
        return f"{bytes_value / 1024:.2f} KiB"
    return f"{bytes_value} bytes"


def has_amiibo_files(base: str, script_name: str) -> bool:
    # Check if any amiibo-sized files exist under the base directory.
    for folder, _, files in os.walk(base):
        for f in files:
            if f == script_name:
                continue
            size = os.path.getsize(os.path.join(folder, f))
            if size in VALID_AMIIBO_SIZES:
                return True
    return False


# CLI

def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Check sanity of a folder of amiibo files for pixl.js based devices."
    )
    parser.add_argument("-a", "--add", type=int, default=DEFAULT_ADD_LEN, help=f"Additional length to add to each path. Default is {DEFAULT_ADD_LEN}.")
    parser.add_argument("-l", "--limit", type=int, default=DEFAULT_DEVICE_LIMIT, help=f"Device size limit in bytes. Default is {DEFAULT_DEVICE_LIMIT} (2 MiB).")
    parser.add_argument("-p", "--no-pause", action="store_true", help="Do not pause for 'Enter' key at the end of execution.")
    args = parser.parse_args()

    device_limit = args.limit
    base = os.getcwd()
    script_name = os.path.basename(__file__)

    # Fallback to ../pixljs/ if no amiibo files found
    if not has_amiibo_files(base, script_name):
        fallback = os.path.abspath(os.path.join(base, "..", "pixljs"))
        if os.path.isdir(fallback):
            print(f"ℹ️  No amiibo files found in current directory, switching to:\n    📁  {fallback}\n")
            base = fallback
        else:
            print("❌  No amiibo files found and fallback '../pixljs/' does not exist.")
            print("Exiting.")
            return args.no_pause

    # Accumulate scan results
    violations: List[Tuple[str, int]] = []
    all_paths: List[Tuple[str, int]] = []
    bad_extensions: List[str] = []
    bad_sizes: List[Tuple[str, int]] = []
    innocuous_files: List[Tuple[str, int]] = []
    total_valid_size = 0
    valid_file_count = 0

    for folder, _, files in os.walk(base):
        for f in files:
            if f == script_name:
                continue

            full_path = os.path.join(folder, f)
            rel_path = os.path.relpath(full_path, base)

            # Calculate effective path length (root + relative + folder overhead)
            total_len = 3 + len(rel_path) + args.add  # Root: e.g. "E:/" = 3 chars
            all_paths.append((rel_path, total_len))

            if total_len > 63:  # pixl.js max path length
                violations.append((rel_path, total_len))

            _, ext = os.path.splitext(f)
            ext = ext.lower()

            if ext in (".bin", ".nfc"):
                bad_extensions.append(rel_path)

            size = os.path.getsize(full_path)

            if size in (540, 572):  # Untrimmed NTAG215 sizes
                bad_sizes.append((rel_path, size))

            if size not in VALID_AMIIBO_SIZES:
                innocuous_files.append((rel_path, size))
            else:
                total_valid_size += size
                valid_file_count += 1

    # Report Results

    if violations:
        print("❌  These file paths will exceed the 63-character limit:")
        for path, length in violations:
            print(f"  📄  {path}   (length {length})")
    else:
        print("✅  All file paths will fit within the 63-character limit.")

    longest = sorted(all_paths, key=lambda x: x[1], reverse=True)[:10]
    print("\nℹ️  Top 10 longest paths:")
    for path, length in longest:
        print(f"  📄  {path}   (length {length})")

    if bad_extensions:
        print("\n❓  Files that appear to have unneeded extensions:")
        for path in bad_extensions:
            print(f"  📄  {path}")
    else:
        print("\n✅  All files appear to be properly free of unneeded extensions.")

    if bad_sizes:
        print("\n❓  Files that appear to be untrimmed NTAG215s:")
        for path, size in bad_sizes:
            print(f"  📄  {path}  ({size} bytes)")
    else:
        print("\n✅  No untrimmed NTAG215s were found.")

    if innocuous_files:
        print("\n❌  Non-amiibo files found:")
        for path, size in innocuous_files:
            print(f"  📄  {path}  ({size} bytes)")
    else:
        print("\n✅  No non-amiibo files were found.")

    if not violations:
        human_size = format_size(total_valid_size)
        print(f"\n📦  Total size of all valid amiibo files: {human_size}  ({valid_file_count} files)")
        if total_valid_size > device_limit:
            print(f"❌  Total size exceeds the device limit of {format_size(device_limit)}!")

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
