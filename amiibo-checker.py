#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibo checker - Validates Amiibo dumps for health, corruption, and initialization status.

import argparse
import os
import sys
from typing import NamedTuple, Optional, Tuple

print("👾  amiibo checker v1.5.3 by CheatFreak  👾\n"
      "-------------------------------------------\n"
      "Checks if amiibo are invalid, if they have save data, non-zero write counts, or are non-standard sizes.\n"
      "Tries to check bins in the current folder or local mcas-tracker repo if ran with no commands.\n"
      "Run with -h to for helpful information on all functions.\n")

try:
    from amiibo import AmiiboDump, AmiiboMasterKey
except ImportError:
    print("Error: The 'pyamiibo' package is required but not installed.")
    print("Please install it via your terminal: pip install pyamiibo")
    sys.exit(1)


#  Validation Result

class ValidationResult(NamedTuple):
    # Structured result from amiibo validation.
    status: str       # SUCCESS, UNHEALTHY, FAILED_UID, FAILED_CORRUPT, SKIPPED
    message: str      # Human-readable status message
    write_count: int  # Write counter value
    initialized: str  # "Yes", "No ", or "Unknown"
    file_size: int    # Raw file size in bytes


#  Exit & Error Helpers

def abort(msg: str) -> None:
    # Print error message and exit.
    print(msg)
    sys.exit(1)


#  Master Key Loading

def load_master_keys() -> AmiiboMasterKey:
    # Load master keys from key_retail.bin, checking default locations.
    candidates = ["key_retail.bin", os.path.join("..", "keys", "key_retail.bin")]

    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    return AmiiboMasterKey.from_combined_bin(f.read())
            except Exception as e:
                abort(f"Error reading '{path}': {e}")

    abort("Error: Master key file 'key_retail.bin' not found in the current directory or in '../keys/'.")


#  Amiibo Validation

def validate_amiibo(bin_path: str, master_key: AmiiboMasterKey, *,
                    ignore_size: bool = False) -> ValidationResult:
    # Validate an Amiibo bin file's structure, signature, write count, and initialization status.
    try:
        with open(bin_path, "rb") as f:
            data = f.read()

        file_size = len(data)

        # Skip v3 amiibos (2048 bytes)
        if file_size == 2048:
            return ValidationResult("SKIPPED", "v3 amiibo (2048 bytes ignored)", 0, "No ", file_size)

        # Accept only standard dump sizes (532, 540, or 572 bytes)
        if file_size not in (532, 540, 572):
            return ValidationResult(
                "FAILED_CORRUPT",
                f"Invalid or corrupted file: Unsupported file size ({file_size} bytes)",
                0, "Unknown", file_size,
            )

        # Normalize container size for pyamiibo compatibility
        if file_size == 572:
            parse_data = data[:540]
        elif file_size == 532:
            parse_data = data + b"\x00" * (540 - file_size)
        else:
            parse_data = data

        # Load into pyamiibo dump handler; unlock triggers internal crypto validation
        dump = AmiiboDump(master_key, parse_data)
        dump.unlock()

        uid = dump.uid_hex
        write_count = int.from_bytes(dump.data[0x108:0x10A], "big")  # Write counter offset
        reg_flag = dump.data[0x14]  # Registration flag (00 = uninit, 10/20/30 = has data)
        initialized = "Yes" if reg_flag != 0 else "No "

        # Evaluate health criteria
        is_unhealthy = (write_count > 0 or reg_flag != 0)
        if not ignore_size and file_size != 540:
            is_unhealthy = True

        status = "UNHEALTHY" if is_unhealthy else "SUCCESS"
        return ValidationResult(status, f"UID: {uid}", write_count, initialized, file_size)

    except Exception as e:
        file_sz = len(data) if 'data' in locals() else 0
        err_str = str(e)
        # Distinguish UID failures from general corruption/crypto failures
        if "uid" in err_str.lower():
            return ValidationResult("FAILED_UID", f"Invalid or corrupted file: {err_str}", 0, "Unknown", file_sz)
        return ValidationResult("FAILED_CORRUPT", f"Invalid or corrupted file: {err_str}", 0, "Unknown", file_sz)


#  Output Formatting

def format_output(result: ValidationResult, ignore_size: bool) -> str:
    # Format validation result with emojis, cell-aligned padding, and warning markers.
    is_warn = result.status == "UNHEALTHY"
    is_fail_uid = result.status == "FAILED_UID"
    is_fail_corrupt = result.status == "FAILED_CORRUPT"
    is_skip = result.status == "SKIPPED"

    # Sub-line emoji selector
    if is_fail_uid:
        sub_emoji = "❌"
    elif is_fail_corrupt:
        sub_emoji = "❓"
    elif is_skip:
        sub_emoji = "⏭️"
    elif is_warn:
        sub_emoji = "❌"
    else:
        sub_emoji = "✅"

    if is_fail_uid or is_fail_corrupt or is_skip:
        return f"  {sub_emoji}  {result.message}"

    wc_str = f"{result.write_count:05d}"

    # Cell-aligned warning markers (emoji + space = 3 visual cells)
    wc_mark = "❌ " if is_warn and result.write_count > 0 else "   "
    init_mark = "❌ " if is_warn and result.initialized.strip() == "Yes" else "   "
    size_mark = "❌ " if is_warn and not ignore_size and result.file_size != 540 else "   "

    return (
        f"  {sub_emoji}  {result.message} | "
        f"Write Count: {wc_str}{wc_mark} | "
        f"Initialized: {result.initialized}{init_mark} | "
        f"Size: {result.file_size}B{size_mark}"
    )


#  Path Processing

def process_file(filepath: str, master_key: AmiiboMasterKey, *,
                 ignore_size: bool) -> None:
    # Process and display results for a single amiibo file.
    result = validate_amiibo(filepath, master_key, ignore_size=ignore_size)

    print(f"📄  {filepath}")
    print(format_output(result, ignore_size))
    print()


def process_directory(dir_path: str, master_key: AmiiboMasterKey, *,
                      ignore_size: bool, ignore_extension: bool,
                      verbose: bool) -> None:
    # Recursively scan and validate amiibo files in a directory.
    success_count = 0
    warn_count = 0
    fail_count = 0
    skip_count = 0
    total_count = 0

    for root, _, files in os.walk(dir_path):
        for file in files:
            if not (ignore_extension or file.lower().endswith(".bin")):
                continue

            total_count += 1
            full_path = os.path.join(root, file)
            result = validate_amiibo(full_path, master_key, ignore_size=ignore_size)

            # Determine if this result should be printed
            should_print = False
            if result.status == "SUCCESS":
                success_count += 1
                should_print = verbose
            elif result.status == "SKIPPED":
                skip_count += 1
                should_print = verbose
            elif result.status == "UNHEALTHY":
                warn_count += 1
                should_print = True
            else:
                fail_count += 1
                should_print = True

            if should_print:
                print(f"📄  {file}")
                print(format_output(result, ignore_size))
                print()

    print(
        f"Finished: {success_count} valid, {warn_count} flagged/unhealthy,"
        f" {fail_count} failed, {skip_count} skipped out of {total_count} total"
        " files.\n"
    )


def process_path(target_path: str, master_key: AmiiboMasterKey, *,
                 ignore_size: bool, ignore_extension: bool, verbose: bool) -> None:
    # Route target path to file or directory processor.
    if os.path.isfile(target_path):
        process_file(target_path, master_key, ignore_size=ignore_size)
    elif os.path.isdir(target_path):
        process_directory(target_path, master_key,
                          ignore_size=ignore_size,
                          ignore_extension=ignore_extension,
                          verbose=verbose)
    else:
        print(f"Error: Path '{target_path}' is not a valid file or directory.")


#  CLI

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate Amiibo bin files using retail master keys with health reporting."
    )
    parser.add_argument("path", nargs="?", default=None,
                        help="Path to a .bin file or directory (positional)")
    parser.add_argument("-d", "--directory", help="Directory path to scan")
    parser.add_argument("-x", "--ignore-extension", action="store_true",
                        help="Bypass the .bin extension filter (only works with -d)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show successful/skipped checks in addition to warnings and failures")
    parser.add_argument("-s", "--ignore-size", action="store_true",
                        help="Ignore non-540 file size warnings (treats 532B/572B sizes as standard)")
    args = parser.parse_args()

    if args.ignore_extension and not args.directory:
        abort("Error: -x / --ignore-extension can only be used when specifying a directory with -d / --directory.")

    master_key = load_master_keys()

    # Resolve target path from arguments
    if args.directory:
        target_path = args.directory
    elif args.path:
        target_path = args.path
    else:
        target_path = "."

    # Auto-fallback to ../fullset if directory has no matching files
    if os.path.isdir(target_path):
        if args.ignore_extension:
            has_matching = any(files for _, _, files in os.walk(target_path))
        else:
            has_matching = any(
                f.lower().endswith(".bin")
                for _, _, files in os.walk(target_path)
                for f in files
            )

        if not has_matching:
            fallback_path = "../fullset"
            if os.path.exists(fallback_path):
                target_path = fallback_path

    process_path(target_path, master_key,
                 ignore_size=args.ignore_size,
                 ignore_extension=args.ignore_extension,
                 verbose=args.verbose)


if __name__ == "__main__":
    main()
    if len(sys.argv) == 1:
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
