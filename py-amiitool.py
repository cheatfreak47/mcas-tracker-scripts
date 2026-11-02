#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# py amiitool - Bi-directional Amiibo converter and save transfer tool.

import argparse
import os
import sys
from typing import List, Optional

print("👾  py amiitool v3.9.1 by CheatFreak  👾\n"
      "-----------------------------------------\n"
      "A reimplementation of amiitool in python, with pyamiibo.\n"
      "By default, it tries to decrypt bin files, or encrypt dec files in the current folder.\n"
      "Run with -h to for helpful information on all functions.")

try:
    from amiibo import AmiiboDump, AmiiboMasterKey
except ImportError:
    print("Error: The 'pyamiibo' package is required but not installed.")
    print("Please install it via your terminal: pip install pyamiibo")
    sys.exit(1)

# Constants

# Output filename appendices
SUFFIX_FIXED = "_fixed"
SUFFIX_RESET = "_reset"
SUFFIX_SAVE = "_save"


# Exit & Error Helpers

def abort(msg: str, no_pause: bool = False) -> None:
    print(msg)
    if not no_pause:
        input("\nPress Enter to exit...")
    sys.exit(1)


# Dump Helpers

def apply_lenient_bypass(dump: AmiiboDump) -> None:
    # Disable verification and password setting (lenient mode), this is a workaround to basically implement the original amiitool lenient mode.
    # Honestly, I have no real need for this, but for feature pairity it's here. It can help fix very odd circumstance amiibo.
    dump.verify = lambda: None
    dump.set_password = lambda: None


def validate_registration_flag(dump: AmiiboDump) -> None:
    # Registation flag 0x14 (decrypted) is useful to see if the tag decrypted properly. It will always have one of these values.
    flag = dump.data[0x14]  # Registration flag offset (00 = uninit, 10 = no save, 20 = no owner, 30 = both present)
    if flag not in (0x00, 0x10, 0x20, 0x30):
        valid = " or ".join(f"0x{v:02X}" for v in (0x00, 0x10, 0x20, 0x30))
        raise ValueError(
            f"Invalid registration flag at 0x14: 0x{flag:02X} (expected {valid})"
        )


def _try_with_lenient_fallback(create_fn, process_fn, *,
                               lenient: bool,
                               fail_msg: str,
                               lenient_fail_msg: str) -> AmiiboDump:
    # Generic try/except/lenient-retry for dump operations.
    try:
        dump = create_fn()
        if lenient:
            apply_lenient_bypass(dump)
        process_fn(dump)
        return dump
    except Exception as e:
        if not lenient:
            err_msg = str(e) or type(e).__name__
            raise ValueError(f"{fail_msg} ({err_msg}). Use -l for lenient mode.")

        print(f"   ⚠️  {fail_msg}. Lenient input used.")
        try:
            dump = create_fn()
            apply_lenient_bypass(dump)
            process_fn(dump)
            return dump
        except Exception as inner_e:
            err_msg = str(inner_e) or type(inner_e).__name__
            raise ValueError(f"{lenient_fail_msg} ({err_msg}).")


def unlock_dump(data: bytes, master_keys: AmiiboMasterKey, *,
                lenient: bool = False, descriptor: str = "Input file") -> AmiiboDump:
    # Create an AmiiboDump from locked data and unlock it.
    return _try_with_lenient_fallback(
        create_fn=lambda: AmiiboDump(master_keys, data),
        process_fn=lambda d: d.unlock(),
        lenient=lenient,
        fail_msg=f"{descriptor} unlock failed",
        lenient_fail_msg=f"After lenient unlock, {descriptor.lower()} is corrupt. Bad UID or crypto failure",
    )


def load_dec_dump(data: bytes, master_keys: AmiiboMasterKey, *,
                  lenient: bool = False, descriptor: str = "Input file") -> AmiiboDump:
    # Create an AmiiboDump from decrypted data (no unlock needed).
    return _try_with_lenient_fallback(
        create_fn=lambda: AmiiboDump(master_keys, data, is_locked=False),
        process_fn=lambda d: None,  # Dec dumps don't need unlocking
        lenient=lenient,
        fail_msg=f"{descriptor} processing failed",
        lenient_fail_msg=f"After lenient processing, {descriptor.lower()} is corrupt. Bad UID or crypto failure",
    )


def lock_dump(dump: AmiiboDump, *,
              lenient: bool = False, descriptor: str = "Target file") -> None:
    # Lock an AmiiboDump with valid signatures.
    def _try_lock(is_lenient: bool) -> None:
        if is_lenient:
            apply_lenient_bypass(dump)
        dump.lock()

    try:
        _try_lock(lenient)
    except Exception as e:
        if not lenient:
            err_msg = str(e) or type(e).__name__
            raise ValueError(f"{descriptor} lock failed ({err_msg}). Use -l for lenient mode.")

        print(f"   ⚠️  {descriptor} lock failed. Lenient input used.")
        try:
            _try_lock(True)
        except Exception as inner_e:
            err_msg = str(inner_e) or type(inner_e).__name__
            raise ValueError(f"After lenient locking, {descriptor.lower()} is corrupt ({err_msg}).")


def load_dump_auto(filepath: str, master_keys: AmiiboMasterKey, *,
                   lenient: bool = False, descriptor: str = "Input file") -> AmiiboDump:
    # Load and unlock an AmiiboDump from either .bin or .dec file.
    data = read_and_normalize_dump(filepath, lenient=lenient)
    is_dec = filepath.lower().endswith(".dec")

    if is_dec:
        return load_dec_dump(data, master_keys, lenient=lenient, descriptor=descriptor)
    return unlock_dump(data, master_keys, lenient=lenient, descriptor=descriptor)


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
                abort(f"Error reading '{path}': {e}", no_pause)

    if explicit_key_path:
        abort(f"Error: Specified key file '{explicit_key_path}' not found.", no_pause)
    else:
        abort("Error: Master key file 'key_retail.bin' not found in current directory or '../keys/'.", no_pause)


# Layout Detection & Conversion

def is_amiitool_plain(data: bytes) -> bool:
    # OG amiitool uses a jank-ass scrabled layout for everything while decrypted. I have no idea why they did this, but we support it anyway for ingest.
    # Check if data uses amiitool's scrambled layout (UID buried at 0x1D4).
    if len(data) < 476:  # Needs at least 0x1DC
        return False

    # Standard layout: UID at 0x000
    if data[0] == 0x04 and data[7] in (0x80, 0x81, 0x90, 0x91):
        return False

    # Amiitool layout: UID at 0x1D4
    return (
        data[0x1D4] == 0x04
        and data[0x1DB] in (0x80, 0x81, 0x90, 0x91)
    )


def convert_amiitool_plain_to_tag(plain_data: bytes) -> bytearray:
    # Unscramble amiitool 'plain' layout into standard NTAG215 physical layout, with decrypted sections. (modern .dec basically)
    tag = bytearray(540)

    tag[0x000:0x008] = plain_data[0x1D4:0x1DC]  # UID
    tag[0x008:0x010] = plain_data[0x000:0x008]  # Write Counters
    tag[0x010:0x034] = plain_data[0x028:0x04C]  # Encrypted Data Part 1
    tag[0x034:0x054] = plain_data[0x1B4:0x1D4]  # Tag HMAC
    tag[0x054:0x080] = plain_data[0x1DC:0x208]  # Model Info
    tag[0x080:0x0A0] = plain_data[0x008:0x028]  # Data HMAC
    tag[0x0A0:0x208] = plain_data[0x04C:0x1B4]  # Encrypted Data Part 2

    # NTAG215 Trailer / Configuration defaults
    tag[0x208:0x20C] = bytes([0x01, 0x00, 0x0F, 0xBD])
    tag[0x20C:0x210] = bytes([0x00, 0x00, 0x00, 0x04])
    tag[0x210:0x214] = bytes([0x5F, 0x00, 0x00, 0x00])

    # Derive password from UID
    uid = tag[0x000:0x007]
    tag[0x214:0x218] = bytes([
        0xAA ^ uid[1] ^ uid[3],
        0x55 ^ uid[2] ^ uid[4],
        0xAA ^ uid[3] ^ uid[5],
        0x55 ^ uid[4] ^ uid[6],
    ])
    tag[0x218:0x21C] = bytes([0x80, 0x80, 0x00, 0x00])

    return tag


# File I/O & Normalization

def read_and_normalize_dump(filepath: str, lenient: bool = False) -> bytearray:
    # Read an Amiibo dump, normalize to 540 bytes, with hardware format guards.
    with open(filepath, "rb") as f:
        data = f.read()

    size = len(data)

    if size in {1968, 2048}:  # NT3H2211 (Amiibo v3) file sizes
        raise ValueError("NT3H2211 (Amiibo v3) are not supported by this tool.")

    # NT3H2111 (Super Nintendo World Wristbands) via size or signature
    is_snw = (
        size in {944, 1024}
        or (size >= 0x60
            and data[0x07] == 0x00 and data[0x09] == 0x00
            and data[0x5C:0x60] == b'\xAA\xBB\xCC\xDD')
    )
    if is_snw:
        raise ValueError(
            "NT3H2111 (Super Nintendo World Wristbands) are not supported by this tool.\n"
            "   ℹ️  You may convert them to NTAG215 with amiibandtool.py."
        )

    # Normalize to 540 bytes
    # Todo: maybe make truncation of 572s optional? Eh, it's a bad habit to keep 572s around...
    if size == 572:
        normalized = data[:540]
    elif size == 532:
        normalized = data + b"\x00" * (540 - size)
    else:
        normalized = data

    if is_amiitool_plain(normalized):
        print("    ℹ️  Detected legacy amiitool scrambled layout.")
        normalized = convert_amiitool_plain_to_tag(normalized)

    if len(normalized) != 540:
        raise ValueError(f"Unsupported file size/layout for '{filepath}' ({size} bytes).")

    result = bytearray(normalized)

    # Auto-fix BCC checksums in lenient mode
    if lenient and len(result) >= 9:
        expected_bcc0 = 0x88 ^ result[0] ^ result[1] ^ result[2]
        expected_bcc1 = result[4] ^ result[5] ^ result[6] ^ result[7]
        if result[3] != expected_bcc0 or result[8] != expected_bcc1:
            print("   ⚠️  Invalid UID BCC checksums detected. Auto-fixing BCCs in lenient mode.")
            result[3] = expected_bcc0
            result[8] = expected_bcc1

    return result


# Conversion Operations

def _write_dump(dump: AmiiboDump, output_path: str) -> None:
    # Write dump data to file with global overwrite protection.
    if os.path.exists(output_path):
        raise ValueError(f"Output file '{output_path}' already exists (overwrite protection enabled).")
    with open(output_path, "wb") as f:
        f.write(dump.data)


def convert_bin_to_dec(input_path: str, output_path: str,
                        master_keys: AmiiboMasterKey, lenient: bool = False) -> None:
    # Decrypt an encrypted .bin file into a standard .dec layout.
    data = read_and_normalize_dump(input_path, lenient=lenient)
    dump = unlock_dump(data, master_keys, lenient=lenient)
    validate_registration_flag(dump)
    _write_dump(dump, output_path)


def convert_dec_to_bin(input_path: str, output_path: str,
                        master_keys: AmiiboMasterKey, lenient=False) -> None:
    # Encrypt/sign a raw .dec file into a valid .bin dump.
    data = read_and_normalize_dump(input_path, lenient=lenient)
    dump = load_dec_dump(data, master_keys, lenient=lenient)
    validate_registration_flag(dump)
    lock_dump(dump, lenient=lenient)
    _write_dump(dump, output_path)


# Save Transfer

def perform_save_copy(source_path: str, target_path: str, output_path: str,
                      master_keys: AmiiboMasterKey, lenient: bool = False) -> None:
    # Copy save data regions from source Amiibo to target Amiibo.
    # Mostly implemented because amiitool had it... only it actually didn't work properly on amiitool at all lol
    # Oh well, my implementation works.
    print(f"📦  Source Save File: {source_path}")
    print(f"🎯  Target Amiibo   : {target_path}")

    source_dump = load_dump_auto(source_path, master_keys, lenient=lenient, descriptor="Save file")
    validate_registration_flag(source_dump)

    if source_dump.data[0x14] == 0x00:  # Registration flag offset check
        raise ValueError(
            "Source save file has an uninitialized registration flag "
            "(0x14 is 0x00). There is no save data to copy."
        )

    target_dump = load_dump_auto(target_path, master_keys, lenient=lenient, descriptor="Target file")

    # Copy save regions on decrypted data (0x14-0x33 and 0xA0-0x207)
    target_dump.data[0x14:0x34] = source_dump.data[0x14:0x34]
    target_dump.data[0xA0:0x208] = source_dump.data[0xA0:0x208]

    lock_dump(target_dump, lenient=lenient, descriptor="Target file")
    _write_dump(target_dump, output_path)

    print(f"   ✅  Successfully copied save data and saved to: {output_path}\n")


# Fix & Reset Operations

def perform_fix(input_path: str, output_path: str,
                master_keys: AmiiboMasterKey) -> None:
    # Fix/sanitize a dump (implies lenient): fix BCCs, check 0x14, auto-reset if corrupt.
    print(f"🔧  Fixing Amiibo Dump: {input_path}")

    # Capture pristine normalized bytes without lenient BCC healing for comparison reference
    original_normalized = read_and_normalize_dump(input_path, lenient=False)

    # Load and unlock with lenient fixing enabled
    dump = load_dump_auto(input_path, master_keys, lenient=True, descriptor="Input file")

    # Fix uid3 if it triggers a Cascade Tag conflict
    if dump.data[0x04] == 0x88:
        print("   ⚠️  UID contains 0x88 at uid3 (Cascade Tag conflict). Fixing UID byte.")
        import random
        new_uid3 = random.randint(0, 255)
        while new_uid3 == 0x88:
            new_uid3 = random.randint(0, 255)
        dump.data[0x04] = new_uid3

    # Recalculate BCC0 (offset 0x03) and BCC1 (offset 0x08) to ensure UID integrity
    dump.data[0x03] = 0x88 ^ dump.data[0x00] ^ dump.data[0x01] ^ dump.data[0x02]
    dump.data[0x08] = dump.data[0x04] ^ dump.data[0x05] ^ dump.data[0x06] ^ dump.data[0x07]

    # Force standard NTAG215 trailer configuration bytes (Pages 130-132 / offsets 0x208-0x210)
    dump.data[0x208:0x20C] = bytes([0x01, 0x00, 0x0F, 0xBD])  # DLB (Page 130)
    dump.data[0x20C:0x210] = bytes([0x00, 0x00, 0x00, 0x04])  # CFG0 (Page 131)
    dump.data[0x210:0x214] = bytes([0x5F, 0x00, 0x00, 0x00])  # CFG1 (Page 132)

    flag = dump.data[0x14]  # Registration flag offset
    if flag not in (0x00, 0x10, 0x20, 0x30):  # Invalid registration flag
        print("   ⚠️  Save file is corrupt, resetting.")
        dump.data[0x14:0x18] = b'\x00' * 4                # Wipe configuration/init bits through 0x17
        dump.data[0x11:0x13] = os.urandom(2)              # Random garbage in 0x11-0x12
        dump.data[0x18:0x34] = os.urandom(0x34 - 0x18)    # Random garbage in 0x18-0x33
        dump.data[0xA0:0x208] = os.urandom(0x208 - 0xA0)  # Random garbage in save region
        dump.data[0x108:0x10A] = b'\x00' * 2              # Zero out app counters

    lock_dump(dump, lenient=True, descriptor="Input file")

    # Compare resulting bytes to pristine original input; skip writing if already healthy/unchanged
    if bytes(dump.data) == bytes(original_normalized):
        print("   ℹ️  No errors detected; file is already healthy. Skipping output generation.\n")
        return

    _write_dump(dump, output_path)
    print(f"   ✅  Successfully fixed Amiibo and saved to: {output_path}\n")


def perform_reset(input_path: str, output_path: str,
                  master_keys: AmiiboMasterKey, lenient: bool = False) -> None:
    # Reset an Amiibo dump to Nintendo factory reset state.
    print(f"🔄  Resetting Amiibo State: {input_path}")

    dump = load_dump_auto(input_path, master_keys, lenient=lenient, descriptor="Input file")

    # Nintendo factory reset behavior:
    # 1. Zero out registration/init bytes 0x14 through 0x17
    dump.data[0x14:0x18] = b'\x00' * 4

    # 2. Fill bytes 0x11 and 0x12 with random garbage
    dump.data[0x11:0x13] = os.urandom(2)

    # 3. Fill region 0x18 to 0x33 with random garbage
    dump.data[0x18:0x34] = os.urandom(0x34 - 0x18)

    # 4. Fill save data region 0xA0 to 0x207 with random garbage, except app counters at 0x108-0x109
    dump.data[0xA0:0x208] = os.urandom(0x208 - 0xA0)
    dump.data[0x108:0x10A] = b'\x00' * 2

    lock_dump(dump, lenient=lenient, descriptor="Input file")
    _write_dump(dump, output_path)

    print(f"   ✅  Successfully reset Amiibo and saved to: {output_path}\n")


# Single File Processing

def process_single_file(input_path: str, output_path: str,
                        master_keys: AmiiboMasterKey, *,
                        force_decrypt: bool = False,
                        force_encrypt: bool = False,
                        lenient: bool = False) -> None:
    # Process a single file: auto-detect direction or use forced mode.
    print(f"📄  {input_path}")

    is_dec_op = (
        force_encrypt
        if force_encrypt or force_decrypt
        else input_path.lower().endswith(".dec")
    )

    try:
        if is_dec_op:
            convert_dec_to_bin(input_path, output_path, master_keys, lenient=lenient)
        else:
            convert_bin_to_dec(input_path, output_path, master_keys, lenient=lenient)

        print(f"   ✅  {os.path.basename(output_path)} output!\n")
    except Exception as e:
        print(f"   ❌  Error: {e}\n")


# Output Path Helpers

def compute_suffixed_path(input_path: str, suffix: str) -> str:
    # Generate output path with suffix inserted before extension.
    base, ext = os.path.splitext(input_path)
    return f"{base}{suffix}{ext if ext else '.bin'}"


def compute_swap_ext_path(input_path: str, *,
                          force_ext: Optional[str] = None) -> str:
    # Generate output path by swapping or forcing extension.
    base, _ = os.path.splitext(input_path)
    if force_ext:
        return f"{base}{force_ext}"
    ext = ".bin" if input_path.lower().endswith(".dec") else ".dec"
    return f"{base}{ext}"


# CLI

def resolve_inputs(args) -> List[str]:
    # Merge positional and -i inputs into a single list.
    inputs = list(args.positional_inputs or [])
    inputs.extend(args.input or [])
    return inputs


def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Bi-directional Amiibo converter (.bin <-> .dec) and save transfer tool using pyamiibo."
    )
    parser.add_argument("positional_inputs", nargs="*", help="Input file(s)")
    parser.add_argument("-i", "--input", nargs="+", help="Input file(s)")
    parser.add_argument("-o", "--output", default=None, help="Output file path")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Force decryption")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Force encryption")
    parser.add_argument("-c", "--copy", action="store_true", help="Copy save data from --save to --input")
    parser.add_argument("-s", "--save", default=None, help="Source save file (requires -c)")
    parser.add_argument("-f", "--fix", action="store_true", help="Fix mode (implies lenient)")
    parser.add_argument("-r", "--reset", action="store_true", help="Reset to factory state")
    parser.add_argument("-l", "--lenient", action="store_true", help="Lenient mode")
    parser.add_argument("-p", "--no-pause", action="store_true", help="Skip exit pause")
    parser.add_argument("-k", "--key", default=None, help="Path to key_retail.bin")
    args = parser.parse_args()

    master_keys = load_master_keys(args.key, no_pause=args.no_pause)
    all_inputs = resolve_inputs(args)

    # Fix Mode (implies lenient) 
    if args.fix:
        if args.output and len(all_inputs) > 1:
            abort("❌  Error: The -o / --output option can only be used when processing a single file.", args.no_pause)

        # Auto-discover .bin files if no inputs specified
        if not all_inputs:
            files = os.listdir(".")
            all_inputs = [f for f in files if f.lower().endswith(".bin") and f.lower() != "key_retail.bin"]
            if not all_inputs:
                abort("❌  Error: The --fix (-f) function requires input file(s) or local .bin files to process.", args.no_pause)
            print(f"Found {len(all_inputs)} .bin file(s). Fixing all...\n")

        for path in all_inputs:
            if not os.path.exists(path):
                print(f"📄  {path}\n   ❌  Error: Input file not found.\n")
                continue
            output = args.output if (args.output and len(all_inputs) == 1) else compute_suffixed_path(path, SUFFIX_FIXED)
            try:
                perform_fix(path, output, master_keys)
            except Exception as e:
                print(f"   ❌  Error: {e}\n")
        return args.no_pause

    # Reset Mode 
    if args.reset:
        if not all_inputs:
            abort("❌  Error: The --reset (-r) function requires input file(s).", args.no_pause)
        if args.output and len(all_inputs) > 1:
            abort("❌  Error: The -o / --output option can only be used when processing a single file.", args.no_pause)

        for path in all_inputs:
            if not os.path.exists(path):
                print(f"📄  {path}\n   ❌  Error: Input file not found.\n")
                continue
            output = args.output if (args.output and len(all_inputs) == 1) else compute_suffixed_path(path, SUFFIX_RESET)
            try:
                perform_reset(path, output, master_keys, lenient=args.lenient)
            except Exception as e:
                print(f"   ❌  Error: {e}\n")
        return args.no_pause

    # Copy Save Mode 
    if args.copy:
        if not args.save:
            abort("❌  Error: The --copy (-c) function requires a source save file specified via --save (-s).", args.no_pause)
        if not all_inputs:
            abort("❌  Error: No target Amiibo input file specified for copy operation (use -i or positional argument).", args.no_pause)

        target = all_inputs[0]
        if not os.path.exists(args.save):
            abort(f"❌  Error: Source save file '{args.save}' not found.", args.no_pause)
        if not os.path.exists(target):
            abort(f"❌  Error: Target Amiibo file '{target}' not found.", args.no_pause)

        output = args.output or compute_suffixed_path(target, SUFFIX_SAVE)
        try:
            perform_save_copy(args.save, target, output, master_keys, lenient=args.lenient)
        except Exception as e:
            print(f"   ❌  Error: {e}\n")
        return args.no_pause

    # Guard: --save without --copy
    if args.save and not args.copy:
        abort("❌  Error: --save (-s) can only be used in conjunction with --copy (-c).", args.no_pause)

    inputs_are_explicit = len(all_inputs) > 0
    force_decrypt = args.decrypt and inputs_are_explicit
    force_encrypt = args.encrypt and inputs_are_explicit

    # Auto-Discovery Mode 
    if not all_inputs:
        files = os.listdir(".")
        bin_files = [f for f in files if f.lower().endswith(".bin") and f.lower() != "key_retail.bin"]
        dec_files = [f for f in files if f.lower().endswith(".dec")]

        bin_map = {os.path.splitext(f)[0].lower(): f for f in bin_files}
        dec_map = {os.path.splitext(f)[0].lower(): f for f in dec_files}
        common_bases = set(bin_map) & set(dec_map)

        if common_bases:
            name = next(iter(common_bases))
            abort(f"\n❌  I don't know what you want me to do:\n    Both {name}.bin and {name}.dec exist in the folder.", args.no_pause)

        if bin_files and not dec_files:
            print(f"Found {len(bin_files)} .bin file(s) and no .dec files. Decrypting all...\n")
            for f in bin_files:
                process_single_file(f, os.path.splitext(f)[0] + ".dec", master_keys, lenient=args.lenient)
        elif dec_files and not bin_files:
            print(f"Found {len(dec_files)} .dec file(s) and no .bin files. Encrypting all...\n")
            for f in dec_files:
                process_single_file(f, os.path.splitext(f)[0] + ".bin", master_keys, lenient=args.lenient)
        else:
            parser.print_help()
            abort("\n❌  Error: No input files specified and no valid .bin/.dec files found in the folder.", args.no_pause)

        print("Finished!")
        return args.no_pause

    # Explicit Input Mode 
    if args.output and len(all_inputs) > 1:
        abort("❌  Error: The -o / --output option can only be used when processing a single input file.", args.no_pause)

    for input_path in all_inputs:
        if not os.path.exists(input_path):
            print(f"📄  {input_path}")
            print("   ❌  Error: Input file not found.\n")
            continue

        if args.output and len(all_inputs) == 1:
            output_path = args.output
        else:
            if force_decrypt:
                force_ext = ".dec"
            elif force_encrypt:
                force_ext = ".bin"
            else:
                force_ext = None
            output_path = compute_swap_ext_path(input_path, force_ext=force_ext)

        process_single_file(
            input_path, output_path, master_keys,
            force_decrypt=force_decrypt, force_encrypt=force_encrypt, lenient=args.lenient,
        )

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
