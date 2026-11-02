#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# amiibandtool - Tool to manage, decrypt, encrypt, and convert SNW Power-Up Band dumps.

import argparse
import os
import sys
from typing import List, Optional, Tuple

print("👾  amiibandtool v1.6.0 by CheatFreak  👾\n"
      "-----------------------------------------\n"
      "World's first tool for working with Super Nintendo World Wristbands.\n"
      "By default, it tries to decrypt bin files, or encrypt dec files in the current folder.\n"
      "Run with -h to for helpful information on all functions.\n")

try:
    from amiibo import AmiiboDump, AmiiboMasterKey
except ImportError:
    print("Error: The 'pyamiibo' package is required but not installed.")
    print("Please install it via your terminal: pip install pyamiibo")
    sys.exit(1)


# Constants

CONVERTED_SUFFIX = "_std_ntag215"


# Exit & Error Helpers

def abort(msg: str, no_pause: bool = False) -> None:
    # Print error message and exit cleanly.
    print(msg)
    if not no_pause:
        input("\nPress Enter to exit...")
    sys.exit(1)


# SNW Power-Up Band Dump

class SNWPowerUpBandDump(AmiiboDump):
    # Custom subclass for Super Nintendo World Power-Up Bands (NTAG I2C layout).
    @property
    def _uid_raw(self) -> bytes:
        # NT3H2111 has a continuous 7-byte UID at the very beginning
        return self.data[0x00:0x07]


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


# File I/O & Splitting

def _write_dump(data: bytearray, output_path: str) -> None:
    # Write dump data to file with global overwrite protection.
    if os.path.exists(output_path):
        raise FileExistsError(f"Output file '{output_path}' already exists (overwrite protection enabled).")
    with open(output_path, "wb") as f:
        f.write(bytes(data))


def _split_core_and_trailing(data: bytes) -> Tuple[bytearray, bytes, int]:
    # Split raw bytes into padded 540-byte (0x21C) core and trailing lossless bytes, retaining original size.
    orig_size = len(data)
    if orig_size >= 0x21C:
        core = bytearray(data[:0x21C])
        trailing = data[0x21C:]
    else:
        core = bytearray(data) + bytearray(0x21C - orig_size)
        trailing = b""
    return core, trailing, orig_size


def load_lossless_dump(filepath: str) -> Tuple[bytearray, bytes, int]:
    # Validate size, check SNW band signature, and split into core 0x21C EEPROM data and trailing lossless bytes.
    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    valid_sizes = {532, 540, 572, 944, 1024}
    if len(raw_bytes) not in valid_sizes:
        raise ValueError(f"Invalid file size ({len(raw_bytes)}B). Expected one of: {valid_sizes}")

    if len(raw_bytes) > 0x07 and raw_bytes[0x07] != 0x00:  # SNW band signature check
        raise ValueError(
            f"Not a Nintendo World Band: Byte at offset 0x07 "
            f"is 0x{raw_bytes[0x07]:02X} (expected 0x00)."
        )

    return _split_core_and_trailing(raw_bytes)


# Processing Functions

def process_decrypt(filepath: str, output_path: str, master_keys: AmiiboMasterKey) -> None:
    # Decrypt an SNW Power-Up Band .bin file to .dec format.
    core_540, trailing_bytes, _ = load_lossless_dump(filepath)

    dump = SNWPowerUpBandDump(master_keys, bytes(core_540), is_locked=True)
    dump.verify = lambda *args, **kwargs: True
    dump.unlock()

    lossless_dec = bytearray(dump.data[:0x21C]) + trailing_bytes
    _write_dump(lossless_dec, output_path)
    print(f"   ✅  {os.path.basename(output_path)} output!\n")


def process_encrypt(filepath: str, output_path: str, master_keys: AmiiboMasterKey) -> None:
    # Encrypt an SNW Power-Up Band .dec file to .bin format.
    with open(filepath, "rb") as f:
        input_bytes = f.read()

    core_540, trailing_bytes, orig_size = _split_core_and_trailing(input_bytes)

    dump = SNWPowerUpBandDump(master_keys, bytes(core_540), is_locked=False)
    
    # Bypass pyamiibo's strict BCC check property entirely by overriding uid_bin
    type(dump).uid_bin = property(lambda self: self._uid_raw)

    dump.lock()

    # 1. Extract generated PWD/PACK from standard NTAG location (pages 0x85/0x86 -> offsets 0x214:0x21C)
    pwd_pack = dump.data[0x214:0x21C]

    # 2. Zero out the original NTAG215 password/PACK offset in the core so it isn't duplicated
    dump.data[0x214:0x21C] = b"\x00" * 8

    # 3. Move PWD/PACK to SNW pages 0xE5/0xE6 in trailing bytes (offset 0x178)
    if len(trailing_bytes) >= 0x180:
        trailing_bytes = bytearray(trailing_bytes)
        trailing_bytes[0x178:0x180] = pwd_pack

    lossless_enc = bytearray(dump.data[:0x21C]) + bytes(trailing_bytes)
    
    # Strictly preserve original file size if it was 944 or 1024 bytes
    if orig_size == 944 and len(lossless_enc) > 944:
        lossless_enc = lossless_enc[:944]
    elif orig_size == 1024 and len(lossless_enc) < 1024:
        lossless_enc = lossless_enc + b"\x00" * (1024 - len(lossless_enc))

    _write_dump(lossless_enc, output_path)
    print(f"   ✅  {os.path.basename(output_path)} output!\n")


def process_convert(filepath: str, output_path: str, master_keys: AmiiboMasterKey) -> None:
    # Convert an SNW Power-Up Band dump into standard NTAG215 format.
    core_540, _, _ = load_lossless_dump(filepath)

    # 1. Unlock using SNW Power-Up Band layout
    dump = SNWPowerUpBandDump(master_keys, bytes(core_540), is_locked=True)
    dump.verify = lambda *args, **kwargs: True
    dump.unlock()

    # 2. Extract 7-byte UID from NTAG I2C layout (Page 0x00 bytes 0x00-0x03 + Page 0x01 bytes 0x00-0x02)
    uid = core_540[0x00:0x04] + core_540[0x04:0x07]

    # 3. Calculate standard NTAG215 BCC checksums
    bcc0 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2]
    bcc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]

    # 4. Modify decrypted data to use standard NTAG215 layout
    dump.data[0x00:0x04] = bytes([uid[0], uid[1], uid[2], bcc0])
    dump.data[0x04:0x08] = bytes([uid[3], uid[4], uid[5], uid[6]])
    dump.data[0x08]      = bcc1
    dump.data[0x09]      = 0x48

    # 5. Lock under standard NTAG215 cryptographic layout
    std_dump = AmiiboDump(master_keys, bytes(dump.data), is_locked=False)
    std_dump.verify = lambda *args, **kwargs: True
    std_dump.lock()

    # 6. Strictly output 540 bytes (0x21C)
    std_bytes = bytearray(std_dump.data[:0x21C])
    _write_output(std_bytes, output_path)
    print(f"   ✅  {os.path.basename(output_path)} output!\n")


# Path Computation Helpers

def compute_swap_ext_path(input_path: str, *, force_ext: Optional[str] = None) -> str:
    # Generate output path by swapping or forcing extension.
    base, _ = os.path.splitext(input_path)
    if force_ext:
        return f"{base}{force_ext}"
    ext = ".bin" if input_path.lower().endswith(".dec") else ".dec"
    return f"{base}{ext}"


def compute_suffixed_path(input_path: str, suffix: str) -> str:
    # Generate output path with suffix inserted before extension.
    base, ext = os.path.splitext(input_path)
    return f"{base}{suffix}{ext if ext else '.bin'}"


# CLI

def resolve_inputs(args) -> List[str]:
    # Merge positional and -i inputs into a single list.
    inputs = list(args.positional_inputs or [])
    inputs.extend(args.input or [])
    return inputs


def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Lossless tool to manage, decrypt, encrypt, and convert SNW Power-Up Band dumps."
    )
    parser.add_argument("positional_inputs", nargs="*", help="Input file(s)")
    parser.add_argument("-i", "--input", nargs="+", help="Input file(s)")
    parser.add_argument("-o", "--output", default=None, help="Output file path")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Force decryption")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Force encryption")
    parser.add_argument("-c", "--convert", action="store_true", help="Convert SNW Power-Up Band dump into standard NTAG215 format")
    parser.add_argument("-p", "--no-pause", action="store_true", help="Skip exit pause")
    parser.add_argument("-k", "--key", default=None, help="Path to key_retail.bin")
    args = parser.parse_args()

    master_keys = load_master_keys(args.key, no_pause=args.no_pause)
    all_inputs = resolve_inputs(args)

    inputs_are_explicit = len(all_inputs) > 0
    force_decrypt = args.decrypt and inputs_are_explicit
    force_encrypt = args.encrypt and inputs_are_explicit

    # Auto-Discovery Mode 
    if not all_inputs:
        files = os.listdir(".")
        valid_sizes = {532, 540, 572, 944, 1024}
        
        # Ignore key_retail.bin silently
        bin_files = [f for f in files if f.lower().endswith(".bin") and f.lower() != "key_retail.bin"]
        dec_files = [f for f in files if f.lower().endswith(".dec") and f.lower() != "key_retail.dec"]

        bin_map = {os.path.splitext(f)[0].lower(): f for f in bin_files if os.path.getsize(f) in valid_sizes}
        dec_map = {os.path.splitext(f)[0].lower(): f for f in dec_files if os.path.getsize(f) in valid_sizes}

        # Guard: Check for mixed file types with identical base names
        common_bases = set(bin_map) & set(dec_map)
        if common_bases:
            name = next(iter(common_bases))
            abort(f"\n❌  I don't know what you want me to do:\n    Both {name}.bin and {name}.dec exist in the folder.", args.no_pause)

        if bin_map and not dec_map:
            print(f"Found {len(bin_map)} .bin file(s) and no .dec files. Decrypting all...\n")
            for f in bin_map.values():
                print(f"📄  {f}")
                try:
                    out_path = compute_swap_ext_path(f, force_ext=".dec")
                    process_decrypt(f, out_path, master_keys)
                except Exception as e:
                    print(f"   ❌  Error: {e}\n")
        elif dec_map and not bin_map:
            print(f"Found {len(dec_map)} .dec file(s) and no .bin files. Encrypting all...\n")
            for f in dec_map.values():
                print(f"📄  {f}")
                try:
                    out_path = compute_swap_ext_path(f, force_ext=".bin")
                    process_encrypt(f, out_path, master_keys)
                except Exception as e:
                    print(f"   ❌  Error: {e}\n")
        else:
            parser.print_help()
            abort("\n❌  Error: No input files specified and no valid .bin/.dec files found in the folder.", args.no_pause)

        print("Finished!")
        return args.no_pause

    # Explicit Input Mode 
    if args.output and len(all_inputs) > 1:
        abort("Error: The -o / --output option can only be used when processing a single input file.", args.no_pause)

    # Check for illegal mixed explicit input types (.bin AND .dec in the same command execution)
    exts = {os.path.splitext(p)[1].lower() for p in all_inputs if os.path.exists(p)}
    if ".bin" in exts and ".dec" in exts and not (args.decrypt or args.encrypt or args.convert):
        abort("❌  I don't know what you want me to do: Both .bin and .dec files were specified in input arguments.", args.no_pause)

    for input_path in all_inputs:
        if not os.path.exists(input_path):
            print(f"📄  {input_path}")
            print("   ❌  Error: Input file not found.\n")
            continue

        print(f"📄  {input_path}")

        if args.output and len(all_inputs) == 1:
            output_path = args.output
        elif args.convert:
            output_path = compute_suffixed_path(input_path, CONVERTED_SUFFIX)
        else:
            if force_decrypt:
                force_ext = ".dec"
            elif force_encrypt:
                force_ext = ".bin"
            else:
                force_ext = None
            output_path = compute_swap_ext_path(input_path, force_ext=force_ext)

        try:
            if args.convert:
                process_convert(input_path, output_path, master_keys)
            elif force_decrypt:
                process_decrypt(input_path, output_path, master_keys)
            elif force_encrypt:
                process_encrypt(input_path, output_path, master_keys)
            else:
                # Infer action from extension
                ext = os.path.splitext(input_path)[1].lower()
                if ext == ".dec":
                    process_encrypt(input_path, output_path, master_keys)
                elif ext in (".bin", ".raw"):
                    process_decrypt(input_path, output_path, master_keys)
                else:
                    print("   ❌  Error: Unknown file extension. Expected .bin or .dec\n")
        except Exception as err:
            print(f"   ❌  Error: {err}\n")

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
