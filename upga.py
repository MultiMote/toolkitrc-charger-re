#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upga.py - unpack/repack ToolkitRC firmware containers (*.upga).

Container format (little-endian):
    0x00  magic[8]      e.g. "SWVVM8PD"
    0x08  length  u32   payload length (without padding)
    0x0C  reserved[4]   always zero
    0x10  iv[16]        AES-CBC initialization vector
    0x20  ciphertext    AES-128-CBC, key b"swvv"*4, zero padded to 16

File size = 32 + round_up(length, 16).

Commands:
    info    FILE                 show header and vector table
    unpack  FILE [-o OUT]        decrypt into a raw image (*.bin)
    pack    FILE [-o OUT]        encrypt a raw image back into *.upga
    verify  FILE                 check container (rebuild + byte compare)

Examples:
    ./upga.py info app.upga
    ./upga.py unpack app.upga -o app.bin
    ./upga.py pack app.bin -o app_new.upga --iv random
    ./upga.py verify app.upga
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

# --------------------------------------------------------------------------
# Format constants
# --------------------------------------------------------------------------

KEY = b"swvv" * 4          # AES-128: "swvvswvvswvvswvv"
HEADER_SIZE = 32
DEFAULT_MAGIC = b"SWVVM8PD"

# Observed magic values (first 4 bytes are the "SWVV" prefix, last one is "D").
KNOWN_MAGICS = {
    "M8P": b"SWVVM8PD",
    "M6P": b"SWVVM6PD",
    "M7": b"SWVVM6PD",
    "MC8": b"SWVVMC8D",
    "DS8": b"SWVVDS8D",
}

# Assumed image load address (see VTOR analysis in main()).
DEFAULT_BASE = 0x08009000


# --------------------------------------------------------------------------
# AES-CBC: pycryptodome, with a cryptography fallback
# --------------------------------------------------------------------------

def _aes_cbc(data: bytes, iv: bytes, encrypt: bool, key: bytes = KEY) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if len(data) % 16:
        raise ValueError("data length must be a multiple of 16")
    try:
        from Crypto.Cipher import AES  # pycryptodome
        c = AES.new(key, AES.MODE_CBC, iv)
        return c.encrypt(data) if encrypt else c.decrypt(data)
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:  # pragma: no cover
        raise SystemExit("pycryptodome (pip install pycryptodome) "
                         "or cryptography is required") from e
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    ctx = c.encryptor() if encrypt else c.decryptor()
    return ctx.update(data) + ctx.finalize()


# --------------------------------------------------------------------------
# Container
# --------------------------------------------------------------------------

def looks_like_raw_image(data: bytes) -> bool:
    """Does it look like a raw Cortex-M image (SP in RAM, reset with Thumb bit)?"""
    if len(data) < 8:
        return False
    sp, reset = struct.unpack_from("<II", data, 0)
    return (0x20000000 <= sp <= 0x20080000) and bool(reset & 1)


def parse_header(data: bytes) -> dict:
    if len(data) < HEADER_SIZE:
        raise ValueError("file is shorter than the 32-byte header")
    magic = data[0:8]
    length = struct.unpack_from("<I", data, 8)[0]
    reserved = data[12:16]
    iv = data[16:32]
    return {
        "magic": magic,
        "length": length,
        "reserved": reserved,
        "iv": iv,
        "body": data[HEADER_SIZE:],
    }


def decrypt_container(data: bytes, key: bytes = KEY) -> tuple[bytes, dict]:
    h = parse_header(data)
    need = (h["length"] + 15) // 16 * 16
    if len(h["body"]) < need:
        raise ValueError(
            "less data than the header claims: need %d, have %d"
            % (need, len(h["body"]))
        )
    plain = _aes_cbc(h["body"][:need], h["iv"], encrypt=False, key=key)
    return plain[: h["length"]], h


def build_container(payload: bytes, magic: bytes = DEFAULT_MAGIC,
                    iv: bytes | None = None, key: bytes = KEY) -> bytes:
    if iv is None:
        iv = os.urandom(16)
    magic = magic.ljust(8, b"\x00")[:8]
    pad = (-len(payload)) % 16
    cipher = _aes_cbc(payload + b"\x00" * pad, iv, encrypt=True, key=key)
    header = magic + struct.pack("<I", len(payload)) + b"\x00" * 4 + iv
    return header + cipher


# --------------------------------------------------------------------------
# Vector table parsing (for info)
# --------------------------------------------------------------------------

def analyze_image(img: bytes, base: int | None = None) -> dict:
    out = {"size": len(img), "md5": hashlib.md5(img).hexdigest()}
    if len(img) < 8:
        return out
    sp, reset = struct.unpack_from("<II", img, 0)
    out["sp"] = sp
    out["reset"] = reset
    out["sp_in_ram"] = 0x20000000 <= sp <= 0x20080000
    out["reset_thumb"] = bool(reset & 1)
    if len(img) >= 16:
        out["nmi"], out["hardfault"] = struct.unpack_from("<II", img, 8)
    if base is not None:
        out["base"] = base
        out["reset_offset"] = (reset & ~1) - base
    return out


def magic_to_text(magic: bytes) -> str:
    try:
        s = magic.rstrip(b"\x00").decode("ascii")
        if s.isprintable():
            return s
    except UnicodeDecodeError:
        pass
    return magic.hex()


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_info(args) -> int:
    data = open(args.file, "rb").read()

    if looks_like_raw_image(data) and not data.startswith(b"SWVV"):
        a = analyze_image(data, args.base)
        print("Format      : raw image (not a container)")
        print("Size        : %d (0x%X)" % (a["size"], a["size"]))
        print("MD5         : %s" % a["md5"])
        print("SP          : 0x%08X" % a["sp"])
        print("Reset       : 0x%08X" % a["reset"])
        return 0

    payload, h = decrypt_container(data, key=_key_from_args(args))
    a = analyze_image(payload, args.base)

    print("Format      : ToolkitRC .upga (AES-128-CBC)")
    print("File        : %s" % args.file)
    print("File size   : %d (0x%X)" % (len(data), len(data)))
    print("Magic       : %r (%s)" % (h["magic"], magic_to_text(h["magic"])))
    print("Length      : %d (0x%X)" % (h["length"], h["length"]))
    print("Reserved    : %s" % h["reserved"].hex())
    print("IV          : %s" % h["iv"].hex())
    print("Expected    : %d" % (HEADER_SIZE + (h["length"] + 15) // 16 * 16))
    print("Payload MD5 : %s" % a["md5"])
    print("SP          : 0x%08X%s" % (a["sp"], "" if a.get("sp_in_ram") else "  (!) not in RAM"))
    print("Reset       : 0x%08X%s" % (a["reset"], "  (Thumb)" if a.get("reset_thumb") else ""))
    if "nmi" in a:
        print("NMI         : 0x%08X" % a["nmi"])
        print("HardFault   : 0x%08X" % a["hardfault"])
    if args.base is not None:
        print("Base (given): 0x%08X" % args.base)
        if "reset_offset" in a:
            print("Reset offset: 0x%X (file offset of the reset handler)" % a["reset_offset"])

    if args.json:
        meta = {
            "file": os.path.abspath(args.file),
            "magic": h["magic"].decode("latin-1"),
            "length": h["length"],
            "iv": h["iv"].hex(),
            "md5": a["md5"],
            "base": args.base,
            "sp": a.get("sp"),
            "reset": a.get("reset"),
        }
        json.dump(meta, open(args.json, "w"), indent=2, ensure_ascii=False)
        print("Metadata    : %s" % args.json)
    return 0


def cmd_unpack(args) -> int:
    data = open(args.file, "rb").read()

    if looks_like_raw_image(data) and not data.startswith(b"SWVV"):
        payload, meta = data, {"magic": b"", "length": len(data), "iv": b""}
        print("Warning: this is not a container but a raw image - copying as is")
    else:
        payload, meta = decrypt_container(data, key=_key_from_args(args))
        print("Magic: %s  length=%d  IV=%s"
              % (magic_to_text(meta["magic"]), meta["length"], meta["iv"].hex()))

    out = args.output or _replace_ext(args.file, ".bin")
    with open(out, "wb") as f:
        f.write(payload)

    a = analyze_image(payload, args.base)
    print("Written: %s  (%d bytes, MD5 %s)" % (out, len(payload), a["md5"]))
    if args.base is not None and "reset_offset" in a:
        print("Reset: 0x%08X -> file offset 0x%X" % (a["reset"], a["reset_offset"]))

    if args.sidecar:
        side = {
            "source": os.path.abspath(args.file),
            "magic": meta["magic"].decode("latin-1") if meta["magic"] else None,
            "length": meta["length"],
            "iv": meta["iv"].hex() if meta["iv"] else None,
            "base": args.base,
            "md5": a["md5"],
        }
        json.dump(side, open(args.sidecar, "w"), indent=2, ensure_ascii=False)
        print("Sidecar : %s" % args.sidecar)
    return 0


def cmd_pack(args) -> int:
    payload = open(args.file, "rb").read()

    if payload[:8] in KNOWN_MAGICS.values():
        print("Warning: input already looks like a .upga container. "
              "Unpack it first.", file=sys.stderr)
        if not args.force:
            return 2

    magic = _resolve_magic(args)
    iv = _resolve_iv(args)

    if not args.force and not looks_like_raw_image(payload):
        print("Warning: data does not look like a Cortex-M image "
              "(unexpected SP/Reset). Continuing (use --force to silence).",
              file=sys.stderr)

    blob = build_container(payload, magic=magic, iv=iv, key=_key_from_args(args))

    out = args.output or _replace_ext(args.file, ".upga")
    with open(out, "wb") as f:
        f.write(blob)

    print("Magic   : %s" % magic_to_text(magic))
    print("Length  : %d (0x%X)" % (len(payload), len(payload)))
    print("IV      : %s%s" % (iv.hex(), "  (random)" if args.iv == "random" else ""))
    print("Written : %s  (%d bytes)" % (out, len(blob)))
    print("Check   : %s" % ("OK" if decrypt_container(blob)[0] == payload else "FAILED"))
    return 0


def cmd_verify(args) -> int:
    data = open(args.file, "rb").read()
    payload, h = decrypt_container(data, key=_key_from_args(args))
    rebuilt = build_container(payload, magic=h["magic"], iv=h["iv"],
                              key=_key_from_args(args))
    same = rebuilt == data
    print("File        : %s" % args.file)
    print("Length      : %d, padding %d bytes"
          % (h["length"], (16 - h["length"] % 16) % 16))
    print("Rebuild     : %s" % ("byte-identical" if same else "DIFFERS"))
    if not same:
        for i, (x, y) in enumerate(zip(rebuilt, data)):
            if x != y:
                print("First mismatch at offset 0x%X" % i)
                break
    return 0 if same else 1


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _replace_ext(path: str, ext: str) -> str:
    root, _ = os.path.splitext(path)
    return root + ext


def _key_from_args(args) -> bytes:
    k = getattr(args, "key", None)
    if not k:
        return KEY
    k = k.encode() if isinstance(k, str) else k
    if len(k) != 16:
        raise SystemExit("key must be 16 bytes (AES-128)")
    return k


def _resolve_magic(args) -> bytes:
    if args.magic:
        m = args.magic.encode("latin-1")
        if len(m) > 8:
            raise SystemExit("magic is longer than 8 bytes")
        return m.ljust(8, b"\x00")
    if args.model:
        m = KNOWN_MAGICS.get(args.model.upper())
        if not m:
            raise SystemExit("unknown model %r, known: %s"
                             % (args.model, ", ".join(KNOWN_MAGICS)))
        return m
    return DEFAULT_MAGIC


def _resolve_iv(args) -> bytes:
    if args.iv == "random":
        return os.urandom(16)
    if args.iv == "zero":
        return b"\x00" * 16
    raw = bytes.fromhex(args.iv)
    if len(raw) != 16:
        raise SystemExit("IV must be 16 bytes (32 hex characters)")
    return raw


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Unpack/repack ToolkitRC .upga firmware (AES-128-CBC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, base_default=None):
        sp.add_argument("file", help="input file")
        sp.add_argument("--key", help="16-byte key (default 'swvv'*4)")
        sp.add_argument("--base", type=lambda s: int(s, 0), default=base_default,
                        help="image load address (e.g. 0x08009000)")

    sp = sub.add_parser("info", help="show header and vector table")
    common(sp)
    sp.add_argument("--json", metavar="FILE", help="save metadata to JSON")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("unpack", help="decrypt into a raw image")
    common(sp)
    sp.add_argument("-o", "--output", help="output .bin (default: next to input)")
    sp.add_argument("--sidecar", metavar="FILE", help="save metadata to JSON")
    sp.set_defaults(func=cmd_unpack)

    sp = sub.add_parser("pack", help="encrypt a raw image into a container")
    common(sp)
    sp.add_argument("-o", "--output", help="output .upga (default: next to input)")
    sp.add_argument("--magic", help="8-byte magic, e.g. SWVVM8PD")
    sp.add_argument("--model", help="model used to pick magic: " + ", ".join(KNOWN_MAGICS))
    sp.add_argument("--iv", default="random",
                    help="IV: 'random' (default), 'zero' or 32 hex characters")
    sp.add_argument("--force", action="store_true", help="skip input checks")
    sp.set_defaults(func=cmd_pack)

    sp = sub.add_parser("verify", help="verify a container by rebuilding it")
    common(sp)
    sp.set_defaults(func=cmd_verify)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
