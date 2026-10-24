# `upga.py` — unpack/repack ToolkitRC firmware

Single file, no dependencies besides AES (`pycryptodome` or `cryptography`).

```bash
pip install pycryptodome        # if not installed yet
chmod +x upga.py
```

## Container format

```
0x00  magic[8]     "SWVVM8PD" (M8P), "SWVVMC8D" (MC8), "SWVVM6PD" (M7/M6P), ...
0x08  length u32   payload length (LE)
0x0C  reserved[4]  zeros
0x10  iv[16]       AES-CBC initialization vector
0x20  ciphertext   AES-128-CBC (key = b"swvv"*4), zero padded to 16 bytes
```

File size = `32 + round_up(length, 16)`.

## Commands

```bash
# show header, IV, SP/Reset, file offset of the reset handler
./upga.py info app.upga --base 0x08009000

# decrypt into a raw image (default output: app.bin next to the input)
./upga.py unpack app.upga -o app.bin --base 0x08009000
./upga.py unpack app.upga -o app.bin --sidecar app.json   # + metadata

# encrypt back (random IV by default)
./upga.py pack app.bin -o app_new.upga
./upga.py pack app.bin -o app_new.upga --model M8P
./upga.py pack app.bin -o app_new.upga --magic SWVVM8PD
./upga.py pack app.bin -o app_new.upga --iv zero          # deterministic
./upga.py pack app.bin -o app_new.upga --iv c23c194dbfccbf429204d57e0f16405d

# verify: decrypt + rebuild + byte compare
./upga.py verify app.upga
```

Verified on `app.upga` (V3.07): `unpack` → `pack` with the original IV produces a
**byte-identical** file, and `verify` passes.

## Notes

* The image is linked at **`0x08009000`**, so `file_offset = address − 0x08009000`.
  Reset_Handler `0x08009148` lives at offset `0x148`, `main` `0x0801CF30` at `0x13F30`.
  `--base` is informational only: it never modifies the output bytes, it is used
  to print the file offset of the reset handler.
* The magic must match the model: the updater most likely compares it against the
  device. Observed values: `SWVVM8PD` (M8P), `SWVVMC8D` (MC8), `SWVVM6PD`
  (M7 V3.06 / M6P), `SWVVDS8D` (DS8), `STM32M7D` (M7 V2.08 — old format).
* The IV does not affect the image contents, only the ciphertext, so a random one
  is fine.
* Padding is zero bytes (checked on all samples).
* The stock upgrade utility usually expects the file to be named `app.upga`.
* Raw images (`.upg`, e.g. M8 V1.44) are detected automatically and `unpack`
  simply copies them.
