# .synthimg Format v1

A `.synthimg` file is a single self-contained container image: metadata + rootfs.

## Byte layout

| Offset | Size | Field |
|---|---|---|
| 0  | 8  | magic: `SYNTHIMG` (ASCII) |
| 8  | 1  | format version (`0x01`) |
| 9  | 4  | flags, uint32 LE. bit0 = payload is gzip-compressed |
| 13 | 4  | manifest length, uint32 LE |
| 17 | 32 | SHA-256 of the stored payload bytes (raw, 32 bytes) |
| 49 | N  | manifest, UTF-8 JSON |
| 49+N | — | payload: ustar stream of the rootfs |

## Manifest JSON

```json
{
  "name": "demo",
  "version": "1",
  "arch": "x86_64",
  "created": "2026-09-23T08:46:24Z",
  "hostname": "synthbox",
  "working_dir": "/",
  "entrypoint": ["/bin/sh"],
  "env": ["GREETING=synthbox"]
}
```

## Payload

A classic ustar archive (512-byte headers, regular files, directories,
symlinks; modes preserved; ownership normalized to 0:0 inside the image).
Optionally gzip-compressed (flags bit0). Extraction never follows absolute
paths or `..` — entries are written strictly beneath the target directory.

## Integrity

The header's SHA-256 covers the payload exactly as stored (compressed bytes
when gzip is on). `synthctl inspect`, `unpack`, and `run` all recompute and
compare before touching the payload; a mismatch aborts with "image corrupt".
The digest is standard SHA-256: `sha256sum` over the payload byte range
produces the same value.

## Content addressing

Unpacked images live at `~/.synthctl/images/<payload-sha256-hex>/`. Same
payload → same directory (dedup). Changed payload → new directory (no
accidental cache poisoning).
