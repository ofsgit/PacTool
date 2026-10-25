# PacTool

**Unpack, inspect, verify and re-pack Spreadtrum / Unisoc `.pac` firmware on Linux.**

A single-file C tool with no dependencies. It started from the idea of [iscle/unpac](https://github.com/iscle/unpac) (unpack-only) and was rewritten against the layout and CRC scheme used by the official Unisoc `unpac.pl`, adding a packer, CRC generation and verification, and hardened parsing.

- Unpack a PAC into its images plus an editable `pac.manifest`
- Pack a directory back into a valid PAC (sizes, offsets, file count and both CRCs are recomputed)
- Untouched unpack followed by pack gives a **byte-identical** PAC
- List the header and file table, or verify size, magic, CRCs and data bounds
- Safe on untrusted PACs: bounds-checked, no path traversal, no symlink following

## Build

```sh
make
sudo install pactool /usr/local/bin/
```

or with CMake:

```sh
mkdir build && cd build
cmake .. && make
```

Requires a C99 compiler and a POSIX system (Linux). Large files (over 4 GiB) are supported.

## Usage

```
pactool unpack [-S] [-f] <file.pac> <outdir>   extract images and write pac.manifest
pactool pack   <outdir|manifest> <out.pac>      build a PAC from a manifest
pactool list   <file.pac>                       show header and file table
pactool verify <file.pac>                       check size, magic, CRC1/CRC2 and data bounds
```

| Option | Applies to | Meaning |
|--------|-----------|---------|
| `-S`   | `unpack`  | Skip CRC verification (same as `unpac.pl -S`) |
| `-f`   | `unpack`  | Force: continue despite size or CRC mismatch |

Exit status is `0` on success and `1` on any error.

### Example

```console
$ pactool list firmware.pac
Version:         BP_R1.0.0
Product:         ...
Files:           8
Magic:           0xFFFAFFFA   CRC1: 0xCA8F   CRC2: 0xEE52

  #  ID             Name              Size  Offset        Flag/Chk/Omit  Addr
  0  FDL            fdl1-sign.bin     9000  0x00000058ec  1/1/0          0x5000
  1  FDL2           fdl2-sign.bin    70000  0x0000007c14  1/1/0          0x9EFFFE00
  ...
```

## Editing firmware

```sh
pactool unpack firmware.pac work/
cp my_boot.img work/boot.img        # replace any image, any size
pactool pack work/ modified.pac
pactool verify modified.pac
```

Keep the original PAC, and always run `verify` on the result.

## pac.manifest

`unpack` writes `pac.manifest` next to the extracted images. It is plain text (`key=value`), strings are UTF-8 (stored as UTF-16LE in the PAC), and control characters and `%` are written as `%XX`.

```ini
[pac]
version=BP_R1.0.0              # max 21 characters
product=...
product_version=...
alias=...
mode=1
flash_type=2
nand_strategy=3
nv_backup=1
nand_page_type=4
oma_dm_product_flag=0
is_oma_dm=0
is_preload=0
magic=0xFFFAFFFA
reserved=<1600 hex digits>     # only written if non-zero

[file]                         # one block per table entry; order is preserved
id=FDL2                        # what the flasher keys on
name=fdl2-sign.bin             # name stored in the PAC (omit: basename of file=)
version=
file=fdl2-sign.bin             # local image; omit for operation-only entries
flag=1                         # 1 = needs a file, 0 = operation only
check_flag=1
can_omit=0
addr_num=1
addr=0x9EFFFE00,0,0,0,0        # up to five load addresses
raw_offset=...                 # preserved for data-less entries with a non-zero offset
reserved=<1992 hex digits>     # only written if non-zero
```

- **Add an image:** add a `[file]` block with `id`, `file`, and any flags or addresses.
- **Remove an image:** delete its block.
- **Defaults:** unspecified numbers are `0`; `flag` defaults to `1` when `file=` is given.
- **Paths:** `file=` must be relative to the manifest's directory (no absolute paths, no `..`).
- `size`, offsets, file count and CRCs are never stored; they are computed on `pack`.

## PAC format

```
offset  size            contents
0       2124            header (magic 0xFFFAFFFA at 2116, wCRC1 at 2120, wCRC2 at 2122)
2124    count x 2580    file table
...                     file data, addressed by 64-bit (hi/lo) offset and size per entry
```

```
CRC     = CRC-16/ARC (poly 0xA001 reflected, init 0, no final xor)
wCRC1   = CRC over bytes [0, 2120)
wCRC2   = CRC over bytes [2124, end of file)
```

Entries with size `0` are operations (for example `FLASH` or `EraseUBOOT`) and carry no data. PACs beginning with `PK\3\4` are ZIP archives; `pactool` detects them and tells you to use `unzip`.

## What's different from iscle/unpac

- Packer, `list`, `verify`, manifest, and CRC checking and generation
- 64-bit sizes and offsets (the original struct's version field swallowed the high words)
- Real UTF-16 handling (surrogates, non-ASCII names) instead of truncating to `char`
- Bounds-checked parsing: implausible counts and out-of-range or table-overlapping offsets are rejected
- Output names are reduced to a safe basename, duplicates become `name(1)`, and files are created with `O_EXCL | O_NOFOLLOW`, so nothing is written outside the output directory and symlinks are not followed
- Streaming I/O instead of `mmap`; `pack` writes `out.pac.tmp` and renames it on success

## Testing

```sh
tests/run_tests.sh [path/to/official/unpac.pl]
```

Builds with ASAN/UBSAN and checks:

- CRCs from an independent Python PAC generator (`tests/make_test_pac.py`, no shared code with the C) verify
- unpack followed by pack is byte-identical
- Corruption is detected and `-S` bypasses the check
- Path traversal in hostile filenames is contained
- Optionally, the official Unisoc `unpac.pl` accepts a repacked PAC with CRC checking on

Tested against synthetic PACs and the official tool's behavior, not against PACs from every chipset. Please open an issue if a real-world PAC fails to unpack, verify, or round-trip.

## Disclaimer

A repacked PAC is only as good as the images and addresses you put in it. Flashing wrong partition images or load addresses can brick a device. Use at your own risk and keep the original firmware.

## Credits

- [@iscle](https://github.com/iscle) ([iscle/unpac](https://github.com/iscle/unpac)) for the original unpacker this grew out of
- The official Unisoc `unpac.pl` for the reference layout and CRC algorithm
