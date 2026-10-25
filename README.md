# pactool

Unpack, inspect, verify and **re-pack** Spreadtrum/Unisoc `.pac` firmware on Linux.
Single C file, no dependencies. Built on the idea of [iscle/unpac](https://github.com/iscle/unpac)
(unpack-only), rewritten against the layout and CRC scheme of the official Unisoc `unpac.pl`.

## Build

    make                      # or: mkdir build && cd build && cmake .. && make
    sudo install pactool /usr/local/bin/

## Usage

    pactool unpack [-S] [-f] <file.pac> <outdir>   extract images + write pac.manifest
    pactool pack   <outdir|manifest> <out.pac>      build a PAC
    pactool list   <file.pac>                       header + file table
    pactool verify <file.pac>                       size, magic, CRC1/CRC2, data bounds

`-S` skips CRC verification (like `unpac.pl -S`), `-f` continues despite size/CRC mismatch.

### Typical edit workflow

    pactool unpack firmware.pac work/
    cp my_boot.img work/boot.img        # replace any image, any size
    pactool pack work/ modified.pac
    pactool verify modified.pac

File count, sizes, offsets, total size and both CRCs are recomputed on `pack`.
An untouched `unpack` -> `pack` reproduces the original PAC byte for byte (for PACs laid out
canonically, i.e. data contiguous in table order, which is how the vendor tools write them).

## pac.manifest

Plain text, `key=value`, `%XX` escapes for control chars and `%`. Strings are UTF-8 (stored as UTF-16LE).

    [pac]
    version=BP_R1.0.0          # max 21 chars
    product=...  product_version=...  alias=...
    mode= flash_type= nand_strategy= nv_backup= nand_page_type=
    oma_dm_product_flag= is_oma_dm= is_preload= magic=0xFFFAFFFA
    reserved=<1600 hex>        # only written if non-zero

    [file]                     # one block per table entry, order is preserved
    id=FDL2                    # what the flasher keys on
    name=fdl2-sign.bin         # szFileName stored in the PAC (omit => basename of file=)
    version=
    file=fdl2-sign.bin         # local image; omit for operation-only entries (FLASH, Erase...)
    flag=1                     # 1 = needs a file, 0 = operation only (defaults to 1 if file= given)
    check_flag=1  can_omit=0
    addr_num=1
    addr=0x9EFFFE00,0,0,0,0
    raw_offset=...             # kept for data-less entries that carry a non-zero offset
    reserved=<1992 hex>        # only written if non-zero

New image = add a `[file]` block. Remove an image = delete its block. `file=` must be a relative path
inside the manifest's directory (no `..`, no absolute paths).

## Format notes

    header     2124 B   magic 0xFFFAFFFA at 2116, wCRC1 at 2120, wCRC2 at 2122
    entries    count x 2580 B directly after the header
    data       referenced by 64-bit (hi/lo) offset+size per entry

    CRC = CRC-16/ARC (poly 0xA001 reflected, init 0, no final xor)
    wCRC1 = CRC over bytes [0, 2120)        wCRC2 = CRC over [2124, EOF)

Entries with size 0 are *operations* (e.g. `FLASH`, `EraseUBOOT`) and have no data file.
PACs that start with `PK\3\4` are ZIP archives; use `unzip` (pactool tells you).

## Differences from iscle/unpac

- packer, `list`, `verify`, manifest, CRC check/generation
- 64-bit sizes/offsets (the "version" field in unpac's struct actually swallowed the hi words)
- real UTF-16 handling (surrogates, non-ASCII names) instead of truncating to `char`
- bounds-checked: bad counts/offsets can't read out of range; names are reduced to a safe basename,
  duplicates become `name(1)`, output files are created with `O_EXCL|O_NOFOLLOW` (no symlink following,
  no writes outside the output dir, `pac.manifest` can't be clobbered)
- streaming I/O instead of mmap (works on large PACs, 32-bit too), pack writes to `out.pac.tmp` then renames

## Testing

`tests/run_tests.sh [path/to/official/unpac.pl]` builds with ASAN/UBSAN and checks: independent generator
(`tests/make_test_pac.py`, shares no code with the C) -> verify, unpack -> pack byte-identical,
corruption detection, path-traversal containment, and (optionally) that the official Perl unpacker
accepts a repacked PAC with CRC checking on.

Tested only against synthetic PACs and the official tool's behaviour, not against a PAC from every
chipset. **Run `pactool verify` and a plain `unpack` -> `pack` -> `cmp` on your own PAC first.**
A repacked PAC is only as good as what you put in it: wrong partition images or addresses can brick a device.
