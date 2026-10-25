/*
 * pactool - Spreadtrum / Unisoc ".pac" firmware unpacker and packer for Linux
 *
 * Based on iscle/unpac (struct layout idea), rewritten against the layout and
 * CRC scheme used by the official Unisoc unpac.pl:
 *
 *   header      2124 bytes  (magic 0xFFFAFFFA, wCRC1, wCRC2 at the end)
 *   file table  nFileCount * 2580 bytes, directly after the header
 *   file data   referenced by 64-bit offset/size pairs from the table
 *
 *   wCRC1 = CRC-16/ARC (poly 0xA001 reflected, seed 0) over bytes 0..2119
 *   wCRC2 = same CRC over every byte from 2124 to the end of the file
 *
 * Commands:
 *   pactool unpack [-S] [-f] <file.pac> <outdir>   extract images + pac.manifest
 *   pactool pack   <outdir|manifest> <out.pac>     build a PAC from a manifest
 *   pactool list   <file.pac>                      show header and file table
 *   pactool verify <file.pac>                      check size, magic, CRCs, bounds
 */

#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ------------------------------------------------------------------ */
/* On-disk layout                                                      */
/* ------------------------------------------------------------------ */

#define PAC_MAGIC        0xFFFAFFFAu
#define PAC_HEADER_SIZE  2124
#define PAC_ENTRY_SIZE   2580
#define PAC_CRC_COVERED  2120          /* wCRC1 covers bytes [0, 2120) */
#define MAX_ENTRIES      8192          /* sanity cap; real PACs have < 100 */

/* header field offsets */
#define H_VERSION        0             /* 44 bytes, UTF-16LE */
#define H_HISIZE         44
#define H_LOSIZE         48
#define H_PRDNAME        52            /* 512 */
#define H_PRDVER         564           /* 512 */
#define H_FILECOUNT      1076
#define H_FILEOFFSET     1080
#define H_MODE           1084
#define H_FLASHTYPE      1088
#define H_NANDSTRATEGY   1092
#define H_NVBACKUP       1096
#define H_NANDPAGETYPE   1100
#define H_ALIAS          1104          /* 200 */
#define H_OMADMFLAG      1304
#define H_ISOMADM        1308
#define H_ISPRELOAD      1312
#define H_RESERVED       1316          /* 800 */
#define H_MAGIC          2116
#define H_CRC1           2120
#define H_CRC2           2122

/* file table entry field offsets */
#define E_SIZE           0
#define E_ID             4             /* 512 */
#define E_NAME           516           /* 512 */
#define E_VERSION        1028          /* 504 */
#define E_HISIZE         1532
#define E_HIOFFSET       1536
#define E_LOSIZE         1540
#define E_FLAG           1544
#define E_CHECK          1548
#define E_LOOFFSET       1552
#define E_OMIT           1556
#define E_ADDRNUM        1560
#define E_ADDR           1564          /* 5 x u32 */
#define E_RESERVED       1584          /* 996 */

#define STRBUF           1024
#define MANIFEST_NAME    "pac.manifest"
#define IOBUF_SIZE       (1u << 20)

static uint8_t *iobuf;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static void err(const char *fmt, ...)
{
    va_list ap;
    fputs("pactool: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void warn(const char *fmt, ...)
{
    va_list ap;
    fputs("pactool: warning: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static int all_zero(const uint8_t *p, size_t n)
{
    while (n--) if (*p++) return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* CRC-16/ARC (same as the table in the official unpac.pl)             */
/* ------------------------------------------------------------------ */

static uint16_t crc_table[256];

static void crc_init(void)
{
    for (unsigned i = 0; i < 256; i++) {
        uint16_t c = (uint16_t)i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (uint16_t)((c >> 1) ^ 0xA001) : (uint16_t)(c >> 1);
        crc_table[i] = c;
    }
}

static uint16_t crc16(uint16_t crc, const uint8_t *buf, size_t n)
{
    while (n--)
        crc = (uint16_t)((crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xFF]);
    return crc;
}

/* CRC over [start, start+len) of f */
static int crc_stream(FILE *f, uint64_t start, uint64_t len, uint16_t *crc)
{
    uint16_t c = 0;
    if (fseeko(f, (off_t)start, SEEK_SET) != 0) return -1;
    while (len) {
        size_t n = len > IOBUF_SIZE ? IOBUF_SIZE : (size_t)len;
        if (fread(iobuf, 1, n, f) != n) return -1;
        c = crc16(c, iobuf, n);
        len -= n;
    }
    *crc = c;
    return 0;
}

/* ------------------------------------------------------------------ */
/* UTF-16LE <-> UTF-8                                                  */
/* ------------------------------------------------------------------ */

/* Decode a (possibly unterminated) UTF-16LE field. out must hold >= nbytes*2+1 */
static void utf16le_to_utf8(const uint8_t *src, size_t nbytes, char *out)
{
    size_t units = nbytes / 2, o = 0;
    for (size_t i = 0; i < units; i++) {
        uint32_t c = rd16(src + 2 * i);
        if (!c) break;
        if (c >= 0xD800 && c <= 0xDBFF) {
            uint32_t d = (i + 1 < units) ? rd16(src + 2 * (i + 1)) : 0;
            if (d >= 0xDC00 && d <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
                i++;
            } else {
                c = 0xFFFD;
            }
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            c = 0xFFFD;
        }
        if (c < 0x80) {
            out[o++] = (char)c;
        } else if (c < 0x800) {
            out[o++] = (char)(0xC0 | (c >> 6));
            out[o++] = (char)(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out[o++] = (char)(0xE0 | (c >> 12));
            out[o++] = (char)(0x80 | ((c >> 6) & 0x3F));
            out[o++] = (char)(0x80 | (c & 0x3F));
        } else {
            out[o++] = (char)(0xF0 | (c >> 18));
            out[o++] = (char)(0x80 | ((c >> 12) & 0x3F));
            out[o++] = (char)(0x80 | ((c >> 6) & 0x3F));
            out[o++] = (char)(0x80 | (c & 0x3F));
        }
    }
    out[o] = 0;
}

/* Encode UTF-8 into a zero-filled UTF-16LE field of dstbytes (NUL-terminated).
 * Invalid UTF-8 becomes U+FFFD. Returns -1 if it does not fit. */
static int utf8_to_utf16le(const char *s, uint8_t *dst, size_t dstbytes)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t maxunits = dstbytes / 2 - 1, n = 0;
    memset(dst, 0, dstbytes);
    while (*p) {
        uint32_t c;
        int len;
        if (p[0] < 0x80) {
            c = p[0]; len = 1;
        } else if ((p[0] & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
            c = ((uint32_t)(p[0] & 0x1F) << 6) | (p[1] & 0x3F); len = 2;
            if (c < 0x80) c = 0xFFFD;
        } else if ((p[0] & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
            c = ((uint32_t)(p[0] & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F); len = 3;
            if (c < 0x800 || (c >= 0xD800 && c <= 0xDFFF)) c = 0xFFFD;
        } else if ((p[0] & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 &&
                   (p[3] & 0xC0) == 0x80) {
            c = ((uint32_t)(p[0] & 0x07) << 18) | ((uint32_t)(p[1] & 0x3F) << 12) |
                ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
            len = 4;
            if (c < 0x10000 || c > 0x10FFFF) c = 0xFFFD;
        } else {
            c = 0xFFFD; len = 1;
        }
        p += len;
        if (c >= 0x10000) {
            if (n + 2 > maxunits) return -1;
            c -= 0x10000;
            wr16(dst + 2 * n, (uint16_t)(0xD800 + (c >> 10)));
            wr16(dst + 2 * (n + 1), (uint16_t)(0xDC00 + (c & 0x3FF)));
            n += 2;
        } else {
            if (n + 1 > maxunits) return -1;
            wr16(dst + 2 * n, (uint16_t)c);
            n++;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Parsed structures                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    char version[STRBUF], product[STRBUF], product_version[STRBUF], alias[STRBUF];
    uint32_t mode, flash_type, nand_strategy, nv_backup, nand_page_type;
    uint32_t oma_dm_flag, is_oma_dm, is_preload, magic;
    uint8_t reserved[800];
} PacInfo;

typedef struct {
    char id[STRBUF], name[STRBUF], version[STRBUF];
    char file[STRBUF];                 /* local file (manifest only) */
    uint32_t flag, check_flag, can_omit, addr_num, addr[5];
    uint64_t size, offset;
    uint8_t reserved[996];
    int flag_set, name_set;            /* manifest parsing helpers */
} PacEntry;

static void parse_entry(const uint8_t *e, PacEntry *pe)
{
    memset(pe, 0, sizeof *pe);
    utf16le_to_utf8(e + E_ID, 512, pe->id);
    utf16le_to_utf8(e + E_NAME, 512, pe->name);
    utf16le_to_utf8(e + E_VERSION, 504, pe->version);
    pe->size = ((uint64_t)rd32(e + E_HISIZE) << 32) | rd32(e + E_LOSIZE);
    pe->offset = ((uint64_t)rd32(e + E_HIOFFSET) << 32) | rd32(e + E_LOOFFSET);
    pe->flag = rd32(e + E_FLAG);
    pe->check_flag = rd32(e + E_CHECK);
    pe->can_omit = rd32(e + E_OMIT);
    pe->addr_num = rd32(e + E_ADDRNUM);
    for (int i = 0; i < 5; i++) pe->addr[i] = rd32(e + E_ADDR + 4 * i);
    memcpy(pe->reserved, e + E_RESERVED, sizeof pe->reserved);
}

static int put_str16(uint8_t *dst, size_t cap, const char *s, const char *what, int idx)
{
    if (utf8_to_utf16le(s, dst, cap) < 0) {
        if (idx >= 0) err("entry %d: %s is too long for the PAC format (max %zu UTF-16 units)", idx, what, cap / 2 - 1);
        else err("%s is too long for the PAC format (max %zu UTF-16 units)", what, cap / 2 - 1);
        return -1;
    }
    return 0;
}

static int build_entry(uint8_t *e, const PacEntry *pe, int idx)
{
    memset(e, 0, PAC_ENTRY_SIZE);
    wr32(e + E_SIZE, PAC_ENTRY_SIZE);
    if (put_str16(e + E_ID, 512, pe->id, "id", idx) ||
        put_str16(e + E_NAME, 512, pe->name, "name", idx) ||
        put_str16(e + E_VERSION, 504, pe->version, "version", idx))
        return -1;
    wr32(e + E_HISIZE, (uint32_t)(pe->size >> 32));
    wr32(e + E_LOSIZE, (uint32_t)pe->size);
    wr32(e + E_HIOFFSET, (uint32_t)(pe->offset >> 32));
    wr32(e + E_LOOFFSET, (uint32_t)pe->offset);
    wr32(e + E_FLAG, pe->flag);
    wr32(e + E_CHECK, pe->check_flag);
    wr32(e + E_OMIT, pe->can_omit);
    wr32(e + E_ADDRNUM, pe->addr_num);
    for (int i = 0; i < 5; i++) wr32(e + E_ADDR + 4 * i, pe->addr[i]);
    memcpy(e + E_RESERVED, pe->reserved, sizeof pe->reserved);
    return 0;
}

static int build_header(uint8_t *h, const PacInfo *pi, uint64_t total, uint32_t count)
{
    memset(h, 0, PAC_HEADER_SIZE);
    if (put_str16(h + H_VERSION, 44, pi->version, "[pac] version", -1) ||
        put_str16(h + H_PRDNAME, 512, pi->product, "[pac] product", -1) ||
        put_str16(h + H_PRDVER, 512, pi->product_version, "[pac] product_version", -1) ||
        put_str16(h + H_ALIAS, 200, pi->alias, "[pac] alias", -1))
        return -1;
    wr32(h + H_HISIZE, (uint32_t)(total >> 32));
    wr32(h + H_LOSIZE, (uint32_t)total);
    wr32(h + H_FILECOUNT, count);
    wr32(h + H_FILEOFFSET, PAC_HEADER_SIZE);
    wr32(h + H_MODE, pi->mode);
    wr32(h + H_FLASHTYPE, pi->flash_type);
    wr32(h + H_NANDSTRATEGY, pi->nand_strategy);
    wr32(h + H_NVBACKUP, pi->nv_backup);
    wr32(h + H_NANDPAGETYPE, pi->nand_page_type);
    wr32(h + H_OMADMFLAG, pi->oma_dm_flag);
    wr32(h + H_ISOMADM, pi->is_oma_dm);
    wr32(h + H_ISPRELOAD, pi->is_preload);
    memcpy(h + H_RESERVED, pi->reserved, sizeof pi->reserved);
    wr32(h + H_MAGIC, pi->magic);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Opening / validating an existing PAC                                */
/* ------------------------------------------------------------------ */

typedef struct {
    FILE *f;
    uint64_t size, declared_size;
    uint8_t hdr[PAC_HEADER_SIZE];
    PacInfo info;
    uint32_t count, tbl_off;
    uint16_t crc1, crc2;
    uint8_t *table;
} PacFile;

static void pac_close(PacFile *p)
{
    if (p->f) fclose(p->f);
    free(p->table);
    memset(p, 0, sizeof *p);
}

static int pac_open(PacFile *p, const char *path, int force)
{
    memset(p, 0, sizeof *p);
    p->f = fopen(path, "rb");
    if (!p->f) { err("cannot open %s: %s", path, strerror(errno)); return -1; }
    if (fseeko(p->f, 0, SEEK_END) != 0) { err("cannot seek in %s", path); goto fail; }
    off_t end = ftello(p->f);
    if (end < 0) { err("cannot determine size of %s", path); goto fail; }
    p->size = (uint64_t)end;
    if (p->size < PAC_HEADER_SIZE) {
        err("%s is too small to be a PAC (%llu bytes)", path, (unsigned long long)p->size);
        goto fail;
    }
    if (fseeko(p->f, 0, SEEK_SET) != 0 || fread(p->hdr, 1, PAC_HEADER_SIZE, p->f) != PAC_HEADER_SIZE) {
        err("cannot read header of %s", path);
        goto fail;
    }
    if (!memcmp(p->hdr, "PK\x03\x04", 4)) {
        err("%s is a ZIP-based PAC; extract it with 'unzip' instead", path);
        goto fail;
    }

    const uint8_t *h = p->hdr;
    PacInfo *pi = &p->info;
    utf16le_to_utf8(h + H_VERSION, 44, pi->version);
    utf16le_to_utf8(h + H_PRDNAME, 512, pi->product);
    utf16le_to_utf8(h + H_PRDVER, 512, pi->product_version);
    utf16le_to_utf8(h + H_ALIAS, 200, pi->alias);
    p->declared_size = ((uint64_t)rd32(h + H_HISIZE) << 32) | rd32(h + H_LOSIZE);
    p->count = rd32(h + H_FILECOUNT);
    p->tbl_off = rd32(h + H_FILEOFFSET);
    pi->mode = rd32(h + H_MODE);
    pi->flash_type = rd32(h + H_FLASHTYPE);
    pi->nand_strategy = rd32(h + H_NANDSTRATEGY);
    pi->nv_backup = rd32(h + H_NVBACKUP);
    pi->nand_page_type = rd32(h + H_NANDPAGETYPE);
    pi->oma_dm_flag = rd32(h + H_OMADMFLAG);
    pi->is_oma_dm = rd32(h + H_ISOMADM);
    pi->is_preload = rd32(h + H_ISPRELOAD);
    pi->magic = rd32(h + H_MAGIC);
    memcpy(pi->reserved, h + H_RESERVED, sizeof pi->reserved);
    p->crc1 = rd16(h + H_CRC1);
    p->crc2 = rd16(h + H_CRC2);

    if (p->declared_size != p->size) {
        if (!force) {
            err("size in header (%llu) does not match file size (%llu); file truncated or damaged (-f to ignore)",
                (unsigned long long)p->declared_size, (unsigned long long)p->size);
            goto fail;
        }
        warn("size in header (%llu) != file size (%llu)", (unsigned long long)p->declared_size,
             (unsigned long long)p->size);
    }
    if (p->info.magic != PAC_MAGIC)
        warn("unexpected magic 0x%08X (expected 0x%08X)", p->info.magic, PAC_MAGIC);
    if (p->tbl_off != PAC_HEADER_SIZE)
        warn("header says file table is at %u; using %d like the official tool", p->tbl_off, PAC_HEADER_SIZE);
    if (p->count > MAX_ENTRIES || (uint64_t)p->count * PAC_ENTRY_SIZE > p->size - PAC_HEADER_SIZE) {
        err("implausible file count %u for a %llu byte file", p->count, (unsigned long long)p->size);
        goto fail;
    }
    p->table = malloc((size_t)p->count * PAC_ENTRY_SIZE + 1);
    if (!p->table) { err("out of memory"); goto fail; }
    if (fseeko(p->f, PAC_HEADER_SIZE, SEEK_SET) != 0 ||
        fread(p->table, 1, (size_t)p->count * PAC_ENTRY_SIZE, p->f) != (size_t)p->count * PAC_ENTRY_SIZE) {
        err("cannot read file table");
        goto fail;
    }
    return 0;
fail:
    pac_close(p);
    return -1;
}

static int pac_check_crc(PacFile *p, int force)
{
    int bad = 0;
    if (p->info.magic == PAC_MAGIC) {      /* official tool skips CRC1 otherwise */
        uint16_t c1 = crc16(0, p->hdr, PAC_CRC_COVERED);
        if (c1 != p->crc1) {
            err("CRC1 (header) mismatch: stored 0x%04X, computed 0x%04X", p->crc1, c1);
            bad = 1;
        }
    }
    uint16_t c2;
    if (crc_stream(p->f, PAC_HEADER_SIZE, p->size - PAC_HEADER_SIZE, &c2) < 0) {
        err("read error while computing CRC2");
        return -1;
    }
    if (c2 != p->crc2) {
        err("CRC2 (table+data) mismatch: stored 0x%04X, computed 0x%04X", p->crc2, c2);
        bad = 1;
    }
    if (bad) {
        if (!force) return -1;
        warn("continuing despite CRC errors (-f)");
    }
    return 0;
}

/* data range of an entry must lie inside the file and past the file table */
static int entry_in_bounds(const PacFile *p, const PacEntry *e)
{
    uint64_t data_start = PAC_HEADER_SIZE + (uint64_t)p->count * PAC_ENTRY_SIZE;
    if (e->size == 0) return 1;
    if (e->offset < data_start) return 0;
    if (e->offset > p->size || e->size > p->size - e->offset) return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* File name handling for extraction                                   */
/* ------------------------------------------------------------------ */

static void sanitize_name(const char *in, char *out, size_t cap)
{
    const char *base = in, *p;
    size_t o = 0;
    for (p = in; *p; p++)
        if (*p == '/' || *p == '\\') base = p + 1;
    for (p = base; *p && o + 1 < cap; p++) {
        unsigned char c = (unsigned char)*p;
        out[o++] = (c < 0x20 || c == 0x7F) ? '_' : (char)c;
    }
    out[o] = 0;
    if (!strcmp(out, ".") || !strcmp(out, "..")) out[0] = 0;
    if (strlen(out) > 200) {
        size_t n = 200;
        while (n > 0 && (((unsigned char)out[n]) & 0xC0) == 0x80) n--;
        out[n] = 0;
    }
}

static int name_used(char **used, size_t n, const char *name)
{
    for (size_t i = 0; i < n; i++)
        if (!strcmp(used[i], name)) return 1;
    return 0;
}

static void make_disk_name(const PacEntry *e, uint32_t idx, char **used, size_t nused, char *out, size_t cap)
{
    char base[320];                    /* sanitize_name() caps names at 200 bytes */
    sanitize_name(e->name, base, sizeof base);
    if (!base[0]) {
        char idpart[256];
        sanitize_name(e->id, idpart, sizeof idpart);
        if (idpart[0]) snprintf(base, sizeof base, "%s.bin", idpart);
        else snprintf(base, sizeof base, "entry_%u.bin", idx);
    }
    snprintf(out, cap, "%s", base);
    for (int k = 1; name_used(used, nused, out); k++)
        snprintf(out, cap, "%s(%d)", base, k);   /* same scheme as the official tool */
}

static int mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    struct stat st;
    if (len == 0 || len >= sizeof tmp) { errno = EINVAL; return -1; }
    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return -1;
    if (stat(tmp, &st) < 0) return -1;
    if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
    return 0;
}

static int join_path(char *dst, size_t cap, const char *a, const char *b)
{
    int n = snprintf(dst, cap, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* create a fresh regular file; never follows an existing symlink */
static FILE *create_outfile(const char *path)
{
    if (unlink(path) < 0 && errno != ENOENT) return NULL;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "wb");
    if (!f) close(fd);
    return f;
}

static int copy_range(FILE *in, uint64_t off, uint64_t len, FILE *out)
{
    if (fseeko(in, (off_t)off, SEEK_SET) != 0) return -1;
    while (len) {
        size_t n = len > IOBUF_SIZE ? IOBUF_SIZE : (size_t)len;
        if (fread(iobuf, 1, n, in) != n) return -1;
        if (fwrite(iobuf, 1, n, out) != n) return -1;
        len -= n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Manifest writing                                                    */
/* ------------------------------------------------------------------ */

static void esc_write(FILE *f, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7F || c == '%') fprintf(f, "%%%02X", c);
        else fputc(c, f);
    }
}

static void kv_str(FILE *f, const char *k, const char *v)
{
    fprintf(f, "%s=", k);
    esc_write(f, v);
    fputc('\n', f);
}

static void kv_hex(FILE *f, const char *k, const uint8_t *b, size_t n)
{
    fprintf(f, "%s=", k);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fputc('\n', f);
}

static void manifest_write_header(FILE *m, const PacInfo *pi)
{
    fputs("# pactool manifest. Edit values, replace image files, then run:\n"
          "#   pactool pack <this directory> <new.pac>\n"
          "# Sizes, offsets, file count and both CRCs are recomputed when packing.\n\n"
          "[pac]\n", m);
    kv_str(m, "version", pi->version);
    kv_str(m, "product", pi->product);
    kv_str(m, "product_version", pi->product_version);
    kv_str(m, "alias", pi->alias);
    fprintf(m, "mode=%u\nflash_type=%u\nnand_strategy=%u\nnv_backup=%u\nnand_page_type=%u\n",
            pi->mode, pi->flash_type, pi->nand_strategy, pi->nv_backup, pi->nand_page_type);
    fprintf(m, "oma_dm_product_flag=%u\nis_oma_dm=%u\nis_preload=%u\nmagic=0x%08X\n",
            pi->oma_dm_flag, pi->is_oma_dm, pi->is_preload, pi->magic);
    if (!all_zero(pi->reserved, sizeof pi->reserved)) kv_hex(m, "reserved", pi->reserved, sizeof pi->reserved);
}

static void manifest_write_entry(FILE *m, uint32_t idx, const PacEntry *e, const char *diskname)
{
    fprintf(m, "\n[file]\n# entry %u, %llu bytes\n", idx, (unsigned long long)e->size);
    kv_str(m, "id", e->id);
    kv_str(m, "name", e->name);
    kv_str(m, "version", e->version);
    if (diskname) kv_str(m, "file", diskname);
    else if (e->offset) fprintf(m, "raw_offset=%llu\n", (unsigned long long)e->offset);
    fprintf(m, "flag=%u\ncheck_flag=%u\ncan_omit=%u\naddr_num=%u\n", e->flag, e->check_flag, e->can_omit, e->addr_num);
    fprintf(m, "addr=0x%X,0x%X,0x%X,0x%X,0x%X\n", e->addr[0], e->addr[1], e->addr[2], e->addr[3], e->addr[4]);
    if (!all_zero(e->reserved, sizeof e->reserved)) kv_hex(m, "reserved", e->reserved, sizeof e->reserved);
}

/* ------------------------------------------------------------------ */
/* Manifest parsing                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    PacInfo info;
    PacEntry *e;
    size_t n, cap;
} Manifest;

static int parse_u32(const char *s, uint32_t *out)
{
    char *end;
    int base = (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10;
    unsigned long long v;
    if (!*s) return -1;
    errno = 0;
    v = strtoull(s, &end, base);
    if (errno || *end || v > 0xFFFFFFFFull) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int unescape(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%') {
            int hi, lo;
            if (!r[1] || !r[2]) return -1;
            hi = (r[1] >= '0' && r[1] <= '9') ? r[1] - '0' : (r[1] | 0x20) - 'a' + 10;
            lo = (r[2] >= '0' && r[2] <= '9') ? r[2] - '0' : (r[2] | 0x20) - 'a' + 10;
            if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
            *w++ = (char)(hi * 16 + lo);
            r += 2;
        } else {
            *w++ = *r;
        }
    }
    *w = 0;
    return 0;
}

static int parse_hex(const char *s, uint8_t *out, size_t n)
{
    if (strlen(s) != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        int v[2];
        for (int k = 0; k < 2; k++) {
            char c = s[2 * i + k];
            if (c >= '0' && c <= '9') v[k] = c - '0';
            else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') v[k] = (c | 0x20) - 'a' + 10;
            else return -1;
        }
        out[i] = (uint8_t)(v[0] * 16 + v[1]);
    }
    return 0;
}

static int set_str(char *dst, const char *val)
{
    if (strlen(val) >= STRBUF) return -1;
    strcpy(dst, val);
    return 0;
}

static int manifest_parse(const char *path, Manifest *m)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t lcap = 0;
    ssize_t len;
    int lineno = 0, section = 0, rc = 0;

    memset(m, 0, sizeof *m);
    strcpy(m->info.version, "BP_R1.0.0");
    m->info.magic = PAC_MAGIC;
    if (!f) { err("cannot open %s: %s", path, strerror(errno)); return -1; }

    while (rc == 0 && (len = getline(&line, &lcap, f)) >= 0) {
        char *key, *val, *eq;
        lineno++;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
        if (!line[0] || line[0] == '#') continue;
        if (!strcmp(line, "[pac]")) { section = 1; continue; }
        if (!strcmp(line, "[file]")) {
            if (m->n == MAX_ENTRIES) { err("%s:%d: too many [file] entries", path, lineno); rc = -1; break; }
            if (m->n == m->cap) {
                size_t nc = m->cap ? m->cap * 2 : 16;
                PacEntry *ne = realloc(m->e, nc * sizeof *ne);
                if (!ne) { err("out of memory"); rc = -1; break; }
                m->e = ne; m->cap = nc;
            }
            memset(&m->e[m->n++], 0, sizeof *m->e);
            section = 2;
            continue;
        }
        eq = strchr(line, '=');
        if (!eq || !section) { err("%s:%d: syntax error", path, lineno); rc = -1; break; }
        *eq = 0;
        key = line;
        val = eq + 1;
        while (*key == ' ' || *key == '\t') key++;
        for (char *k = key + strlen(key); k > key && (k[-1] == ' ' || k[-1] == '\t'); ) *--k = 0;
        if (unescape(val) < 0) { err("%s:%d: bad %%-escape", path, lineno); rc = -1; break; }

#define NUMKEY(name, field) \
        else if (!strcmp(key, name)) { \
            if (parse_u32(val, &(field))) { err("%s:%d: bad number for '%s'", path, lineno, key); rc = -1; } }
#define STRKEY(name, field) \
        else if (!strcmp(key, name)) { \
            if (set_str(field, val)) { err("%s:%d: value of '%s' too long", path, lineno, key); rc = -1; } }

        if (section == 1) {
            PacInfo *pi = &m->info;
            if (0) {}
            STRKEY("version", pi->version)
            STRKEY("product", pi->product)
            STRKEY("product_version", pi->product_version)
            STRKEY("alias", pi->alias)
            NUMKEY("mode", pi->mode)
            NUMKEY("flash_type", pi->flash_type)
            NUMKEY("nand_strategy", pi->nand_strategy)
            NUMKEY("nv_backup", pi->nv_backup)
            NUMKEY("nand_page_type", pi->nand_page_type)
            NUMKEY("oma_dm_product_flag", pi->oma_dm_flag)
            NUMKEY("is_oma_dm", pi->is_oma_dm)
            NUMKEY("is_preload", pi->is_preload)
            NUMKEY("magic", pi->magic)
            else if (!strcmp(key, "reserved")) {
                if (parse_hex(val, pi->reserved, sizeof pi->reserved)) {
                    err("%s:%d: 'reserved' must be %zu hex digits", path, lineno, sizeof pi->reserved * 2);
                    rc = -1;
                }
            } else {
                warn("%s:%d: unknown [pac] key '%s' ignored", path, lineno, key);
            }
        } else {
            PacEntry *e = &m->e[m->n - 1];
            if (0) {}
            STRKEY("id", e->id)
            else if (!strcmp(key, "name")) {
                if (set_str(e->name, val)) { err("%s:%d: value of 'name' too long", path, lineno); rc = -1; }
                e->name_set = 1;
            }
            STRKEY("version", e->version)
            STRKEY("file", e->file)
            NUMKEY("check_flag", e->check_flag)
            NUMKEY("can_omit", e->can_omit)
            NUMKEY("addr_num", e->addr_num)
            else if (!strcmp(key, "flag")) {
                if (parse_u32(val, &e->flag)) { err("%s:%d: bad number for 'flag'", path, lineno); rc = -1; }
                e->flag_set = 1;
            } else if (!strcmp(key, "raw_offset")) {
                char *end;
                errno = 0;
                e->offset = strtoull(val, &end, 10);
                if (errno || *end || !*val) { err("%s:%d: bad number for 'raw_offset'", path, lineno); rc = -1; }
            } else if (!strcmp(key, "addr")) {
                char *tok, *save = NULL;
                int i = 0;
                for (tok = strtok_r(val, ",", &save); tok && i < 5; tok = strtok_r(NULL, ",", &save), i++) {
                    while (*tok == ' ') tok++;
                    if (parse_u32(tok, &e->addr[i])) { err("%s:%d: bad address '%s'", path, lineno, tok); rc = -1; break; }
                }
                if (rc == 0 && tok) { err("%s:%d: at most 5 addresses", path, lineno); rc = -1; }
            } else if (!strcmp(key, "reserved")) {
                if (parse_hex(val, e->reserved, sizeof e->reserved)) {
                    err("%s:%d: 'reserved' must be %zu hex digits", path, lineno, sizeof e->reserved * 2);
                    rc = -1;
                }
            } else {
                warn("%s:%d: unknown [file] key '%s' ignored", path, lineno, key);
            }
        }
#undef NUMKEY
#undef STRKEY
    }
    free(line);
    fclose(f);
    if (rc == 0 && m->n == 0) { err("%s: no [file] entries", path); rc = -1; }
    if (rc) { free(m->e); m->e = NULL; }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static void print_info(const PacFile *p)
{
    const PacInfo *pi = &p->info;
    printf("Version:         %s\n", pi->version);
    printf("Product:         %s\n", pi->product);
    printf("Product version: %s\n", pi->product_version);
    printf("Alias:           %s\n", pi->alias);
    printf("Size:            %llu bytes\n", (unsigned long long)p->declared_size);
    printf("Files:           %u\n", p->count);
    printf("Mode/Flash/Nand: %u / %u / %u (strategy), page type %u, NV backup %u\n", pi->mode, pi->flash_type,
           pi->nand_strategy, pi->nand_page_type, pi->nv_backup);
    printf("Magic:           0x%08X   CRC1: 0x%04X   CRC2: 0x%04X\n\n", pi->magic, p->crc1, p->crc2);
}

static int cmd_list(const char *path)
{
    PacFile p;
    if (pac_open(&p, path, 1) < 0) return 1;
    print_info(&p);
    printf("%3s  %-14s %-30s %12s  %-12s %s\n", "#", "ID", "Name", "Size", "Offset", "Flag/Chk/Omit  Addr");
    for (uint32_t i = 0; i < p.count; i++) {
        PacEntry e;
        char addr[24] = "-";
        parse_entry(p.table + (size_t)i * PAC_ENTRY_SIZE, &e);
        if (e.addr_num) snprintf(addr, sizeof addr, "0x%X", e.addr[0]);
        printf("%3u  %-14s %-30s %12llu  0x%010llx  %u/%u/%u  %s%s\n", i, e.id, e.name,
               (unsigned long long)e.size, (unsigned long long)e.offset, e.flag, e.check_flag, e.can_omit, addr,
               entry_in_bounds(&p, &e) ? "" : "  [OUT OF BOUNDS]");
    }
    pac_close(&p);
    return 0;
}

static int cmd_verify(const char *path)
{
    PacFile p;
    int bad = 0;
    if (pac_open(&p, path, 0) < 0) return 1;
    if (pac_check_crc(&p, 0) < 0) bad = 1;
    for (uint32_t i = 0; i < p.count; i++) {
        PacEntry e;
        parse_entry(p.table + (size_t)i * PAC_ENTRY_SIZE, &e);
        if (!entry_in_bounds(&p, &e)) {
            err("entry %u (%s): data range [%llu, +%llu) lies outside the file or inside the table", i, e.name,
                (unsigned long long)e.offset, (unsigned long long)e.size);
            bad = 1;
        }
    }
    if (!bad) printf("OK: %s (%u files, %llu bytes, CRC1 0x%04X, CRC2 0x%04X)\n", path, p.count,
                     (unsigned long long)p.size, p.crc1, p.crc2);
    pac_close(&p);
    return bad;
}

static int cmd_unpack(const char *path, const char *outdir, int skip_crc, int force)
{
    PacFile p;
    char **used = NULL;
    size_t nused = 0;
    int failed = 0;
    FILE *m = NULL;
    char mpath[PATH_MAX];

    if (pac_open(&p, path, force) < 0) return 1;
    if (!skip_crc && pac_check_crc(&p, force) < 0) { pac_close(&p); return 1; }
    if (mkdir_p(outdir) < 0) {
        err("cannot create %s: %s", outdir, strerror(errno));
        pac_close(&p);
        return 1;
    }
    if (join_path(mpath, sizeof mpath, outdir, MANIFEST_NAME) < 0) {
        err("output path too long");
        pac_close(&p);
        return 1;
    }
    m = create_outfile(mpath);
    used = calloc((size_t)p.count + 2, sizeof *used);
    if (!m || !used) {
        err("cannot create %s: %s", mpath, strerror(errno));
        if (m) fclose(m);
        free(used);
        pac_close(&p);
        return 1;
    }
    used[nused++] = strdup(MANIFEST_NAME);

    print_info(&p);
    manifest_write_header(m, &p.info);

    for (uint32_t i = 0; i < p.count; i++) {
        PacEntry e;
        char disk[STRBUF] = "", fpath[PATH_MAX];
        int has_data = 0;
        parse_entry(p.table + (size_t)i * PAC_ENTRY_SIZE, &e);

        if (e.size > 0) {
            if (!entry_in_bounds(&p, &e)) {
                err("entry %u (%s): data range [%llu, +%llu) is outside the file or overlaps the header/table; skipped", i, e.name,
                    (unsigned long long)e.offset, (unsigned long long)e.size);
                failed = 1;
            } else {
                make_disk_name(&e, i, used, nused, disk, sizeof disk);
                used[nused++] = strdup(disk);
                if (join_path(fpath, sizeof fpath, outdir, disk) < 0) {
                    err("path too long for %s", disk);
                    failed = 1;
                } else {
                    FILE *o = create_outfile(fpath);
                    if (!o) {
                        err("cannot create %s: %s", fpath, strerror(errno));
                        failed = 1;
                    } else {
                        if (copy_range(p.f, e.offset, e.size, o) < 0 || fclose(o) != 0) {
                            err("write/read error extracting %s", disk);
                            failed = 1;
                        } else {
                            has_data = 1;
                            printf("[%2u] %-12s -> %-28s %12llu bytes\n", i, e.id, disk, (unsigned long long)e.size);
                        }
                    }
                }
            }
        } else {
            printf("[%2u] %-12s    (no data: flag=%u)\n", i, e.id, e.flag);
        }
        manifest_write_entry(m, i, &e, has_data ? disk : NULL);
    }

    if (fclose(m) != 0) { err("error writing manifest"); failed = 1; }
    for (size_t i = 0; i < nused; i++) free(used[i]);
    free(used);
    pac_close(&p);
    if (!failed) printf("\nWrote %s\n", mpath);
    return failed;
}

static int copy_crc(FILE *in, uint64_t len, FILE *out, uint16_t *crc)
{
    uint16_t c = *crc;
    while (len) {
        size_t n = len > IOBUF_SIZE ? IOBUF_SIZE : (size_t)len;
        if (fread(iobuf, 1, n, in) != n) return -1;
        c = crc16(c, iobuf, n);
        if (fwrite(iobuf, 1, n, out) != n) return -1;
        len -= n;
    }
    *crc = c;
    return 0;
}

static int cmd_pack(const char *src, const char *outpath)
{
    char basedir[PATH_MAX], mpath[PATH_MAX], tmppath[PATH_MAX];
    struct stat st;
    Manifest m;
    uint8_t *table = NULL;
    uint8_t hdr[PAC_HEADER_SIZE];
    FILE *o = NULL;
    uint64_t pos, total;
    uint16_t crc2 = 0, crc1;
    int rc = 1;

    if (stat(src, &st) < 0) { err("cannot stat %s: %s", src, strerror(errno)); return 1; }
    if (S_ISDIR(st.st_mode)) {
        if (strlen(src) >= sizeof basedir) { err("path too long"); return 1; }
        strcpy(basedir, src);
        if (join_path(mpath, sizeof mpath, src, MANIFEST_NAME) < 0) { err("path too long"); return 1; }
    } else {
        char *sl;
        if (strlen(src) >= sizeof basedir) { err("path too long"); return 1; }
        strcpy(mpath, src);
        strcpy(basedir, src);
        sl = strrchr(basedir, '/');
        if (!sl) strcpy(basedir, ".");
        else if (sl == basedir) basedir[1] = 0;
        else *sl = 0;
    }
    if (manifest_parse(mpath, &m) < 0) return 1;

    /* resolve files and lay out the data area right after the table */
    pos = PAC_HEADER_SIZE + (uint64_t)m.n * PAC_ENTRY_SIZE;
    for (size_t i = 0; i < m.n; i++) {
        PacEntry *e = &m.e[i];
        if (!e->name_set && e->file[0]) {   /* omitted name= defaults to the file name */
            const char *b = strrchr(e->file, '/');
            snprintf(e->name, sizeof e->name, "%s", b ? b + 1 : e->file);
        }
        if (e->file[0]) {
            char fp[PATH_MAX];
            const char *q;
            if (e->file[0] == '/') { err("entry %zu: absolute 'file' paths are not allowed", i); goto out; }
            for (q = e->file; *q; q++)
                if (q[0] == '.' && q[1] == '.' && (q == e->file || q[-1] == '/') && (q[2] == '/' || q[2] == 0)) {
                    err("entry %zu: '..' in 'file' is not allowed", i);
                    goto out;
                }
            if (join_path(fp, sizeof fp, basedir, e->file) < 0) { err("entry %zu: path too long", i); goto out; }
            if (stat(fp, &st) < 0) {
                err("entry %zu (%s): cannot use '%s': %s", i, e->id, fp, strerror(errno));
                goto out;
            }
            if (!S_ISREG(st.st_mode)) {
                err("entry %zu (%s): '%s' is not a regular file", i, e->id, fp);
                goto out;
            }
            e->size = (uint64_t)st.st_size;
            if (!e->flag_set) e->flag = 1;
            else if (e->flag == 0 && e->size)
                warn("entry %zu (%s): has a file but flag=0 (flashers will treat it as an operation)", i, e->id);
            if (e->size) { e->offset = pos; pos += e->size; }
        } else {
            e->size = 0;                      /* keeps raw_offset from the manifest */
        }
    }
    total = pos;

    table = calloc(m.n ? m.n : 1, PAC_ENTRY_SIZE);
    if (!table) { err("out of memory"); goto out; }
    for (size_t i = 0; i < m.n; i++)
        if (build_entry(table + i * PAC_ENTRY_SIZE, &m.e[i], (int)i) < 0) goto out;
    if (build_header(hdr, &m.info, total, (uint32_t)m.n) < 0) goto out;

    if (snprintf(tmppath, sizeof tmppath, "%s.tmp", outpath) >= (int)sizeof tmppath) { err("path too long"); goto out; }
    o = fopen(tmppath, "w+b");
    if (!o) { err("cannot create %s: %s", tmppath, strerror(errno)); goto out; }

    memset(iobuf, 0, PAC_HEADER_SIZE);                       /* header placeholder */
    if (fwrite(iobuf, 1, PAC_HEADER_SIZE, o) != PAC_HEADER_SIZE) goto wfail;
    crc2 = crc16(0, table, m.n * PAC_ENTRY_SIZE);
    if (fwrite(table, 1, m.n * PAC_ENTRY_SIZE, o) != m.n * PAC_ENTRY_SIZE) goto wfail;

    for (size_t i = 0; i < m.n; i++) {
        PacEntry *e = &m.e[i];
        char fp[PATH_MAX];
        FILE *in;
        int r;
        if (!e->file[0] || !e->size) continue;
        join_path(fp, sizeof fp, basedir, e->file);
        in = fopen(fp, "rb");
        if (!in) { err("cannot open %s: %s", fp, strerror(errno)); goto fail_tmp; }
        r = copy_crc(in, e->size, o, &crc2);
        fclose(in);
        if (r < 0) { err("short read/write while copying %s (file changed during packing?)", fp); goto fail_tmp; }
        printf("[%2zu] %-12s <- %-28s %12llu bytes\n", i, e->id, e->file, (unsigned long long)e->size);
    }
    for (size_t i = 0; i < m.n; i++)
        if (!m.e[i].file[0]) printf("[%2zu] %-12s    (no data)\n", i, m.e[i].id);

    if ((uint64_t)ftello(o) != total) { err("internal error: output size mismatch"); goto fail_tmp; }

    wr16(hdr + H_CRC2, crc2);
    crc1 = crc16(0, hdr, PAC_CRC_COVERED);
    wr16(hdr + H_CRC1, crc1);
    if (fseeko(o, 0, SEEK_SET) != 0 || fwrite(hdr, 1, PAC_HEADER_SIZE, o) != PAC_HEADER_SIZE) goto wfail;
    if (fclose(o) != 0) { o = NULL; goto wfail; }
    o = NULL;
    if (rename(tmppath, outpath) < 0) { err("cannot rename to %s: %s", outpath, strerror(errno)); unlink(tmppath); goto out; }
    printf("\nWrote %s: %zu entries, %llu bytes, CRC1 0x%04X, CRC2 0x%04X\n", outpath, m.n,
           (unsigned long long)total, crc1, crc2);
    rc = 0;
    goto out;

wfail:
    err("write error on %s: %s", tmppath, strerror(errno));
fail_tmp:
    if (o) { fclose(o); o = NULL; }
    unlink(tmppath);
out:
    if (o) fclose(o);
    free(table);
    free(m.e);
    return rc;
}

/* ------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Spreadtrum/Unisoc PAC tool\n\n"
            "Usage:\n"
            "  %s unpack [-S] [-f] <file.pac> <outdir>   extract images and write %s\n"
            "  %s pack   <outdir|manifest> <out.pac>      build a PAC (sizes, offsets, CRCs computed)\n"
            "  %s list   <file.pac>                       show header and file table\n"
            "  %s verify <file.pac>                       check size, magic, CRC1/CRC2, data bounds\n\n"
            "Options for unpack:\n"
            "  -S   skip CRC verification (like unpac.pl -S)\n"
            "  -f   force: continue despite size/CRC mismatch\n",
            argv0, MANIFEST_NAME, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    const char *cmd, *pos[2] = {NULL, NULL};
    int npos = 0, skip_crc = 0, force = 0, rc;

    if (argc < 2) { usage(argv[0]); return 1; }
    cmd = argv[1];
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-S")) skip_crc = 1;
        else if (!strcmp(argv[i], "-f")) force = 1;
        else if (argv[i][0] == '-' && argv[i][1]) { err("unknown option %s", argv[i]); usage(argv[0]); return 1; }
        else if (npos < 2) pos[npos++] = argv[i];
        else { usage(argv[0]); return 1; }
    }

    crc_init();
    iobuf = malloc(IOBUF_SIZE);
    if (!iobuf) { err("out of memory"); return 1; }

    if (!strcmp(cmd, "unpack") && npos == 2) rc = cmd_unpack(pos[0], pos[1], skip_crc, force);
    else if (!strcmp(cmd, "pack") && npos == 2) rc = cmd_pack(pos[0], pos[1]);
    else if (!strcmp(cmd, "list") && npos == 1) rc = cmd_list(pos[0]);
    else if (!strcmp(cmd, "verify") && npos == 1) rc = cmd_verify(pos[0]);
    else { usage(argv[0]); rc = 1; }

    free(iobuf);
    return rc;
}
