#include "sosetta/macho.h"
#include "sosetta/endian.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HDR32_SIZE 28u
#define HDR64_SIZE 32u
#define SEG32_SIZE 56u
#define SEG64_SIZE 72u
#define SYMTAB_SIZE 24u
#define THREAD_CMD_SIZE 16u

static const char *err_ok = "ok";

static void set_err(char *errbuf, size_t errsz, const char *msg)
{
    if (errbuf && errsz) {
        snprintf(errbuf, errsz, "%s", msg);
    }
}

static int append_seg(sosetta_macho *m, const sosetta_seg *seg)
{
    sosetta_seg *n = realloc(m->segs, (m->nsegs + 1) * sizeof(*n));
    if (!n) {
        return -1;
    }
    m->segs = n;
    m->segs[m->nsegs++] = *seg;
    return 0;
}

static void copy_segname(char *dst, const uint8_t *src)
{
    memcpy(dst, src, 16);
    dst[16] = '\0';
}

static int parse_thin(const uint8_t *d, size_t n, sosetta_macho *m,
                      char *errbuf, size_t errsz, int force_fat)
{
    uint32_t magic;
    uint32_t ncmds, sizeofcmds, flags;
    uint32_t off, cend;

    memset(m, 0, sizeof(*m));

    if (n < HDR32_SIZE) {
        set_err(errbuf, errsz, "file too small for mach header");
        return -1;
    }

    magic = be32(d);
    if (magic == MH_MAGIC_64) {
        m->is_64 = 1;
    } else if (magic == MH_MAGIC) {
        m->is_64 = 0;
    } else {
        set_err(errbuf, errsz, "not a big-endian PowerPC Mach-O");
        return -1;
    }
    m->is_fat = force_fat;
    m->data = d;
    m->size = n;

    m->cputype = be32(d + 4);
    m->cpusubtype = be32(d + 8);
    m->filetype = be32(d + 12);
    ncmds = be32(d + 16);
    sizeofcmds = be32(d + 20);
    flags = be32(d + 24);

    if (m->cputype != CPU_TYPE_POWERPC && m->cputype != CPU_TYPE_POWERPC64) {
        set_err(errbuf, errsz, "cputype is not PowerPC");
        return -1;
    }

    off = m->is_64 ? HDR64_SIZE : HDR32_SIZE;
    cend = off + sizeofcmds;
    if (cend > n) {
        set_err(errbuf, errsz, "load commands extend past end of file");
        return -1;
    }

    while (ncmds-- > 0 && off + 8 <= cend) {
        uint32_t cmd = be32(d + off);
        uint32_t size = be32(d + off + 4);
        sosetta_seg seg;

        if (size < 8 || off + size > cend) {
            set_err(errbuf, errsz, "malformed load command");
            goto fail;
        }

        switch (cmd) {
        case LC_SEGMENT:
            if (m->is_64 || size < SEG32_SIZE) {
                set_err(errbuf, errsz, "bad LC_SEGMENT command");
                goto fail;
            }
            memset(&seg, 0, sizeof(seg));
            copy_segname(seg.segname, d + off + 8);
            seg.vmaddr = be32(d + off + 24);
            seg.vmsize = be32(d + off + 28);
            seg.fileoff = be32(d + off + 32);
            seg.filesize = be32(d + off + 36);
            seg.maxprot = be32(d + off + 40);
            seg.initprot = be32(d + off + 44);
            seg.flags = be32(d + off + 52);
            if (append_seg(m, &seg) != 0) {
                set_err(errbuf, errsz, "out of memory");
                goto fail;
            }
            break;

        case LC_SEGMENT_64:
            if (!m->is_64 || size < SEG64_SIZE) {
                set_err(errbuf, errsz, "bad LC_SEGMENT_64 command");
                goto fail;
            }
            memset(&seg, 0, sizeof(seg));
            copy_segname(seg.segname, d + off + 8);
            seg.vmaddr = be64(d + off + 24);
            seg.vmsize = be64(d + off + 32);
            seg.fileoff = be64(d + off + 40);
            seg.filesize = be64(d + off + 48);
            seg.maxprot = be32(d + off + 56);
            seg.initprot = be32(d + off + 60);
            seg.flags = be32(d + off + 68);
            if (append_seg(m, &seg) != 0) {
                set_err(errbuf, errsz, "out of memory");
                goto fail;
            }
            break;

        case LC_SYMTAB:
            if (size < SYMTAB_SIZE) {
                set_err(errbuf, errsz, "bad LC_SYMTAB command");
                goto fail;
            }
            m->symoff = be32(d + off + 8);
            m->nsyms = be32(d + off + 12);
            m->stroff = be32(d + off + 16);
            m->strsize = be32(d + off + 20);
            break;

        case LC_UNIXTHREAD:
            if (size < THREAD_CMD_SIZE + PPC_THREAD_STATE_COUNT * 4u) {
                set_err(errbuf, errsz, "bad LC_UNIXTHREAD command");
                goto fail;
            }
            if (be32(d + off + 8) == PPC_THREAD_STATE) {
                const uint8_t *st = d + off + THREAD_CMD_SIZE;
                uint32_t count = be32(d + off + 12);
                if (count > PPC_THREAD_STATE_COUNT) {
                    count = PPC_THREAD_STATE_COUNT;
                }
                if (count >= 4u) {
                    m->thread.has_thread = 1;
                    m->thread.entry_pc = be32(st);
                    m->thread.entry_sp = be32(st + 3 * 4);
                }
                if (count >= 35u) {
                    m->thread.cr = be32(st + 34 * 4);
                    m->thread.xer = be32(st + 35 * 4);
                    m->thread.lr = be32(st + 36 * 4);
                    m->thread.ctr = be32(st + 37 * 4);
                }
            }
            break;

        default:
            break;
        }

        off += size;
    }

    m->flags = flags;
    return 0;

fail:
    sosetta_macho_free(m);
    return -1;
}

static int parse_fat(const uint8_t *d, size_t n, sosetta_macho *m,
                     char *errbuf, size_t errsz)
{
    uint32_t nfat;
    uint32_t i;

    if (n < 8) {
        set_err(errbuf, errsz, "fat header truncated");
        return -1;
    }
    nfat = be32(d + 4);
    if (nfat > 1000u) {
        set_err(errbuf, errsz, "unreasonable fat arch count");
        return -1;
    }
    if (n < 8u + nfat * 20u) {
        set_err(errbuf, errsz, "fat arch table truncated");
        return -1;
    }

    for (i = 0; i < nfat; i++) {
        const uint8_t *a = d + 8u + i * 20u;
        uint32_t cputype = be32(a);
        uint32_t offset = be32(a + 8);
        uint32_t size = be32(a + 12);

        if (cputype != CPU_TYPE_POWERPC && cputype != CPU_TYPE_POWERPC64) {
            continue;
        }
        if ((uint64_t)offset + size > n) {
            continue;
        }
        return parse_thin(d + offset, size, m, errbuf, errsz, 1);
    }

    set_err(errbuf, errsz, "no PowerPC slice in fat binary");
    return -1;
}

int sosetta_macho_parse(const void *data, size_t size, sosetta_macho *out,
                        char *errbuf, size_t errsz)
{
    const uint8_t *d = (const uint8_t *)data;

    if (errbuf && errsz) {
        errbuf[0] = '\0';
    }
    if (size < 4) {
        set_err(errbuf, errsz, "file too small");
        return -1;
    }

    if (be32(d) == FAT_MAGIC) {
        return parse_fat(d, size, out, errbuf, errsz);
    }
    return parse_thin(d, size, out, errbuf, errsz, 0);
}

void sosetta_macho_free(sosetta_macho *m)
{
    if (!m) {
        return;
    }
    free(m->segs);
    m->segs = NULL;
    m->nsegs = 0;
}

const char *sosetta_macho_strerror(int rc, const char *errbuf, size_t errsz)
{
    (void)rc;
    if (errbuf && errsz && errbuf[0]) {
        return errbuf;
    }
    return err_ok;
}