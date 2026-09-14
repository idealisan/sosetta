#ifndef SOSETTA_TEST_MACHO_BUILDER_H
#define SOSETTA_TEST_MACHO_BUILDER_H

#include "sosetta/macho.h"
#include "sosetta/endian.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MF_MAX_SEGS 32
#define MF_HDR_SIZE 28u

typedef struct mf_seg {
    char     segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t initprot;
    uint32_t maxprot;
    uint32_t flags;
    uint32_t fileoff;
    uint32_t filesize;
    const uint8_t *data;
    size_t   fileoff_cmd_ofs;
} mf_seg;

typedef struct mf_builder {
    uint8_t    *cmds;
    size_t      cmds_cap;
    size_t      cmds_len;
    uint8_t    *payload;
    size_t      payload_cap;
    size_t      payload_len;
    mf_seg     *segs;
    size_t      nsegs;
    size_t      segs_cap;
    int         has_thread;
    uint32_t    entry_pc;
    uint32_t    entry_sp;
    uint32_t    cr;
    uint32_t    xer;
    uint32_t    lr;
    uint32_t    ctr;
} mf_builder;

static void mf_init(mf_builder *b)
{
    memset(b, 0, sizeof(*b));
    b->cmds_cap = 1024;
    b->cmds = (uint8_t *)malloc(b->cmds_cap);
    b->payload_cap = 4096;
    b->payload = (uint8_t *)malloc(b->payload_cap);
    b->segs_cap = MF_MAX_SEGS;
    b->segs = (mf_seg *)malloc(sizeof(mf_seg) * b->segs_cap);
    if (!b->cmds || !b->payload || !b->segs) {
        free(b->cmds);
        free(b->payload);
        free(b->segs);
        memset(b, 0, sizeof(*b));
    }
}

static void mf_free(mf_builder *b)
{
    free(b->cmds);
    free(b->payload);
    free(b->segs);
    memset(b, 0, sizeof(*b));
}

static void mf_reserve(uint8_t **buf, size_t *cap, size_t need)
{
    if (need <= *cap) {
        return;
    }
    do {
        *cap *= 2;
    } while (*cap < need);
    *buf = (uint8_t *)realloc(*buf, *cap);
}

static void mf_cmds_bytes(mf_builder *b, const void *p, size_t n)
{
    mf_reserve(&b->cmds, &b->cmds_cap, b->cmds_len + n);
    memcpy(b->cmds + b->cmds_len, p, n);
    b->cmds_len += n;
}

static void mf_cmds_u32(mf_builder *b, uint32_t v)
{
    uint8_t x[4];
    put_be32(x, v);
    mf_cmds_bytes(b, x, 4);
}

static void mf_payload_bytes(mf_builder *b, const void *p, size_t n)
{
    mf_reserve(&b->payload, &b->payload_cap, b->payload_len + n);
    memcpy(b->payload + b->payload_len, p, n);
    b->payload_len += n;
}

static void mf_add_seg(mf_builder *b, const char *name, uint32_t vmaddr,
                       uint32_t vmsize, uint32_t initprot, uint32_t maxprot,
                       const void *data, uint32_t filesize)
{
    mf_seg *s;
    size_t cmd_start;

    if (b->nsegs >= b->segs_cap) {
        return;
    }
    s = &b->segs[b->nsegs];
    memset(s, 0, sizeof(*s));
    strncpy(s->segname, name, 16);
    s->vmaddr = vmaddr;
    s->vmsize = vmsize;
    s->initprot = initprot;
    s->maxprot = maxprot;
    s->fileoff = (uint32_t)b->payload_len;
    s->filesize = filesize;
    s->data = (const uint8_t *)data;

    cmd_start = b->cmds_len;
    mf_cmds_u32(b, LC_SEGMENT);
    mf_cmds_u32(b, 56u);
    mf_cmds_bytes(b, s->segname, 16);
    mf_cmds_u32(b, s->vmaddr);
    mf_cmds_u32(b, s->vmsize);
    mf_cmds_u32(b, s->fileoff);
    mf_cmds_u32(b, s->filesize);
    mf_cmds_u32(b, s->maxprot);
    mf_cmds_u32(b, s->initprot);
    mf_cmds_u32(b, 0);
    mf_cmds_u32(b, s->flags);
    s->fileoff_cmd_ofs = cmd_start + 8u + 16u + 4u + 4u;

    b->nsegs++;

    if (data && filesize) {
        mf_payload_bytes(b, data, filesize);
    }
}

static void mf_add_thread(mf_builder *b, uint32_t entry_pc, uint32_t entry_sp)
{
    int i;

    if (b->has_thread) {
        return;
    }
    b->has_thread = 1;
    b->entry_pc = entry_pc;
    b->entry_sp = entry_sp;

    mf_cmds_u32(b, LC_UNIXTHREAD);
    mf_cmds_u32(b, 16u + PPC_THREAD_STATE_COUNT * 4u);
    mf_cmds_u32(b, PPC_THREAD_STATE);
    mf_cmds_u32(b, PPC_THREAD_STATE_COUNT);

    mf_cmds_u32(b, entry_pc);
    mf_cmds_u32(b, 0);
    mf_cmds_u32(b, 0);
    mf_cmds_u32(b, entry_sp);
    for (i = 0; i < 30; i++) {
        mf_cmds_u32(b, 0);
    }
    mf_cmds_u32(b, b->cr);
    mf_cmds_u32(b, b->xer);
    mf_cmds_u32(b, b->lr);
    mf_cmds_u32(b, b->ctr);
    for (i = 0; i < 4; i++) {
        mf_cmds_u32(b, 0);
    }
}

static int mf_build(mf_builder *b, uint8_t **out, size_t *outlen)
{
    uint8_t *mem;
    size_t total;
    size_t off;
    size_t i;

    total = MF_HDR_SIZE + b->cmds_len + b->payload_len;
    mem = (uint8_t *)calloc(total ? total : 1, 1);
    if (!mem) {
        return -1;
    }

    put_be32(mem + 0, MH_MAGIC);
    put_be32(mem + 4, CPU_TYPE_POWERPC);
    put_be32(mem + 8, 0);
    put_be32(mem + 12, 2u);
    put_be32(mem + 16, (uint32_t)(b->nsegs + (b->has_thread ? 1 : 0)));
    put_be32(mem + 20, (uint32_t)b->cmds_len);
    put_be32(mem + 24, 0);

    off = MF_HDR_SIZE;
    memcpy(mem + off, b->cmds, b->cmds_len);
    off += b->cmds_len;

    for (i = 0; i < b->nsegs; i++) {
        uint32_t abs_off = (uint32_t)(MF_HDR_SIZE + b->cmds_len +
                                      b->segs[i].fileoff);
        put_be32(mem + MF_HDR_SIZE + b->segs[i].fileoff_cmd_ofs, abs_off);
    }

    if (b->payload_len) {
        memcpy(mem + off, b->payload, b->payload_len);
    }

    *out = mem;
    *outlen = total;
    return 0;
}

static int mf_default_hello(mf_builder *b)
{
    static const uint8_t hello_code[] = {
        0x38, 0x00, 0x00, 0x04,
        0x38, 0x60, 0x00, 0x01,
        0x3C, 0x80, 0x00, 0x00,
        0x60, 0x84, 0x20, 0x00,
        0x38, 0xA0, 0x00, 0x14,
        0x44, 0x00, 0x00, 0x02,
        0x38, 0x00, 0x00, 0x01,
        0x38, 0x60, 0x00, 0x00,
        0x44, 0x00, 0x00, 0x02,
    };
    static const uint8_t hello_data[] = {
        'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm',
        ' ', 'P', 'o', 'w', 'e', 'r', 'P', 'C', '!', '\n',
    };

    mf_init(b);
    if (!b->cmds || !b->payload || !b->segs) {
        return -1;
    }
    mf_add_seg(b, "__TEXT", 0x1000u, 0x1000u,
               VM_PROT_READ | VM_PROT_EXEC, VM_PROT_READ | VM_PROT_EXEC,
               hello_code, (uint32_t)sizeof(hello_code));
    mf_add_seg(b, "__DATA", 0x2000u, 0x1000u,
               VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
               hello_data, (uint32_t)sizeof(hello_data));
    mf_add_thread(b, 0x1000u, 0u);
    return 0;
}

#endif