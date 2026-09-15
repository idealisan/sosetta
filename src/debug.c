#define _POSIX_C_SOURCE 200809L

#include "sosetta/debug.h"
#include "sosetta/cpu.h"
#include "sosetta/endian.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MH_BE_MAGIC 0xfeedfaceu
#define LC_SYMTAB_CMD 0x02u
#define N_TYPE_SECT 0x0eu

/* ---- symbol table index ---- */

static int d_syment_cmp(const void *a, const void *b)
{
    const struct sosetta_debug_syment *ea = a;
    const struct sosetta_debug_syment *eb = b;
    if (ea->addr < eb->addr) {
        return -1;
    }
    if (ea->addr > eb->addr) {
        return 1;
    }
    return 0;
}

int sosetta_debug_symtab_load(const uint8_t *data, size_t size,
                              struct sosetta_debug_symtab *st)
{
    uint32_t ncmds, off, i;
    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    int have_symtab = 0;

    memset(st, 0, sizeof(*st));
    if (size < 28u || be32(data) != MH_BE_MAGIC) {
        return -1;
    }
    ncmds = be32(data + 16);
    off = 28u;
    for (i = 0; i < ncmds && (size_t)off + 8u <= size; i++) {
        uint32_t cmd = be32(data + off);
        uint32_t cmdsize = be32(data + off + 4);
        if (cmd == LC_SYMTAB_CMD && cmdsize >= 24u) {
            symoff = be32(data + off + 8);
            nsyms = be32(data + off + 12);
            stroff = be32(data + off + 16);
            strsize = be32(data + off + 20);
            have_symtab = 1;
        }
        if (cmdsize < 8u) {
            break;
        }
        off += cmdsize;
    }
    if (!have_symtab || nsyms == 0) {
        return -1;
    }
    if ((size_t)symoff + (size_t)nsyms * 12u > size) {
        return -1;
    }
    if ((size_t)stroff + (size_t)strsize > size) {
        return -1;
    }

    st->entries = calloc(nsyms, sizeof(*st->entries));
    if (!st->entries) {
        return -1;
    }
    for (i = 0; i < nsyms; i++) {
        const uint8_t *e = data + symoff + (size_t)i * 12u;
        uint8_t n_type = e[4];
        uint32_t value = be32(e + 8);
        if ((n_type & N_TYPE_SECT) == N_TYPE_SECT && value != 0) {
            st->entries[st->count].addr = value;
            st->entries[st->count].idx = i;
            st->count++;
        }
    }
    qsort(st->entries, st->count, sizeof(*st->entries), d_syment_cmp);
    st->data = data;
    st->symoff = symoff;
    st->stroff = stroff;
    st->strsize = strsize;
    return 0;
}

void sosetta_debug_symtab_free(struct sosetta_debug_symtab *st)
{
    if (!st) {
        return;
    }
    free(st->entries);
    memset(st, 0, sizeof(*st));
}

void sosetta_debug_symtab_sym(const struct sosetta_debug_symtab *st,
                              uint32_t addr, char *buf, size_t cap)
{
    size_t lo = 0;
    size_t hi = st->count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (st->entries[mid].addr <= addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        snprintf(buf, cap, "0x%08x", addr);
        return;
    }
    {
        const struct sosetta_debug_syment *e = &st->entries[lo - 1];
        uint32_t strx = be32(st->data + st->symoff + (size_t)e->idx * 12u);
        uint32_t avail;
        const char *name;
        const char *nul;
        uint32_t off = addr - e->addr;

        if (strx >= st->strsize) {
            snprintf(buf, cap, "0x%08x", addr);
            return;
        }
        name = (const char *)st->data + (size_t)st->stroff + strx;
        avail = st->strsize - strx;
        nul = memchr(name, 0, avail);
        if (!nul) {
            snprintf(buf, cap, "0x%08x", addr);
            return;
        }
        if (off == 0) {
            snprintf(buf, cap, "%s", name);
        } else {
            snprintf(buf, cap, "%s+0x%x", name, off);
        }
    }
}

/* ---- guest debug state ---- */

static struct sosetta_debug_symtab d_symtab;
static int d_symtab_ready;
static sosetta_guest *d_guest;

static uint32_t *d_ring;
static size_t d_ring_cap;
static size_t d_ring_pos;
static uc_hook d_ring_hook;

static void d_ring_cb(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    (void)uc;
    (void)size;
    (void)user_data;
    if (d_ring) {
        d_ring[d_ring_pos % d_ring_cap] = (uint32_t)address;
        d_ring_pos++;
    }
}

struct d_bp {
    uint32_t addr;
    uc_hook hk;
    unsigned hits;
};

static struct d_bp *d_bps;
static size_t d_nbps;

static unsigned d_bp_limit;
static int d_bp_limit_ready = -1;

static unsigned d_bp_limit_get(void)
{
    if (d_bp_limit_ready < 0) {
        const char *v = getenv("SOSETTA_BP_HITS");
        d_bp_limit = (v && *v) ? (unsigned)strtoul(v, NULL, 0) : 3u;
        if (!d_bp_limit) {
            d_bp_limit = 3u;
        }
        d_bp_limit_ready = 1;
    }
    return d_bp_limit;
}

static void d_bp_cb(uc_engine *uc, uint64_t address, uint32_t size,
                    void *user_data)
{
    size_t i;
    uint32_t pc = (uint32_t)address;
    uint32_t lr = 0;
    uint32_t r3 = 0;
    uint32_t r4 = 0;
    uint32_t r5 = 0;
    char sym[128];
    char lrsym[128];

    (void)size;
    (void)user_data;
    for (i = 0; i < d_nbps; i++) {
        if (d_bps[i].addr == pc) {
            break;
        }
    }
    if (i >= d_nbps || d_bps[i].hits >= d_bp_limit_get()) {
        return;
    }
    d_bps[i].hits++;
    uc_reg_read(uc, UC_PPC_REG_LR, &lr);
    sosetta_guest_get_gpr(d_guest, 3, &r3);
    sosetta_guest_get_gpr(d_guest, 4, &r4);
    sosetta_guest_get_gpr(d_guest, 5, &r5);
    sosetta_debug_sym(pc, sym, sizeof(sym));
    sosetta_debug_sym(lr, lrsym, sizeof(lrsym));
    fprintf(stderr,
            "[sosetta] bp[%zu] hit 0x%08x (%s) lr=0x%08x (%s) r3=0x%08x r4=0x%08x r5=0x%08x\n",
            i, pc, sym, lr, lrsym, r3, r4, r5);
}

static uint32_t d_step_begin;
static uint32_t d_step_end;
static uc_hook d_step_hook;
static int d_step_on;

static void d_step_cb(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    uint32_t r1 = 0;
    uint32_t r2 = 0;
    uint32_t r3 = 0;
    uint32_t r4 = 0;
    uint32_t lr = 0;

    (void)size;
    (void)user_data;
    uc_reg_read(uc, UC_PPC_REG_LR, &lr);
    sosetta_guest_get_gpr(d_guest, 1, &r1);
    sosetta_guest_get_gpr(d_guest, 2, &r2);
    sosetta_guest_get_gpr(d_guest, 3, &r3);
    sosetta_guest_get_gpr(d_guest, 4, &r4);
    fprintf(stderr,
            "[sosetta] step 0x%08x r1=0x%08x r2=0x%08x r3=0x%08x r4=0x%08x lr=0x%08x\n",
            (uint32_t)address, r1, r2, r3, r4, lr);
}

static void d_env_range(const char *name, uint32_t *begin, uint32_t *end)
{
    const char *v = getenv(name);
    char *endp = NULL;
    unsigned long long a;
    unsigned long long b;

    if (!v) {
        return;
    }
    a = strtoull(v, &endp, 0);
    if (!endp || *endp != ':') {
        return;
    }
    b = strtoull(endp + 1, NULL, 0);
    if (b <= a) {
        return;
    }
    *begin = (uint32_t)a;
    *end = (uint32_t)b;
}

void sosetta_debug_init(sosetta_guest *g, const sosetta_macho *im)
{
    const char *renv;
    const char *benv;
    char *bwalk;
    uint32_t step_begin = 0;
    uint32_t step_end = 0;

    d_guest = g;
    if (sosetta_debug_symtab_load(im->data, im->size, &d_symtab) == 0) {
        d_symtab_ready = 1;
        fprintf(stderr, "[sosetta] debug: %zu symbols loaded\n",
                d_symtab.count);
    }

    renv = getenv("SOSETTA_RING");
    if (renv) {
        unsigned long long depth = strtoull(renv, NULL, 0);
        if (depth >= 16u && depth <= (1u << 20)) {
            d_ring = malloc((size_t)depth * sizeof(uint32_t));
            if (d_ring) {
                memset(d_ring, 0, (size_t)depth * sizeof(uint32_t));
                d_ring_cap = (size_t)depth;
                d_ring_pos = 0;
                if (uc_hook_add(g->uc, &d_ring_hook, UC_HOOK_CODE, d_ring_cb,
                                g, 1, 0xffffffffu) != UC_ERR_OK) {
                    free(d_ring);
                    d_ring = NULL;
                } else {
                    fprintf(stderr, "[sosetta] debug: ring %llu entries\n",
                            depth);
                }
            }
        }
    }

    benv = getenv("SOSETTA_BREAK");
    if (benv) {
        size_t count = 1;
        char *copy;
        const char *walk;
        size_t i;

        for (walk = benv; *walk; walk++) {
            if (*walk == ',') {
                count++;
            }
        }
        copy = strdup(benv);
        d_bps = calloc(count, sizeof(*d_bps));
        if (copy && d_bps) {
            bwalk = copy;
            for (i = 0; i < count; i++) {
                char *comma = strchr(bwalk, ',');
                if (comma) {
                    *comma = 0;
                }
                d_bps[d_nbps].addr = (uint32_t)strtoul(bwalk, NULL, 0);
                d_nbps++;
                if (!comma) {
                    break;
                }
                bwalk = comma + 1;
            }
            for (i = 0; i < d_nbps; i++) {
                if (uc_hook_add(g->uc, &d_bps[i].hk, UC_HOOK_BLOCK, d_bp_cb, g,
                                d_bps[i].addr, d_bps[i].addr) != UC_ERR_OK) {
                    fprintf(stderr, "[sosetta] debug: bp %zu install failed\n",
                            i);
                } else {
                    char sym[128];
                    sosetta_debug_sym(d_bps[i].addr, sym, sizeof(sym));
                    fprintf(stderr, "[sosetta] debug: bp[%zu] at 0x%08x (%s)\n",
                            i, d_bps[i].addr, sym);
                }
            }
        }
        free(copy);
        if (!d_nbps) {
            free(d_bps);
            d_bps = NULL;
        }
    }

    d_env_range("SOSETTA_CODETRACE", &step_begin, &step_end);
    if (step_end > step_begin) {
        d_step_begin = step_begin;
        d_step_end = step_end;
        if (uc_hook_add(g->uc, &d_step_hook, UC_HOOK_CODE, d_step_cb, g,
                        d_step_begin, d_step_end) == UC_ERR_OK) {
            d_step_on = 1;
            fprintf(stderr, "[sosetta] debug: step 0x%08x..0x%08x\n",
                    d_step_begin, d_step_end);
        }
    }
}

void sosetta_debug_shutdown(void)
{
    free(d_ring);
    d_ring = NULL;
    free(d_bps);
    d_bps = NULL;
    d_nbps = 0;
    sosetta_debug_symtab_free(&d_symtab);
    d_symtab_ready = 0;
    d_guest = NULL;
}

void sosetta_debug_sym(uint32_t addr, char *buf, size_t cap)
{
    if (d_symtab_ready) {
        sosetta_debug_symtab_sym(&d_symtab, addr, buf, cap);
        return;
    }
    snprintf(buf, cap, "0x%08x", addr);
}

void sosetta_debug_report(sosetta_guest *g, const char *reason, uint32_t pc)
{
    char pcsym[128];
    uint32_t lr = 0;
    uint32_t fp = 0;
    unsigned i;
    unsigned frame;

    uc_reg_read(g->uc, UC_PPC_REG_LR, &lr);
    sosetta_debug_sym(pc, pcsym, sizeof(pcsym));
    fprintf(stderr, "[sosetta] fault: %s\n", reason);
    fprintf(stderr, "[sosetta]   pc=0x%08x (%s)\n", pc, pcsym);
    {
        char lrsym[128];
        sosetta_debug_sym(lr, lrsym, sizeof(lrsym));
        fprintf(stderr, "[sosetta]   lr=0x%08x (%s)\n", lr, lrsym);
    }
    for (i = 0; i < 32; i += 4) {
        uint32_t v0 = 0;
        uint32_t v1 = 0;
        uint32_t v2 = 0;
        uint32_t v3 = 0;
        sosetta_guest_get_gpr(g, i, &v0);
        sosetta_guest_get_gpr(g, i + 1u, &v1);
        sosetta_guest_get_gpr(g, i + 2u, &v2);
        sosetta_guest_get_gpr(g, i + 3u, &v3);
        fprintf(stderr, "[sosetta]   r%02u=0x%08x r%02u=0x%08x r%02u=0x%08x r%02u=0x%08x\n",
                i, v0, i + 1u, v1, i + 2u, v2, i + 3u, v3);
    }
    fprintf(stderr, "[sosetta] backtrace:\n");
    {
        char sym[128];
        sosetta_debug_sym(pc, sym, sizeof(sym));
        fprintf(stderr, "[sosetta]   #0 0x%08x (%s)\n", pc, sym);
    }
    {
        char sym[128];
        sosetta_debug_sym(lr, sym, sizeof(sym));
        fprintf(stderr, "[sosetta]   #1 0x%08x (%s) [lr]\n", lr, sym);
    }
    fp = 0;
    sosetta_guest_get_gpr(g, 1, &fp);
    for (frame = 0; frame < 16; frame++) {
        uint32_t next = 0;
        uint32_t saved = 0;
        char sym[128];

        if (fp & 3u) {
            break;
        }
        if (sosetta_guest_read(g, fp, &next, 4) != 0) {
            break;
        }
        if (sosetta_guest_read(g, fp + 8u, &saved, 4) != 0) {
            break;
        }
        if (saved == 0) {
            break;
        }
        sosetta_debug_sym(saved, sym, sizeof(sym));
        fprintf(stderr, "[sosetta]   #%u 0x%08x (%s)\n", frame + 2u, saved,
                sym);
        if (next <= fp || (next - fp) > 0x100000u || (next & 3u)) {
            break;
        }
        fp = next;
    }
    if (d_ring && d_ring_pos) {
        size_t k;
        size_t n = d_ring_pos < 32u ? d_ring_pos : 32u;
        fprintf(stderr, "[sosetta] recent instructions:\n");
        for (k = 0; k < n; k++) {
            size_t idx = (d_ring_pos - 1u - k) % d_ring_cap;
            char sym[128];
            uint32_t a = d_ring[idx];
            sosetta_debug_sym(a, sym, sizeof(sym));
            fprintf(stderr, "[sosetta]   -%02zu 0x%08x (%s)\n", k, a, sym);
        }
        {
            const char *rf = getenv("SOSETTA_RING_FILE");
            if (rf) {
                FILE *f = fopen(rf, "w");
                if (f) {
                    size_t total = d_ring_pos < d_ring_cap ? d_ring_pos : d_ring_cap;
                    for (k = 0; k < total; k++) {
                        size_t idx = (d_ring_pos - 1u - k) % d_ring_cap;
                        char sym[128];
                        sosetta_debug_sym(d_ring[idx], sym, sizeof(sym));
                        fprintf(f, "-%zu 0x%08x %s\n", k, d_ring[idx], sym);
                    }
                    fclose(f);
                    fprintf(stderr, "[sosetta] ring written to %s\n", rf);
                }
            }
        }
    }
}
