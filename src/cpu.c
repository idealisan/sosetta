#include "sosetta/cpu.h"
#include "sosetta/hle.h"
#include "sosetta/debug.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUEST_PAGE_SIZE 0x1000u

static int trace_state = -1;

static int trace_enabled(void)
{
    if (trace_state < 0) {
        trace_state = getenv("SOSETTA_TRACE") != NULL;
    }
    return trace_state;
}

static void block_cb(uc_engine *uc, uint64_t address, uint32_t size,
                     void *user_data)
{
    (void)uc;
    (void)size;
    (void)user_data;
    if (address >= 0x8fe00000u && address < 0x90000000u) {
        fprintf(stderr, "[sosetta] enter dyld stub region at 0x%08llx\n",
                (unsigned long long)address);
    }
}

static uint32_t watch_addr;
static uint32_t watch_end;
static int watch_ready = -1;

static bool write_prot_cb(uc_engine *uc, uc_mem_type type, uint64_t addr,
                          int size, int64_t value, void *user_data)
{
    uint32_t pc = 0;
    char sym[128];

    (void)type;
    (void)user_data;
    uc_reg_read(uc, UC_PPC_REG_PC, &pc);
    sosetta_debug_sym(pc, sym, sizeof(sym));
    fprintf(stderr,
            "[sosetta] mem-prot: addr=0x%08llx size=%d value=0x%08llx from pc=0x%08x (%s)\n",
            (unsigned long long)addr, size, (unsigned long long)(uint64_t)value,
            pc, sym);
    return false;
}

static void watch_cb(uc_engine *uc, uc_mem_type type, uint64_t addr, int size,
                     int64_t value, void *user_data)
{
    uint32_t pc = 0;

    (void)type;
    (void)user_data;
    uc_reg_read(uc, UC_PPC_REG_PC, &pc);
    fprintf(stderr,
            "[sosetta] watch: write 0x%08x size=%d value=0x%08llx from pc=0x%08x\n",
            (uint32_t)addr, size, (unsigned long long)(uint64_t)value, pc);
}

static void watch_install(sosetta_guest *g)
{
    const char *w;
    char *end = NULL;
    unsigned long long a;
    unsigned long long n;
    uc_hook hk;

    if (watch_ready >= 0) {
        return;
    }
    watch_ready = 1;
    w = getenv("SOSETTA_WATCH");
    if (!w) {
        return;
    }
    a = strtoull(w, &end, 0);
    if (!end || *end != ':') {
        return;
    }
    n = strtoull(end + 1, NULL, 0);
    if (n == 0) {
        return;
    }
    watch_addr = (uint32_t)a;
    watch_end = (uint32_t)(a + n);
    if (uc_hook_add(g->uc, &hk, UC_HOOK_MEM_WRITE, watch_cb, g,
                    watch_addr, watch_end - 1u) != UC_ERR_OK) {
        fprintf(stderr, "[sosetta] watch: hook add failed\n");
    } else {
        fprintf(stderr, "[sosetta] watching 0x%08x..0x%08x\n",
                watch_addr, watch_end - 1u);
    }
}

static void intr_cb(uc_engine *uc, uint32_t intno, void *user_data)
{
    sosetta_guest *g = (sosetta_guest *)user_data;

    (void)uc;
    if (intno == SOSETTA_PPC_EXCP_SYSCALL && g->sys) {
        sosetta_syscall_hook(g, intno);
    }
}

static bool fetch_unmapped_cb(uc_engine *uc, uc_mem_type type,
                              uint64_t addr, int size, int64_t value,
                              void *user_data)
{
    sosetta_guest *g = (sosetta_guest *)user_data;
    uint32_t pc = (uint32_t)addr;
    uint32_t lr = 0;
    uint32_t a[8];
    uint32_t ret = 0;
    unsigned i;

    (void)type;
    (void)size;
    (void)value;
    if (pc == 0 && g->sys) {
        uint32_t key = 0;
        uint32_t sz = 0;
        uint32_t blk;
        uc_reg_read(uc, UC_PPC_REG_LR, &lr);
        sosetta_guest_get_gpr(g, 3, &key);
        sosetta_guest_get_gpr(g, 4, &sz);
        if (key == 1) {
            blk = sosetta_hle_alloc_zeroed(g, sz);
            if (blk == 0) {
                blk = 0x8fe01000u;
            }
            sosetta_guest_set_gpr(g, 3, blk);
        } else if (sz == 0) {
            uint32_t obj = 0;
            sosetta_guest_get_gpr(g, 3, &obj);
            sosetta_guest_set_gpr(g, 30, obj);
        } else {
            blk = sosetta_hle_alloc_zeroed(g, sz);
            if (blk == 0) {
                blk = 0x8fe01000u;
            }
            sosetta_guest_set_gpr(g, 2, blk);
            sosetta_guest_set_gpr(g, 3, blk);
            sosetta_guest_set_gpr(g, 30, blk);
        }
        g->sys->resume_pc = lr;
        g->sys->trap_pending = 1;
        uc_emu_stop(uc);
        return true;
    }
    if (pc < HLE_TRAP_BASE || pc >= HLE_TRAP_BASE + HLE_TRAP_SIZE || !g->sys) {
        return false;
    }
    uc_reg_read(uc, UC_PPC_REG_LR, &lr);
    for (i = 0; i < 8; i++) {
        if (sosetta_guest_get_gpr(g, 3 + i, &a[i]) != 0) {
            a[i] = 0;
        }
    }
    {
        hle_env_public ep;
        sosetta_hle_call(g, g->sys, pc, (pc - HLE_TRAP_BASE) / 4u, a, &ret,
                         &ep);
        if (ep.has_redirect) {
            uint32_t r3v = ep.call_r3;
            uint32_t r4v = ep.call_r4;
            sosetta_guest_set_gpr(g, 3, r3v);
            sosetta_guest_set_gpr(g, 4, r4v);
            uc_reg_write(uc, UC_PPC_REG_LR, &ep.call_lr);
            g->sys->resume_pc = ep.redirect_pc;
        } else {
            sosetta_guest_set_gpr(g, 3, ret);
            g->sys->resume_pc = lr;
        }
        g->sys->trap_pending = 1;
        uc_emu_stop(uc);
    }
    return true;
}

int sosetta_guest_open(sosetta_guest **out)
{
    sosetta_guest *g;
    uc_err err;

    if (!out) {
        return -1;
    }
    if (!uc_arch_supported(UC_ARCH_PPC)) {
        return -1;
    }

    g = (sosetta_guest *)calloc(1, sizeof(*g));
    if (!g) {
        return -1;
    }

    err = uc_open(UC_ARCH_PPC, (uc_mode)(UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN),
                  &g->uc);
    if (err != UC_ERR_OK) {
        free(g);
        return -1;
    }

    g->run_until = 0;
    *out = g;
    return 0;
}

void sosetta_guest_close(sosetta_guest *g)
{
    if (!g) {
        return;
    }
    if (g->uc) {
        if (g->intr_hook) {
            uc_hook_del(g->uc, g->intr_hook);
            g->intr_hook = 0;
        }
        uc_close(g->uc);
    }
    free(g);
}

int sosetta_guest_map(sosetta_guest *g, uint32_t addr, uint32_t size,
                      uint32_t prot)
{
    uint64_t base;
    uint64_t end;
    uint64_t span;
    uc_err err;

    if (!g || !g->uc || size == 0) {
        return -1;
    }

    base = (uint64_t)addr & ~(uint64_t)(GUEST_PAGE_SIZE - 1);
    end = (uint64_t)addr + size;
    end = (end + GUEST_PAGE_SIZE - 1) & ~(uint64_t)(GUEST_PAGE_SIZE - 1);
    span = end - base;
    if (span == 0) {
        return -1;
    }

    err = uc_mem_map(g->uc, base, span, prot);
    if (err != UC_ERR_OK && trace_enabled()) {
        fprintf(stderr, "[sosetta] map 0x%08x+%#llx failed: %s\n",
                (uint32_t)addr, (unsigned long long)span, uc_strerror(err));
    }
    return err == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_write(sosetta_guest *g, uint32_t addr, const void *buf,
                        size_t n)
{
    if (!g || !g->uc) {
        return -1;
    }
    return uc_mem_write(g->uc, addr, buf, n) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_read(sosetta_guest *g, uint32_t addr, void *buf, size_t n)
{
    if (!g || !g->uc) {
        return -1;
    }
    return uc_mem_read(g->uc, addr, buf, n) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_set_pc(sosetta_guest *g, uint32_t pc)
{
    if (!g || !g->uc) {
        return -1;
    }
    return uc_reg_write(g->uc, UC_PPC_REG_PC, &pc) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_get_pc(sosetta_guest *g, uint32_t *pc)
{
    if (!g || !g->uc || !pc) {
        return -1;
    }
    return uc_reg_read(g->uc, UC_PPC_REG_PC, pc) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_set_gpr(sosetta_guest *g, unsigned idx, uint32_t val)
{
    int reg;

    if (!g || !g->uc || idx > 31) {
        return -1;
    }
    reg = UC_PPC_REG_0 + idx;
    return uc_reg_write(g->uc, reg, &val) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_get_gpr(sosetta_guest *g, unsigned idx, uint32_t *val)
{
    int reg;

    if (!g || !g->uc || idx > 31 || !val) {
        return -1;
    }
    reg = UC_PPC_REG_0 + idx;
    return uc_reg_read(g->uc, reg, val) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_set_cr(sosetta_guest *g, uint32_t val)
{
    if (!g || !g->uc) {
        return -1;
    }
    return uc_reg_write(g->uc, UC_PPC_REG_CR, &val) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_get_cr(sosetta_guest *g, uint32_t *val)
{
    if (!g || !g->uc || !val) {
        return -1;
    }
    return uc_reg_read(g->uc, UC_PPC_REG_CR, val) == UC_ERR_OK ? 0 : -1;
}

int sosetta_guest_install_syscall(sosetta_guest *g, sosetta_syscall_ctx *ctx)
{
    uc_err err;

    if (!g || !g->uc || !ctx) {
        return -1;
    }
    g->sys = ctx;
    ctx->guest = g;
    err = uc_hook_add(g->uc, &g->intr_hook, UC_HOOK_INTR, intr_cb, g, 1, 0);
    if (err != UC_ERR_OK) {
        return -1;
    }
    err = uc_hook_add(g->uc, &g->fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED,
                      fetch_unmapped_cb, g, 1, 0);
    if (err != UC_ERR_OK) {
        return -1;
    }
    if (trace_enabled()) {
        uc_hook wp;
        if (uc_hook_add(g->uc, &wp, UC_HOOK_MEM_WRITE_PROT, write_prot_cb, g,
                        1, 0) == UC_ERR_OK) {
            fprintf(stderr, "[sosetta] write-prot tracing on\n");
        }
        if (uc_hook_add(g->uc, &wp, UC_HOOK_MEM_WRITE_UNMAPPED, write_prot_cb,
                        g, 1, 0) == UC_ERR_OK) {
            fprintf(stderr, "[sosetta] write-unmapped tracing on\n");
        }
        if (uc_hook_add(g->uc, &wp, UC_HOOK_MEM_READ_UNMAPPED, write_prot_cb,
                        g, 1, 0) == UC_ERR_OK) {
            fprintf(stderr, "[sosetta] read-unmapped tracing on\n");
        }
    }
    if (trace_enabled()) {
        err = uc_hook_add(g->uc, &g->block_hook, UC_HOOK_BLOCK, block_cb, g, 1, 0);
        if (err != UC_ERR_OK) {
            return -1;
        }
        watch_install(g);
    }
    return 0;
}

int sosetta_guest_run(sosetta_guest *g)
{
    uint32_t pc;
    uc_err err;

    if (!g || !g->uc) {
        return -1;
    }
    if (sosetta_guest_get_pc(g, &pc) != 0) {
        return -1;
    }
    err = uc_emu_start(g->uc, pc, g->run_until, g->run_timeout_us, 0);
    return (int)err;
}