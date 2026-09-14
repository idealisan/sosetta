#include "sosetta/cpu.h"

#include <stdlib.h>
#include <string.h>

#define GUEST_PAGE_SIZE 0x1000u

static void intr_cb(uc_engine *uc, uint32_t intno, void *user_data)
{
    sosetta_guest *g = (sosetta_guest *)user_data;

    (void)uc;
    if (intno == SOSETTA_PPC_EXCP_SYSCALL && g->sys) {
        sosetta_syscall_hook(g, intno);
    }
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
    return err == UC_ERR_OK ? 0 : -1;
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