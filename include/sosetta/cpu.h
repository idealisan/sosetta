#ifndef SOSETTA_CPU_H
#define SOSETTA_CPU_H

#include <stdint.h>
#include <stddef.h>
#include <unicorn/unicorn.h>
#include "sosetta/syscall.h"

typedef struct sosetta_guest {
    uc_engine *uc;
    sosetta_syscall_ctx *sys;
    uc_hook intr_hook;
    uc_hook block_hook;
    uc_hook fetch_hook;
    uint64_t run_until;
    uint64_t run_timeout_us;
} sosetta_guest;

int sosetta_guest_open(sosetta_guest **out);
void sosetta_guest_close(sosetta_guest *g);

int sosetta_guest_map(sosetta_guest *g, uint32_t addr, uint32_t size,
                      uint32_t prot);
int sosetta_guest_write(sosetta_guest *g, uint32_t addr, const void *buf,
                        size_t n);
int sosetta_guest_read(sosetta_guest *g, uint32_t addr, void *buf, size_t n);

int sosetta_guest_set_pc(sosetta_guest *g, uint32_t pc);
int sosetta_guest_get_pc(sosetta_guest *g, uint32_t *pc);

int sosetta_guest_set_gpr(sosetta_guest *g, unsigned idx, uint32_t val);
int sosetta_guest_get_gpr(sosetta_guest *g, unsigned idx, uint32_t *val);
int sosetta_guest_set_cr(sosetta_guest *g, uint32_t val);
int sosetta_guest_get_cr(sosetta_guest *g, uint32_t *val);

int sosetta_guest_install_syscall(sosetta_guest *g, sosetta_syscall_ctx *ctx);
int sosetta_guest_run(sosetta_guest *g);
void sosetta_guest_dump_trace(void);

#endif