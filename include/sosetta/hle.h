#ifndef SOSETTA_HLE_H
#define SOSETTA_HLE_H

#include "sosetta/cpu.h"
#include "sosetta/macho.h"

#include <stddef.h>

#define HLE_TRAP_BASE  0x7F000000u
#define HLE_TRAP_SIZE  0x8000u

int sosetta_hle_bind(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                     const sosetta_macho *im);

void sosetta_hle_set_errno(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                           uint32_t darwin_errno);
int sosetta_hle_host_fd(int guest_fd);
uint32_t sosetta_hle_alloc_zeroed(sosetta_guest *g, uint32_t size);

typedef struct hle_env_public {
    int has_redirect;
    uint32_t redirect_pc;
    uint32_t call_r3;
    uint32_t call_r4;
    uint32_t call_lr;
} hle_env_public;

void sosetta_hle_call(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                       uint32_t pc, uint32_t id, const uint32_t *a,
                       uint32_t *ret, hle_env_public *out);

#endif
