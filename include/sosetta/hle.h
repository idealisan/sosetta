#ifndef SOSETTA_HLE_H
#define SOSETTA_HLE_H

#include "sosetta/cpu.h"
#include "sosetta/macho.h"

#include <stddef.h>

#define HLE_TRAP_BASE  0x7F000000u
#define HLE_TRAP_SIZE  0x8000u

int sosetta_hle_bind(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                     const sosetta_macho *im);
void sosetta_hle_call(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                      uint32_t id, const uint32_t *a, uint32_t *ret);
void sosetta_hle_set_errno(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                           uint32_t darwin_errno);

#endif
