#ifndef SOSETTA_DEBUG_H
#define SOSETTA_DEBUG_H

#include <stddef.h>
#include <stdint.h>

#include "sosetta/cpu.h"
#include "sosetta/macho.h"

struct sosetta_debug_symtab {
    struct sosetta_debug_syment {
        uint32_t addr;
        uint32_t idx;
    } *entries;
    size_t count;
    const uint8_t *data;
    uint32_t symoff;
    uint32_t stroff;
    uint32_t strsize;
};

int sosetta_debug_symtab_load(const uint8_t *data, size_t size,
                              struct sosetta_debug_symtab *st);
void sosetta_debug_symtab_free(struct sosetta_debug_symtab *st);
void sosetta_debug_symtab_sym(const struct sosetta_debug_symtab *st,
                              uint32_t addr, char *buf, size_t cap);

void sosetta_debug_init(sosetta_guest *g, const sosetta_macho *im);
void sosetta_debug_shutdown(void);
void sosetta_debug_sym(uint32_t addr, char *buf, size_t cap);
void sosetta_debug_report(sosetta_guest *g, const char *reason, uint32_t pc);

#endif
