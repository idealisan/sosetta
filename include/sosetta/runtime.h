#ifndef SOSETTA_RUNTIME_H
#define SOSETTA_RUNTIME_H

#include <stdint.h>
#include <stddef.h>
#include <unicorn/unicorn.h>
#include "sosetta/macho.h"
#include "sosetta/cpu.h"
#include "sosetta/syscall.h"

#define SOSETTA_STACK_SIZE  0x10000u
#define SOSETTA_STACK_TOP   0x80000000u

typedef struct sosetta_runtime {
    sosetta_macho im;
    uint8_t *filebuf;
    size_t filelen;
    sosetta_guest *guest;
    sosetta_syscall_ctx sys;
    uint32_t stack_top;
    uint32_t stack_base;
    uint32_t entry_pc;
    int map_hint;
    int exit_code;
    int ran;
} sosetta_runtime;

int sosetta_runtime_open(sosetta_runtime *rt, const char *path,
                         char *errbuf, size_t errsz);
int sosetta_runtime_open_bytes(sosetta_runtime *rt, const uint8_t *data,
                               size_t size, char *errbuf, size_t errsz);
void sosetta_runtime_close(sosetta_runtime *rt);

int sosetta_runtime_load(sosetta_runtime *rt);
int sosetta_runtime_setup_stack(sosetta_runtime *rt, int argc, char **argv,
                                char **envp);
int sosetta_runtime_run(sosetta_runtime *rt);

#endif