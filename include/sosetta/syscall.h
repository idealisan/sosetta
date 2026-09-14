#ifndef SOSETTA_SYSCALL_H
#define SOSETTA_SYSCALL_H

#include <stdint.h>
#include <stddef.h>

typedef struct sosetta_guest sosetta_guest;

#define SOSETTA_PPC_EXCP_SYSCALL 8u

typedef struct sosetta_syscall_ctx {
    int (*mem_map)(void *data, uint32_t addr, uint32_t size, uint32_t prot);
    int (*mem_unmap)(void *data, uint32_t addr, uint32_t size);
    void *mem_data;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    uint32_t map_hint;
    int should_stop;
    int exit_code;
    sosetta_guest *guest;
} sosetta_syscall_ctx;

void sosetta_syscall_hook(sosetta_guest *g, uint32_t intno);
int sosetta_syscall_errno_to_darwin(int linux_errno);

#endif