#ifndef SOSETTA_SYSCALL_H
#define SOSETTA_SYSCALL_H

#include <stdint.h>
#include <stddef.h>

typedef struct sosetta_guest sosetta_guest;

#define SOSETTA_PPC_EXCP_SYSCALL 8u

#define DARWIN_SYS_exit    1
#define DARWIN_SYS_read    3
#define DARWIN_SYS_write   4
#define DARWIN_SYS_open    5
#define DARWIN_SYS_close   6
#define DARWIN_SYS_unlink  10
#define DARWIN_SYS_getpid  20
#define DARWIN_SYS_lseek   199
#define DARWIN_SYS_mmap    197
#define DARWIN_SYS_munmap  198

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
    int trap_pending;
    uint32_t resume_pc;
    uint32_t errno_addr;
    sosetta_guest *guest;
} sosetta_syscall_ctx;

void sosetta_syscall_hook(sosetta_guest *g, uint32_t intno);
void sosetta_bsd_syscall(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                         uint32_t nr, const uint32_t *a, uint32_t *ret);
int sosetta_syscall_errno_to_darwin(int linux_errno);

#endif