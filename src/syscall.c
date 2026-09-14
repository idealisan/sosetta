#define _POSIX_C_SOURCE 200809L

#include "sosetta/syscall.h"
#include "sosetta/cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DARWIN_SYS_exit    1
#define DARWIN_SYS_fork    2
#define DARWIN_SYS_read    3
#define DARWIN_SYS_write   4
#define DARWIN_SYS_open    5
#define DARWIN_SYS_close   6
#define DARWIN_SYS_unlink  10
#define DARWIN_SYS_getpid  20
#define DARWIN_SYS_lseek   199
#define DARWIN_SYS_mmap    197
#define DARWIN_SYS_munmap  198

#define DARWIN_PROT_READ  0x1u
#define DARWIN_PROT_WRITE 0x2u
#define DARWIN_PROT_EXEC  0x4u

#define DARWIN_O_CREAT    0x0200u
#define DARWIN_O_EXCL     0x0800u
#define DARWIN_O_TRUNC    0x0400u
#define DARWIN_O_APPEND   0x0008u
#define DARWIN_O_NONBLOCK 0x0004u
#define DARWIN_O_ACCMODE  0x0003u

#define DARWIN_MAP_ANON   0x1000u
#define DARWIN_MAP_FIXED  0x0010u

#define MAX_IO_SIZE (1u << 20)

int sosetta_syscall_errno_to_darwin(int linux_errno)
{
    static const struct {
        int darwin;
        int linux;
    } table[] = {
        {1, EPERM}, {2, ENOENT}, {3, ESRCH}, {4, EINTR}, {5, EIO},
        {6, ENXIO}, {7, E2BIG}, {8, ENOEXEC}, {9, EBADF}, {10, ECHILD},
        {11, EDEADLK}, {12, ENOMEM}, {13, EACCES}, {14, EFAULT},
        {15, ENOTBLK}, {16, EBUSY}, {17, EEXIST}, {18, EXDEV},
        {19, ENODEV}, {20, ENOTDIR}, {21, EISDIR}, {22, EINVAL},
        {23, ENFILE}, {24, EMFILE}, {25, ENOTTY}, {26, ETXTBSY},
        {27, EFBIG}, {28, ENOSPC}, {29, ESPIPE}, {30, EROFS},
        {31, EMLINK}, {32, EPIPE}, {33, EDOM}, {34, ERANGE},
        {35, EAGAIN}, {36, EINPROGRESS}, {37, EALREADY}, {38, ENOTSOCK},
        {39, EDESTADDRREQ}, {40, EMSGSIZE}, {41, EPROTOTYPE},
        {42, ENOPROTOOPT}, {43, EPROTONOSUPPORT}, {44, ESOCKTNOSUPPORT},
        {45, EOPNOTSUPP}, {46, EPFNOSUPPORT}, {47, EAFNOSUPPORT},
        {48, EADDRINUSE}, {49, EADDRNOTAVAIL}, {50, ENETDOWN},
        {51, ENETUNREACH}, {52, ENETRESET}, {53, ECONNABORTED},
        {54, ECONNRESET}, {55, ENOBUFS}, {56, EISCONN}, {57, ENOTCONN},
        {58, ESHUTDOWN}, {59, ETOOMANYREFS}, {60, ETIMEDOUT},
        {61, ECONNREFUSED}, {62, ELOOP}, {63, ENAMETOOLONG},
        {64, EHOSTDOWN}, {65, EHOSTUNREACH}, {66, ENOTEMPTY},
        {68, EUSERS}, {69, EDQUOT}, {70, ESTALE}, {78, ENOSYS},
        {86, EOVERFLOW}, {91, ECANCELED}, {92, EIDRM}, {93, ENOMSG},
        {94, EILSEQ},
    };
    size_t i;

    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (table[i].linux == linux_errno) {
            return table[i].darwin;
        }
    }
    return linux_errno;
}

static int32_t fail_linux(int linux_errno)
{
    return -(int32_t)sosetta_syscall_errno_to_darwin(linux_errno);
}

static int read_guest_string(sosetta_guest *g, uint32_t addr, char *buf,
                             size_t cap)
{
    size_t i;

    for (i = 0; i + 1 < cap; i++) {
        char c;
        if (sosetta_guest_read(g, addr + (uint32_t)i, &c, 1) != 0) {
            return 1;
        }
        buf[i] = c;
        if (c == '\0') {
            return 0;
        }
    }
    buf[cap - 1] = '\0';
    return 0;
}

static int translate_open_flags(uint32_t dflags, int *out)
{
    int f = (int)(dflags & DARWIN_O_ACCMODE);

    if (dflags & DARWIN_O_CREAT) f |= O_CREAT;
    if (dflags & DARWIN_O_EXCL) f |= O_EXCL;
    if (dflags & DARWIN_O_TRUNC) f |= O_TRUNC;
    if (dflags & DARWIN_O_APPEND) f |= O_APPEND;
    if (dflags & DARWIN_O_NONBLOCK) f |= O_NONBLOCK;
    *out = f;
    return 0;
}

static int guest_mmap_anon(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                           const uint32_t *args, uint32_t *ret)
{
    uint32_t addr = args[0];
    uint32_t size = args[1];
    uint32_t prot = args[2];
    uint32_t flags = args[3];
    uint32_t asked = size;
    int fixed = (flags & DARWIN_MAP_FIXED) != 0;

    if (size == 0) {
        return 1;
    }
    size = (size + 0xFFFu) & ~0xFFFu;

    if (fixed) {
        if (addr & 0xFFFu) {
            return 1;
        }
    } else {
        addr = ctx->map_hint;
        if (addr & 0xFFFu) {
            addr = (addr + 0xFFFu) & ~0xFFFu;
        }
    }

    if (ctx->mem_map(ctx->mem_data, addr, size, prot) != 0) {
        return 1;
    }

    if (!fixed) {
        ctx->map_hint = addr + size;
    }
    *ret = (int32_t)addr;
    (void)g;
    (void)asked;
    return 0;
}

static int guest_munmap_anon(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                             const uint32_t *args, uint32_t *ret)
{
    uint32_t addr = args[0];
    uint32_t size = args[1];

    (void)g;
    if (ctx->mem_unmap(ctx->mem_data, addr, size) != 0) {
        return 1;
    }
    *ret = 0;
    return 0;
}

static void dispatch(sosetta_guest *g, sosetta_syscall_ctx *ctx, uint32_t nr,
                     const uint32_t *a, uint32_t *ret)
{
    int fd;
    char path[4096];

    switch (nr) {
    case DARWIN_SYS_exit:
        ctx->exit_code = (int)(int32_t)a[0];
        ctx->should_stop = 1;
        uc_emu_stop(g->uc);
        return;

    case DARWIN_SYS_fork:
    default:
        *ret = (uint32_t)fail_linux(ENOSYS);
        return;

    case DARWIN_SYS_unlink:
        if (read_guest_string(g, a[0], path, sizeof(path)) != 0) {
            *ret = (uint32_t)fail_linux(EFAULT);
        } else {
            *ret = (uint32_t)(unlink(path) != 0 ? fail_linux(errno) : 0);
        }
        return;

    case DARWIN_SYS_getpid:
        *ret = (uint32_t)getpid();
        return;

    case DARWIN_SYS_close: {
        ssize_t r = close((int)(int32_t)a[0]);
        *ret = (uint32_t)(r != 0 ? fail_linux(errno) : (int32_t)r);
        return;
    }

    case DARWIN_SYS_lseek: {
        off_t r = lseek((int)(int32_t)a[0], (off_t)(int32_t)a[1],
                        (int)(int32_t)a[2]);
        *ret = r >= 0 ? (uint32_t)(int32_t)r
                      : (uint32_t)fail_linux(errno);
        return;
    }

    case DARWIN_SYS_open: {
        if (read_guest_string(g, a[0], path, sizeof(path)) != 0) {
            *ret = (uint32_t)fail_linux(EFAULT);
            return;
        }
        if (translate_open_flags(a[1], &fd) != 0) {
            *ret = (uint32_t)fail_linux(EINVAL);
            return;
        }
        fd = open(path, fd, (mode_t)(a[2] & 0x1FFu));
        *ret = fd >= 0 ? (uint32_t)fd : (uint32_t)fail_linux(errno);
        return;
    }

    case DARWIN_SYS_read: {
        uint32_t n = a[2];
        uint8_t *buf;

        if (n > MAX_IO_SIZE) {
            n = MAX_IO_SIZE;
        }
        buf = (uint8_t *)malloc(n ? n : 1);
        if (!buf) {
            *ret = (uint32_t)fail_linux(ENOMEM);
            return;
        }
        fd = read((int)(int32_t)a[0], buf, n);
        if (fd >= 0) {
            if (sosetta_guest_write(g, a[1], buf, (size_t)fd) != 0) {
                *ret = (uint32_t)fail_linux(EFAULT);
            } else {
                *ret = (uint32_t)fd;
            }
        } else {
            *ret = (uint32_t)fail_linux(errno);
        }
        free(buf);
        return;
    }

    case DARWIN_SYS_write: {
        uint32_t n = a[2];
        uint8_t *buf;
        ssize_t total = 0;
        ssize_t r = 1;

        if (n > MAX_IO_SIZE) {
            n = MAX_IO_SIZE;
        }
        buf = (uint8_t *)malloc(n ? n : 1);
        if (!buf) {
            *ret = (uint32_t)fail_linux(ENOMEM);
            return;
        }
        if (sosetta_guest_read(g, a[1], buf, n) != 0) {
            free(buf);
            *ret = (uint32_t)fail_linux(EFAULT);
            return;
        }
        while (total < (ssize_t)n) {
            r = write((int)(int32_t)a[0], buf + total, n - (size_t)total);
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            total += r;
        }
        if (r < 0) {
            *ret = (uint32_t)fail_linux(errno);
        } else {
            *ret = (uint32_t)total;
        }
        free(buf);
        return;
    }

    case DARWIN_SYS_mmap:
        if (guest_mmap_anon(g, ctx, a, ret) != 0) {
            *ret = (uint32_t)fail_linux(EINVAL);
        }
        return;

    case DARWIN_SYS_munmap:
        if (guest_munmap_anon(g, ctx, a, ret) != 0) {
            *ret = (uint32_t)fail_linux(EINVAL);
        }
        return;
    }
}

void sosetta_syscall_hook(sosetta_guest *g, uint32_t intno)
{
    sosetta_syscall_ctx *ctx;
    uint32_t nr;
    uint32_t a[8];
    uint32_t ret = 0;
    unsigned i;

    (void)intno;
    if (!g) {
        return;
    }
    ctx = g->sys;
    if (!ctx) {
        return;
    }

    if (sosetta_guest_get_gpr(g, 0, &nr) != 0) {
        nr = 0;
    }
    for (i = 0; i < 8; i++) {
        if (sosetta_guest_get_gpr(g, 3 + i, &a[i]) != 0) {
            a[i] = 0;
        }
    }

    dispatch(g, ctx, nr, a, &ret);
    sosetta_guest_set_gpr(g, 3, ret);
}