#define _POSIX_C_SOURCE 200809L

#include "sosetta/hle.h"
#include "sosetta/syscall.h"
#include "sosetta/cpu.h"
#include "sosetta/endian.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MISC_BASE   0x7E100000u
#define SHIM_BASE   0x7E400000u
#define SHIM_SIZE   0x1000u
#define MISC_SIZE   0x1000u
#define RUNE_BASE   0x7E200000u
#define RUNE_SIZE   0x2000u
#define SF_BASE     0x7E300000u
#define SF_SIZE     0x1000u
#define HEAP_BASE   0x60000000u
#define HEAP_SIZE   0x04000000u

#define SF_SLOTS  20
#define SF_STRIDE 152u

#define ERRNO_ADDR     (MISC_BASE + 0u)
#define CTHREAD_ADDR   (MISC_BASE + 8u)
#define MACHINIT_ADDR  (MISC_BASE + 12u)
#define STRBUF_ADDR    (MISC_BASE + 16u)
#define TM_ADDR        (MISC_BASE + 64u)
#define DIRENT_ADDR    (MISC_BASE + 128u)
#define GAI_ADDR       (MISC_BASE + 256u)

#define TRACE_MAX_LINES 256u

typedef struct hle_env {
    sosetta_guest *g;
    sosetta_syscall_ctx *ctx;
    const uint32_t *a;
    uint32_t ret;
    int has_hi;
    uint32_t ret_hi;
    int has_fret;
    double fret;
    int has_redirect;
    uint32_t redirect_pc;
    uint32_t call_r3;
    uint32_t call_r4;
    uint32_t call_lr;
} hle_env;

#define TRAP_BSEARCH_RET (HLE_TRAP_BASE + 4u * 0x3FFu)

static struct bsearch_state {
    int active;
    uint32_t key;
    uint32_t base;
    uint32_t size;
    uint32_t compar;
    uint32_t orig_lr;
    int lo;
    int hi;
    int mid;
} bs;

static struct pthread_sync_state {
    int active;
    uint32_t caller_lr;
} pts;

#define TRAP_PTHREAD_RET (HLE_TRAP_BASE + 4u * 0x3FEu)

static int trace_state = -1;

static int trace_enabled(void)
{
    if (trace_state < 0) {
        trace_state = getenv("SOSETTA_TRACE") != NULL;
    }
    return trace_state;
}

static int g_read(sosetta_guest *g, uint32_t addr, void *buf, size_t n)
{
    return sosetta_guest_read(g, addr, buf, n);
}

static uint32_t hle_image_header;

static int g_write(sosetta_guest *g, uint32_t addr, const void *buf, size_t n);

#define SHIM_RET1   (SHIM_BASE + 0x40u)
#define SHIM_RET0   (SHIM_BASE + 0x60u)
#define TRAP_HEADER (HLE_TRAP_BASE + 4u * 0x3Fu)
#define TRAP_NAME   (HLE_TRAP_BASE + 4u * 0x3Eu)

static void hle_dyld_get_image_header(hle_env *e)
{
    e->ret = hle_image_header;
}

static void hle_dyld_get_image_name(hle_env *e)
{
    static const char nm[] = "program";
    g_write(e->g, GAI_ADDR + 32u, nm, sizeof(nm));
    e->ret = GAI_ADDR + 32u;
}

static void hle_dyld_func_lookup(hle_env *e);

static int g_write(sosetta_guest *g, uint32_t addr, const void *buf, size_t n)
{
    return sosetta_guest_write(g, addr, buf, n);
}

static int g_read_str(sosetta_guest *g, uint32_t addr, char *buf, size_t cap)
{
    size_t i;

    for (i = 0; i + 1 < cap; i++) {
        char c;
        if (g_read(g, addr + (uint32_t)i, &c, 1) != 0) {
            return -1;
        }
        buf[i] = c;
        if (c == '\0') {
            return 0;
        }
    }
    buf[cap - 1] = '\0';
    return 0;
}

static uint32_t gerr(int darwin_errno)
{
    return (uint32_t)(-(int32_t)darwin_errno);
}

static void hle_set_errno(hle_env *e, uint32_t darwin_errno)
{
    sosetta_hle_set_errno(e->g, e->ctx, darwin_errno);
}

static uint32_t arg_at(hle_env *e, unsigned i)
{
    uint32_t sp;

    if (i < 8) {
        return e->a[i];
    }
    if (sosetta_guest_get_gpr(e->g, 1, &sp) != 0) {
        return 0;
    }
    {
        uint32_t v = 0;
        g_read(e->g, sp + 56u + 4u * (i - 8u), &v, 4);
        return v;
    }
}

static void route_bsd(hle_env *e, uint32_t nr, const uint32_t *args)
{
    uint32_t r = 0;
    sosetta_bsd_syscall(e->g, e->ctx, nr, args, &r);
    e->ret = r;
}

static uint32_t heap_free_head;

static void heap_init(sosetta_guest *g)
{
    uint8_t hdr[8];
    put_be32(hdr, HEAP_SIZE - 8u);
    put_be32(hdr + 4, 0);
    g_write(g, HEAP_BASE, hdr, 8);
    heap_free_head = HEAP_BASE;
}

static uint32_t halloc(sosetta_guest *g, uint32_t n)
{
    uint32_t need = ((n + 15u) & ~15u) + 8u;
    uint32_t prev = 0;
    uint32_t cur;
    uint8_t hdr[8];

    if (need < 8u || need > HEAP_SIZE) {
        if (trace_enabled()) {
            fprintf(stderr, "[sosetta] halloc REJECT n=%u need=%u\n", n, need);
        }
        return 0;
    }
    if (heap_free_head == 0) {
        heap_init(g);
    }
    cur = heap_free_head;
    while (cur != 0 && cur + 8u <= HEAP_BASE + HEAP_SIZE) {
        uint32_t size;
        uint32_t next;
        if (g_read(g, cur, hdr, 8) != 0) {
            return 0;
        }
        size = be32(hdr);
        next = be32(hdr + 4);
        if ((size & 1u) == 0 && size >= need) {
            uint32_t rem = size - need;
            if (rem >= 16u) {
                put_be32(hdr, rem);
                put_be32(hdr + 4, next);
                g_write(g, cur + need, hdr, 8);
                if (prev == 0) {
                    heap_free_head = cur + need;
                } else {
                    uint8_t p[4];
                    put_be32(p, cur + need);
                    g_write(g, prev + 4, p, 4);
                }
            } else {
                if (prev == 0) {
                    heap_free_head = next;
                } else {
                    uint8_t p[4];
                    put_be32(p, next);
                    g_write(g, prev + 4, p, 4);
                }
                need = size;
            }
            put_be32(hdr, need | 1u);
            g_write(g, cur, hdr, 4);
            return cur + 8u;
        }
        prev = cur;
        cur = next;
    }
    if (trace_enabled()) {
        fprintf(stderr, "[sosetta] halloc FAIL n=%u need=%u\n", n, need);
    }
    return 0;
}

static void hfree(sosetta_guest *g, uint32_t p)
{
    uint8_t hdr[8];
    uint8_t w4[4];
    uint32_t h;
    uint32_t size;
    uint32_t prev;
    uint32_t cur;
    uint32_t next;

    if (p == 0 || p < HEAP_BASE + 8u || p >= HEAP_BASE + HEAP_SIZE) {
        return;
    }
    h = p - 8u;
    if (g_read(g, h, hdr, 4) != 0) {
        return;
    }
    size = be32(hdr) & ~1u;
    prev = 0;
    cur = heap_free_head;
    while (cur != 0 && cur < h) {
        uint32_t curn;
        if (g_read(g, cur + 4, w4, 4) != 0) {
            return;
        }
        curn = be32(w4);
        prev = cur;
        cur = curn;
    }
    if (g_read(g, cur, hdr, 8) == 0 && cur != 0) {
        return;
    }
    next = (cur != 0) ? be32(hdr + 4) : 0;
    if (cur != 0) {
        uint8_t full[8];
        if (g_read(g, cur, full, 8) != 0) {
            return;
        }
        next = be32(full + 4);
    }
    put_be32(hdr, size);
    put_be32(hdr + 4, cur);
    g_write(g, h, hdr, 8);
    if (prev == 0) {
        heap_free_head = h;
    } else {
        uint8_t p4[4];
        put_be32(p4, h);
        g_write(g, prev + 4, p4, 4);
    }
    if (cur != 0 && h + size == cur) {
        uint8_t c[8];
        if (g_read(g, cur, c, 8) == 0) {
            return;
        }
        size += be32(c);
        put_be32(hdr, size);
        put_be32(hdr + 4, be32(c + 4));
        g_write(g, h, hdr, 8);
    }
    if (prev != 0) {
        uint8_t p8[8];
        uint32_t psize;
        if (g_read(g, prev, p8, 8) != 0) {
            return;
        }
        psize = be32(p8);
        if (prev + psize == h) {
            put_be32(p8, psize + size);
            put_be32(p8 + 4, next);
            g_write(g, prev, p8, 8);
        }
    }
}

#define FDMAP_SIZE 256
#define FDMAP_BASE 64

static int fdmap[FDMAP_SIZE];
static int fdmap_next = FDMAP_BASE;

static int hle_host_fd(int gfd)
{
    if (gfd >= 0 && gfd < 3) {
        return gfd;
    }
    if (gfd >= FDMAP_BASE && gfd < FDMAP_BASE + FDMAP_SIZE) {
        return fdmap[gfd - FDMAP_BASE];
    }
    return -1;
}

uint32_t sosetta_hle_alloc_zeroed(sosetta_guest *g, uint32_t size)
{
    return halloc(g, size);
}

int sosetta_hle_host_fd(int guest_fd)
{
    return hle_host_fd(guest_fd);
}

static int hle_alloc_gfd(int host_fd)
{
    int i;
    for (i = 0; i < FDMAP_SIZE; i++) {
        int slot = (fdmap_next - FDMAP_BASE + i) % FDMAP_SIZE;
        if (fdmap[slot] == -1) {
            fdmap[slot] = host_fd;
            fdmap_next = FDMAP_BASE + slot + 1;
            return FDMAP_BASE + slot;
        }
    }
    return -1;
}

static void hle_free_gfd(int gfd)
{
    if (gfd >= FDMAP_BASE && gfd < FDMAP_BASE + FDMAP_SIZE) {
        fdmap[gfd - FDMAP_BASE] = -1;
    }
}

static void hle_socket_init(void)
{
    int i;
    for (i = 0; i < FDMAP_SIZE; i++) {
        fdmap[i] = -1;
    }
    fdmap_next = FDMAP_BASE;
}

#define SF_SLOTS 20
#define SF_STRIDE 152u

static FILE *sf_host[SF_SLOTS];
static int sf_kind[SF_SLOTS];
static int sf_eof[SF_SLOTS];
static int sf_err[SF_SLOTS];
static int sf_fd[SF_SLOTS];

static int sf_slot_of(uint32_t gaddr)
{
    if (gaddr < SF_BASE || gaddr >= SF_BASE + (uint32_t)SF_SLOTS * SF_STRIDE) {
        return -1;
    }
    return (int)((gaddr - SF_BASE) / SF_STRIDE);
}

#define SF_KIND_FREE 0
#define SF_KIND_STD  1
#define SF_KIND_FILE 2
#define SF_KIND_DIR  3

static int sf_take(void)
{
    int i;
    for (i = 3; i < SF_SLOTS; i++) {
        if (sf_kind[i] == SF_KIND_FREE) {
            return i;
        }
    }
    return -1;
}

static void hle_socket(hle_env *e)
{
    int host_fd;
    if (e->a[0] != 2u) {
        hle_set_errno(e, 43);
        e->ret = gerr(43);
        return;
    }
    host_fd = socket(AF_INET, (int)(e->a[1] & 0xFFu), 0);
    if (host_fd < 0) {
        hle_set_errno(e, 78);
        e->ret = gerr(78);
        return;
    }
    {
        int gfd = hle_alloc_gfd(host_fd);
        if (gfd < 0) {
            close(host_fd);
            hle_set_errno(e, 24);
            e->ret = gerr(24);
            return;
        }
        e->ret = (uint32_t)gfd;
    }
}

static void hle_connect(hle_env *e)
{
    int host_fd = hle_host_fd((int)(int32_t)e->a[0]);
    uint8_t sa[16];
    struct sockaddr_in sin;
    if (host_fd < 0) {
        hle_set_errno(e, 9);
        e->ret = gerr(9);
        return;
    }
    if (g_read(e->g, e->a[1], sa, 16) != 0) {
        hle_set_errno(e, 14);
        e->ret = gerr(14);
        return;
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_port, sa + 2, 2);
    memcpy(&sin.sin_addr, sa + 4, 4);
    if (connect(host_fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        hle_set_errno(e, (uint32_t)sosetta_syscall_errno_to_darwin(errno));
        e->ret = gerr(78);
        return;
    }
    e->ret = 0;
}

static void hle_send(hle_env *e)
{
    int host_fd = hle_host_fd((int)(int32_t)e->a[0]);
    static uint8_t tmp[1u << 20];
    uint32_t n = e->a[2];
    ssize_t r;
    if (host_fd < 0) {
        hle_set_errno(e, 9);
        e->ret = gerr(9);
        return;
    }
    if (n > sizeof(tmp)) {
        n = sizeof(tmp);
    }
    if (n && g_read(e->g, e->a[1], tmp, n) != 0) {
        hle_set_errno(e, 14);
        e->ret = gerr(14);
        return;
    }
    r = send(host_fd, tmp, n, (int)e->a[3]);
    if (r < 0) {
        hle_set_errno(e, (uint32_t)sosetta_syscall_errno_to_darwin(errno));
        e->ret = gerr(78);
        return;
    }
    e->ret = (uint32_t)r;
}

static void hle_recv(hle_env *e)
{
    int host_fd = hle_host_fd((int)(int32_t)e->a[0]);
    static uint8_t tmp[1u << 20];
    uint32_t n = e->a[2];
    ssize_t r;
    if (host_fd < 0) {
        hle_set_errno(e, 9);
        e->ret = gerr(9);
        return;
    }
    if (n > sizeof(tmp)) {
        n = sizeof(tmp);
    }
    r = recv(host_fd, tmp, n, (int)e->a[3]);
    if (r < 0) {
        hle_set_errno(e, (uint32_t)sosetta_syscall_errno_to_darwin(errno));
        e->ret = gerr(78);
        return;
    }
    if (r > 0) {
        g_write(e->g, e->a[1], tmp, (size_t)r);
    }
    e->ret = (uint32_t)r;
}

static void hle_close_socket(hle_env *e)
{
    int host_fd = hle_host_fd((int)(int32_t)e->a[0]);
    if (host_fd >= 0 && e->a[0] >= FDMAP_BASE) {
        close(host_fd);
        hle_free_gfd((int)(int32_t)e->a[0]);
        e->ret = 0;
        return;
    }
    {
        uint32_t args[4] = { e->a[0], 0, 0, 0 };
        route_bsd(e, DARWIN_SYS_close, args);
    }
}

static void hle_getsockopt(hle_env *e)
{
    if (e->a[1] == 0xFFFFu && e->a[2] == 0x1007u && e->a[4]) {
        uint32_t zero = 0;
        uint32_t four = 4;
        g_write(e->g, e->a[4], &zero, 4);
        if (e->a[5]) {
            g_write(e->g, e->a[5], &four, 4);
        }
        e->ret = 0;
        return;
    }
    e->ret = 0;
}

static void hle_select(hle_env *e)
{
    fd_set rfds;
    fd_set wfds;
    fd_set *rp = NULL;
    fd_set *wp = NULL;
    uint8_t gset[128];
    struct timeval tv;
    uint32_t sec;
    uint32_t usec;
    int r;
    int gfd;
    int host;
    uint32_t addrs[3];
    int i;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    addrs[0] = e->a[1];
    addrs[1] = e->a[2];
    addrs[2] = e->a[3];
    for (i = 0; i < 2; i++) {
        if (!addrs[i]) {
            continue;
        }
        memset(gset, 0, sizeof(gset));
        if (g_read(e->g, addrs[i], gset, 128) != 0) {
            continue;
        }
        for (gfd = 0; gfd < FDMAP_BASE + FDMAP_SIZE; gfd++) {
            if (!(gset[gfd >> 3] & (1u << (gfd & 7u)))) {
                continue;
            }
            host = hle_host_fd(gfd);
            if (host < 0 || host >= 1024) {
                continue;
            }
            if (i == 0) {
                FD_SET(host, &rfds);
                rp = &rfds;
            } else {
                FD_SET(host, &wfds);
                wp = &wfds;
            }
        }
    }
    sec = 0;
    usec = 0;
    if (e->a[4]) {
        uint8_t tmp[8];
        if (g_read(e->g, e->a[4], tmp, 8) == 0) {
            sec = be32(tmp);
            usec = be32(tmp + 4);
        }
        tv.tv_sec = (time_t)sec;
        tv.tv_usec = (suseconds_t)usec;
    }
    r = select(1024, rp, wp, NULL, e->a[4] ? &tv : NULL);
    if (r < 0) {
        hle_set_errno(e, (uint32_t)sosetta_syscall_errno_to_darwin(errno));
        e->ret = gerr(78);
        return;
    }
    for (i = 0; i < 2; i++) {
        fd_set *hs = (i == 0) ? rp : wp;
        if (!addrs[i]) {
            continue;
        }
        memset(gset, 0, 128);
        if (hs) {
            for (gfd = 0; gfd < FDMAP_BASE + FDMAP_SIZE; gfd++) {
                host = hle_host_fd(gfd);
                if (host < 0 || host >= 1024) {
                    continue;
                }
                if (FD_ISSET(host, hs)) {
                    gset[gfd >> 3] |= (uint8_t)(1u << (gfd & 7u));
                }
            }
        }
        g_write(e->g, addrs[i], gset, 128);
    }
    e->ret = (uint32_t)r;
}

static void hle_write_darwin_stat(hle_env *e, uint32_t buf, struct stat *st)
{
    uint8_t tmp[108];
    memset(tmp, 0, sizeof(tmp));
    put_be32(tmp, (uint32_t)st->st_dev);
    put_be32(tmp + 4, (uint32_t)st->st_ino);
    put_be16(tmp + 8, (uint16_t)st->st_mode);
    put_be16(tmp + 10, (uint16_t)st->st_nlink);
    put_be32(tmp + 12, (uint32_t)st->st_uid);
    put_be32(tmp + 16, (uint32_t)st->st_gid);
    put_be32(tmp + 20, (uint32_t)st->st_rdev);
    put_be32(tmp + 28, (uint32_t)st->st_mtim.tv_sec);
    put_be32(tmp + 32, (uint32_t)st->st_mtim.tv_nsec * 1000u);
    put_be32(tmp + 36, (uint32_t)st->st_ctim.tv_sec);
    put_be32(tmp + 40, (uint32_t)st->st_ctim.tv_nsec * 1000u);
    put_be64(tmp + 48, (uint64_t)st->st_size);
    put_be32(tmp + 60, (uint32_t)st->st_blksize);
    put_be32(tmp + 64, (uint32_t)(st->st_blocks * 8u));
    g_write(e->g, buf, tmp, sizeof(tmp));
}

static void hle_fstat(hle_env *e)
{
    int host_fd = hle_host_fd((int)(int32_t)e->a[0]);
    struct stat st;
    if (host_fd < 0 || fstat(host_fd, &st) != 0) {
        hle_set_errno(e, 9);
        e->ret = gerr(9);
        return;
    }
    hle_write_darwin_stat(e, e->a[1], &st);
    e->ret = 0;
}

static void hle_stat(hle_env *e)
{
    char path[4096];
    struct stat st;
    g_read_str(e->g, e->a[0], path, sizeof(path));
    if (stat(path, &st) != 0) {
        hle_set_errno(e, (uint32_t)sosetta_syscall_errno_to_darwin(errno));
        e->ret = gerr(2);
        return;
    }
    hle_write_darwin_stat(e, e->a[1], &st);
    e->ret = 0;
}

static void hle_getaddrinfo(hle_env *e)
{
    char node[256];
    char service[64];
    uint8_t hints[32];
    int family = 0;
    uint32_t ai_ptr;
    uint32_t sa_ptr;
    uint8_t ai[32];
    uint8_t sa[16];
    unsigned long port = 0;
    struct in_addr addr4;

    if (!e->a[0] || !e->a[3]) {
        e->ret = 8;
        return;
    }
    g_read_str(e->g, e->a[0], node, sizeof(node));
    if (e->a[1]) {
        g_read_str(e->g, e->a[1], service, sizeof(service));
        port = strtoul(service, NULL, 10);
    }
    memset(hints, 0, sizeof(hints));
    if (e->a[2]) {
        g_read(e->g, e->a[2], hints, 32);
        family = (int)(int32_t)be32(hints + 4);
    }
    if (family != 0 && family != 2) {
        e->ret = 9;
        return;
    }
    if (inet_pton(AF_INET, node, &addr4) != 1) {
        e->ret = 8;
        return;
    }
    ai_ptr = halloc(e->g, 32);
    sa_ptr = halloc(e->g, 16);
    if (!ai_ptr || !sa_ptr) {
        e->ret = 12;
        return;
    }
    memset(sa, 0, sizeof(sa));
    sa[0] = 16;
    sa[1] = 2;
    put_be16(sa + 2, (uint16_t)(port & 0xFFFFu));
    memcpy(sa + 4, &addr4, 4);
    memset(ai, 0, sizeof(ai));
    put_be32(ai + 4, 2);
    put_be32(ai + 8, 1);
    put_be32(ai + 16, 16);
    put_be32(ai + 24, sa_ptr);
    g_write(e->g, sa_ptr, sa, 16);
    g_write(e->g, ai_ptr, ai, 32);
    g_write(e->g, e->a[3], &ai_ptr, 4);
    e->ret = 0;
}

static void hle_freeaddrinfo(hle_env *e)
{
    uint32_t ai_ptr = e->a[0];
    uint32_t sa_ptr = 0;
    uint8_t tmp[4];
    if (ai_ptr && g_read(e->g, ai_ptr + 24u, tmp, 4) == 0) {
        sa_ptr = be32(tmp);
    }
    if (sa_ptr) {
        hfree(e->g, sa_ptr);
    }
    if (ai_ptr) {
        hfree(e->g, ai_ptr);
    }
    e->ret = 0;
}

static void hle_fcntl_real(hle_env *e)
{
    int host_fd = hle_host_fd((int)(int32_t)e->a[0]);
    if (host_fd < 0) {
        e->ret = 0;
        return;
    }
    if (e->a[1] == 4u) {
        e->ret = 0;
        return;
    }
    e->ret = (uint32_t)fcntl(host_fd, (int)e->a[1]);
}

static int sf_read(FILE *hf, int fd, void *buf, size_t n, size_t *got)
{
    if (hf) {
        *got = fread(buf, 1, n, hf);
        return 0;
    }
    if (fd >= 0) {
        ssize_t r = read(fd, buf, n);
        *got = r > 0 ? (size_t)r : 0;
        return r < 0 ? -1 : 0;
    }
    return -1;
}

static int sf_write(FILE *hf, int fd, const void *buf, size_t n, size_t *put)
{
    if (hf) {
        *put = fwrite(buf, 1, n, hf);
        return 0;
    }
    if (fd >= 0) {
        ssize_t r = write(fd, buf, n);
        *put = r > 0 ? (size_t)r : 0;
        return r < 0 ? -1 : 0;
    }
    return -1;
}

static int sf_get_stream(hle_env *e, uint32_t gaddr, FILE **hf, int *fd,
                         int **eof, int **err)
{
    int slot = sf_slot_of(gaddr);
    if (slot < 0 || sf_kind[slot] == SF_KIND_FREE) {
        hle_set_errno(e, 9);
        return -1;
    }
    *hf = (sf_kind[slot] == SF_KIND_FILE) ? sf_host[slot] : NULL;
    *fd = (sf_kind[slot] == SF_KIND_STD) ? sf_fd[slot] : -1;
    *eof = &sf_eof[slot];
    *err = &sf_err[slot];
    return 0;
}

static char obuf[65536];
static size_t olen;

static void obuf_reset(void)
{
    olen = 0;
}

static void obuf_add(const char *s, size_t n)
{
    if (olen + n > sizeof(obuf)) {
        n = sizeof(obuf) - olen;
    }
    memcpy(obuf + olen, s, n);
    olen += n;
}

typedef struct fmt_target {
    int kind;
    sosetta_guest *g;
    FILE *hf;
    int fd;
    uint32_t gbuf;
    uint32_t gcap;
} fmt_target;

static void fmt_flush(fmt_target *t)
{
    size_t put = 0;
    if (olen == 0) {
        return;
    }
    if (t->kind == 1) {
        sf_write(t->hf, t->fd, obuf, olen, &put);
    } else if (t->kind == 2) {
        uint32_t n = (uint32_t)olen;
        if (n > t->gcap - 1u) {
            n = t->gcap - 1u;
        }
        g_write(t->g, t->gbuf, obuf, n);
        {
            uint8_t z = 0;
            g_write(t->g, t->gbuf + n, &z, 1);
        }
    }
    olen = 0;
}

static void vfmt(hle_env *e, fmt_target *t, uint32_t fmt_addr, unsigned vi)
{
    char fmt[8192];
    size_t i = 0;
    unsigned nfloat = 0;

    obuf_reset();
    if (g_read_str(e->g, fmt_addr, fmt, sizeof(fmt)) != 0) {
        return;
    }
    while (fmt[i] != 0) {
        if (fmt[i] != 37) {
            obuf_add(&fmt[i], 1);
            i++;
            continue;
        }
        {
            char spec[32];
            char tmp[512];
            size_t sp = 0;
            size_t j = i;
            int kind = 0;
            uint32_t av;
            double dv = 0.0;

            spec[sp++] = 37;
            j++;
            while (j < sizeof(fmt) && strchr("-+ #0", fmt[j]) != NULL &&
                   fmt[j] != 0 && sp < sizeof(spec) - 8) {
                spec[sp++] = fmt[j++];
            }
            while (j < sizeof(fmt) && (isdigit((unsigned char)fmt[j]) || fmt[j] == 42) &&
                   sp < sizeof(spec) - 8) {
                if (fmt[j] == 42) {
                    av = arg_at(e, vi);
                    vi++;
                    sp += (size_t)snprintf(spec + sp, sizeof(spec) - sp, "%u", av);
                } else {
                    spec[sp++] = fmt[j];
                }
                j++;
            }
            if (fmt[j] == 46 && sp < sizeof(spec) - 8) {
                spec[sp++] = fmt[j++];
                while (j < sizeof(fmt) && (isdigit((unsigned char)fmt[j]) || fmt[j] == 42) &&
                       sp < sizeof(spec) - 8) {
                    if (fmt[j] == 42) {
                        av = arg_at(e, vi);
                        vi++;
                        sp += (size_t)snprintf(spec + sp, sizeof(spec) - sp, "%u", av);
                    } else {
                        spec[sp++] = fmt[j];
                    }
                    j++;
                }
            }
            while ((fmt[j] == 'l' || fmt[j] == 'h' || fmt[j] == 'L') &&
                   sp < sizeof(spec) - 8) {
                spec[sp++] = fmt[j++];
            }
            switch (fmt[j]) {
            case 'd': case 'i':
                if (sp >= 3 && spec[1] == 'l' && spec[2] == 'l') {
                    uint32_t lo = arg_at(e, vi);
                    uint32_t hi = arg_at(e, vi + 1);
                    long long v64 = ((long long)hi << 32) | lo;
                    vi += 2;
                    snprintf(tmp, sizeof(tmp), spec, v64);
                } else {
                    av = arg_at(e, vi);
                    vi++;
                    snprintf(tmp, sizeof(tmp), spec, (int)(int32_t)av);
                }
                kind = 1;
                break;
            case 'u': case 'x': case 'X': case 'o':
                av = arg_at(e, vi);
                vi++;
                snprintf(tmp, sizeof(tmp), spec, av);
                kind = 1;
                break;
            case 'c':
                av = arg_at(e, vi);
                vi++;
                snprintf(tmp, sizeof(tmp), spec, (int)(av & 0xFFu));
                kind = 1;
                break;
            case 'p':
                av = arg_at(e, vi);
                vi++;
                snprintf(tmp, sizeof(tmp), spec, (uintptr_t)av);
                kind = 1;
                break;
            case 's': {
                char sbuf[4096];
                av = arg_at(e, vi);
                vi++;
                if (av == 0) {
                    snprintf(tmp, sizeof(tmp), "(null)");
                } else {
                    g_read_str(e->g, av, sbuf, sizeof(sbuf));
                    snprintf(tmp, sizeof(tmp), spec, sbuf);
                }
                kind = 1;
                break;
            }
            case 'f': case 'F': case 'e': case 'E':
            case 'g': case 'G': {
                uint64_t bits = 0;
                uc_reg_read(e->g->uc, UC_PPC_REG_FPR1 + nfloat, &bits);
                memcpy(&dv, &bits, sizeof(dv));
                nfloat++;
                vi += 2;
                snprintf(tmp, sizeof(tmp), spec, dv);
                kind = 1;
                break;
            }
            case 37:
                obuf_add("%", 1);
                i = j + 1;
                continue;
            default:
                obuf_add(&fmt[i], j - i + 1);
                i = j + 1;
                continue;
            }
            if (kind) {
                obuf_add(tmp, strlen(tmp));
            }
            i = j + 1;
        }
    }
    fmt_flush(t);
}

static void hle_memcpy(hle_env *e)
{
    uint32_t n = e->a[2];
    if (n > (1u << 20)) {
        e->ret = e->a[0];
        return;
    }
    {
        static uint8_t tmp[1u << 20];
        if (g_read(e->g, e->a[1], tmp, n) != 0) {
            e->ret = e->a[0];
            return;
        }
        g_write(e->g, e->a[0], tmp, n);
        e->ret = e->a[0];
    }
}

static void hle_memmove(hle_env *e)
{
    hle_memcpy(e);
}

static void hle_memset(hle_env *e)
{
    uint32_t n = e->a[2];
    if (n > (1u << 20)) {
        e->ret = e->a[0];
        return;
    }
    {
        static uint8_t tmp[1u << 20];
        memset(tmp, (int)(e->a[1] & 0xFFu), n);
        g_write(e->g, e->a[0], tmp, n);
        e->ret = e->a[0];
    }
}

static void hle_memcmp(hle_env *e)
{
    static uint8_t b1[1u << 16];
    static uint8_t b2[1u << 16];
    uint32_t n = e->a[2] > (1u << 16) ? (1u << 16) : e->a[2];
    g_read(e->g, e->a[0], b1, n);
    g_read(e->g, e->a[1], b2, n);
    e->ret = (uint32_t)(int32_t)memcmp(b1, b2, n);
}

static void hle_memchr(hle_env *e)
{
    static uint8_t b[1u << 16];
    uint32_t n = e->a[2] > (1u << 16) ? (1u << 16) : e->a[2];
    void *r;
    g_read(e->g, e->a[0], b, n);
    r = memchr(b, (int)(e->a[1] & 0xFFu), n);
    e->ret = r ? e->a[0] + (uint32_t)((uint8_t *)r - b) : 0;
}

static void hle_strlen(hle_env *e)
{
    char s[65536];
    g_read_str(e->g, e->a[0], s, sizeof(s));
    e->ret = (uint32_t)strlen(s);
}

static void hle_strcpy(hle_env *e)
{
    char s[65536];
    g_read_str(e->g, e->a[1], s, sizeof(s));
    g_write(e->g, e->a[0], s, strlen(s) + 1);
    e->ret = e->a[0];
}

static void hle_stpcpy(hle_env *e)
{
    char s[65536];
    size_t n;
    g_read_str(e->g, e->a[1], s, sizeof(s));
    n = strlen(s) + 1;
    g_write(e->g, e->a[0], s, n);
    e->ret = e->a[0] + (uint32_t)n - 1u;
}

static void hle_strncpy(hle_env *e)
{
    char s[65536];
    uint32_t n = e->a[2];
    if (n > sizeof(s)) {
        n = sizeof(s);
    }
    memset(s, 0, sizeof(s));
    g_read_str(e->g, e->a[1], s, n);
    g_write(e->g, e->a[0], s, e->a[2] > sizeof(s) ? sizeof(s) : e->a[2]);
    e->ret = e->a[0];
}

static void hle_strcat(hle_env *e)
{
    char d[65536];
    char s[65536];
    size_t dl;
    g_read_str(e->g, e->a[0], d, sizeof(d));
    g_read_str(e->g, e->a[1], s, sizeof(s));
    dl = strlen(d);
    if (dl + strlen(s) + 1 < sizeof(d)) {
        strcat(d, s);
        g_write(e->g, e->a[0], d, dl + strlen(s) + 1);
    }
    e->ret = e->a[0];
}

static void hle_strncat(hle_env *e)
{
    char d[65536];
    char s[65536];
    size_t dl;
    uint32_t n = e->a[2];
    g_read_str(e->g, e->a[0], d, sizeof(d));
    g_read_str(e->g, e->a[1], s, sizeof(s));
    if (n > strlen(s)) {
        n = (uint32_t)strlen(s);
    }
    dl = strlen(d);
    if (dl + n + 1 < sizeof(d)) {
        d[dl + n] = '\0';
        memcpy(d + dl, s, n);
        g_write(e->g, e->a[0], d, dl + n + 1);
    }
    e->ret = e->a[0];
}

static void hle_strcmp(hle_env *e)
{
    if (trace_enabled()) {
        char a1[64];
        char a2[64];
        g_read_str(e->g, e->a[0], a1, sizeof(a1));
        g_read_str(e->g, e->a[1], a2, sizeof(a2));
        fprintf(stderr, "[sosetta] strcmp(%.40s, %.40s)\n", a1, a2);
    }
    char s1[65536];
    char s2[65536];
    g_read_str(e->g, e->a[0], s1, sizeof(s1));
    g_read_str(e->g, e->a[1], s2, sizeof(s2));
    e->ret = (uint32_t)(int32_t)strcmp(s1, s2);
}

static void hle_strncmp(hle_env *e)
{
    if (trace_enabled()) {
        char a1[64];
        char a2[64];
        g_read_str(e->g, e->a[0], a1, sizeof(a1));
        g_read_str(e->g, e->a[1], a2, sizeof(a2));
        fprintf(stderr, "[sosetta] strcasecmp(%.40s, %.40s)\n", a1, a2);
    }
    static char s1[65536];
    static char s2[65536];
    uint32_t n = e->a[2] > sizeof(s1) ? sizeof(s1) : e->a[2];
    memset(s1, 0, sizeof(s1));
    memset(s2, 0, sizeof(s2));
    g_read(e->g, e->a[0], s1, n);
    g_read(e->g, e->a[1], s2, n);
    e->ret = (uint32_t)(int32_t)strncmp(s1, s2, n);
}

static void hle_strcasecmp(hle_env *e)
{
    if (trace_enabled()) {
        char a1[64];
        char a2[64];
        g_read_str(e->g, e->a[0], a1, sizeof(a1));
        g_read_str(e->g, e->a[1], a2, sizeof(a2));
        fprintf(stderr, "[sosetta] strcasecmp(%.40s, %.40s)\n", a1, a2);
    }
    char s1[65536];
    char s2[65536];
    g_read_str(e->g, e->a[0], s1, sizeof(s1));
    g_read_str(e->g, e->a[1], s2, sizeof(s2));
    e->ret = (uint32_t)(int32_t)strcasecmp(s1, s2);
}

static void hle_strncasecmp(hle_env *e)
{
    if (trace_enabled()) {
        char a1[64];
        char a2[64];
        g_read_str(e->g, e->a[0], a1, sizeof(a1));
        g_read_str(e->g, e->a[1], a2, sizeof(a2));
        fprintf(stderr, "[sosetta] strcmp(%.40s, %.40s)\n", a1, a2);
    }
    static char s1[65536];
    static char s2[65536];
    uint32_t n = e->a[2] > sizeof(s1) ? sizeof(s1) : e->a[2];
    memset(s1, 0, sizeof(s1));
    memset(s2, 0, sizeof(s2));
    g_read(e->g, e->a[0], s1, n);
    g_read(e->g, e->a[1], s2, n);
    e->ret = (uint32_t)(int32_t)strncasecmp(s1, s2, n);
}

static void hle_strchr(hle_env *e)
{
    static char s[65536];
    char *r;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    r = strchr(s, (int)(e->a[1] & 0xFFu));
    e->ret = r ? e->a[0] + (uint32_t)(r - s) : 0;
}

static void hle_strrchr(hle_env *e)
{
    static char s[65536];
    char *r;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    r = strrchr(s, (int)(e->a[1] & 0xFFu));
    e->ret = r ? e->a[0] + (uint32_t)(r - s) : 0;
}

static void hle_strstr(hle_env *e)
{
    static char s1[65536];
    static char s2[4096];
    char *r;
    g_read_str(e->g, e->a[0], s1, sizeof(s1));
    g_read_str(e->g, e->a[1], s2, sizeof(s2));
    r = strstr(s1, s2);
    e->ret = r ? e->a[0] + (uint32_t)(r - s1) : 0;
}

static void hle_strdup(hle_env *e)
{
    char s[65536];
    size_t n;
    uint32_t p;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    n = strlen(s) + 1;
    p = halloc(e->g, (uint32_t)n);
    if (p) {
        g_write(e->g, p, s, n);
    }
    e->ret = p;
}

static void hle_strpbrk(hle_env *e)
{
    static char s1[65536];
    static char s2[4096];
    char *r;
    g_read_str(e->g, e->a[0], s1, sizeof(s1));
    g_read_str(e->g, e->a[1], s2, sizeof(s2));
    r = strpbrk(s1, s2);
    e->ret = r ? e->a[0] + (uint32_t)(r - s1) : 0;
}

static void hle_strspn(hle_env *e)
{
    static char s1[65536];
    static char s2[4096];
    g_read_str(e->g, e->a[0], s1, sizeof(s1));
    g_read_str(e->g, e->a[1], s2, sizeof(s2));
    e->ret = (uint32_t)strspn(s1, s2);
}

static void hle_strcspn(hle_env *e)
{
    static char s1[65536];
    static char s2[4096];
    g_read_str(e->g, e->a[0], s1, sizeof(s1));
    g_read_str(e->g, e->a[1], s2, sizeof(s2));
    e->ret = (uint32_t)strcspn(s1, s2);
}

static void hle_strtok(hle_env *e)
{
    e->ret = 0;
}

static void hle_basename(hle_env *e)
{
    e->ret = e->a[0];
}

static void hle_realpath(hle_env *e)
{
    e->ret = 0;
}

static void hle_strerror(hle_env *e)
{
    static const char msg[] = "sosetta error\n";
    g_write(e->g, STRBUF_ADDR, msg, sizeof(msg));
    e->ret = STRBUF_ADDR;
}

static void hle_strerror_r(hle_env *e)
{
    static const char msg[] = "sosetta error";
    g_write(e->g, e->a[1], msg, sizeof(msg));
    e->ret = 0;
}

static void hle_atoi(hle_env *e)
{
    char s[256];
    g_read_str(e->g, e->a[0], s, sizeof(s));
    e->ret = (uint32_t)atoi(s);
}

static void hle_strtol(hle_env *e)
{
    char s[256];
    char *end = NULL;
    long v;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    v = strtol(s, &end, (int)e->a[2]);
    if (end) {
        uint32_t p = e->a[1];
        if (p) {
            uint32_t off = e->a[0] + (uint32_t)(end - s);
            g_write(e->g, p, &off, 4);
        }
    }
    e->ret = (uint32_t)(int32_t)v;
}

static void hle_strtoul(hle_env *e)
{
    char s[256];
    char *end = NULL;
    unsigned long v;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    v = strtoul(s, &end, (int)e->a[2]);
    if (end) {
        uint32_t p = e->a[1];
        if (p) {
            uint32_t off = e->a[0] + (uint32_t)(end - s);
            g_write(e->g, p, &off, 4);
        }
    }
    e->ret = (uint32_t)v;
}

static void hle_strtoll(hle_env *e)
{
    char s[256];
    char *end = NULL;
    long long v;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    v = strtoll(s, &end, (int)e->a[2]);
    if (end) {
        uint32_t p = e->a[1];
        if (p) {
            uint32_t off = e->a[0] + (uint32_t)(end - s);
            g_write(e->g, p, &off, 4);
        }
    }
    e->ret = (uint32_t)(int64_t)v;
    e->ret_hi = (uint32_t)((uint64_t)(int64_t)v >> 32);
    e->has_hi = 1;
}

static void hle_strtod(hle_env *e)
{
    char s[256];
    char *end = NULL;
    double v;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    v = strtod(s, &end);
    if (end) {
        uint32_t p = e->a[1];
        if (p) {
            uint32_t off = e->a[0] + (uint32_t)(end - s);
            g_write(e->g, p, &off, 4);
        }
    }
    e->fret = v;
    e->has_fret = 1;
    e->ret = 0;
}

static void hle_malloc(hle_env *e)
{
    e->ret = halloc(e->g, e->a[0]);
    if (trace_enabled()) {
        fprintf(stderr, "[sosetta] malloc(%u) = 0x%08x", e->a[0], e->ret);
        fputc(10, stderr);
    }
}

static void hle_calloc(hle_env *e)
{
    uint32_t n = e->a[0] * e->a[1];
    uint32_t p;
    if (e->a[0] != 0 && n / e->a[0] != e->a[1]) {
        e->ret = 0;
        return;
    }
    p = halloc(e->g, n);
    if (p && n) {
        static uint8_t z[1u << 16];
        uint32_t done = 0;
        while (done < n) {
            uint32_t chunk = n - done > sizeof(z) ? sizeof(z) : n - done;
            g_write(e->g, p + done, z, chunk);
            done += chunk;
        }
    }
    e->ret = p;
}

static void hle_realloc(hle_env *e)
{
    uint32_t p = e->a[0];
    uint32_t n = e->a[1];
    uint32_t np;
    if (p == 0) {
        e->ret = halloc(e->g, n);
        return;
    }
    if (n == 0) {
        hfree(e->g, p);
        e->ret = 0;
        return;
    }
    np = halloc(e->g, n);
    if (np) {
        uint32_t oldh = p - 8u;
        uint8_t hdr[4];
        uint32_t oldsz = 0;
        if (g_read(e->g, oldh, hdr, 4) == 0) {
            oldsz = (be32(hdr) & ~1u) - 8u;
        }
        if (oldsz > n) {
            oldsz = n;
        }
        if (oldsz) {
            static uint8_t tmp[1u << 20];
            uint32_t chunk = oldsz > sizeof(tmp) ? sizeof(tmp) : oldsz;
            g_read(e->g, p, tmp, chunk);
            g_write(e->g, np, tmp, chunk);
        }
        hfree(e->g, p);
    }
    e->ret = np;
}

static void hle_free(hle_env *e)
{
    hfree(e->g, e->a[0]);
    e->ret = 0;
}

static void hle_write(hle_env *e)
{
    uint32_t args[4] = { e->a[0], e->a[1], e->a[2], 0 };
    route_bsd(e, DARWIN_SYS_write, args);
}

static void hle_read(hle_env *e)
{
    uint32_t args[4] = { e->a[0], e->a[1], e->a[2], 0 };
    route_bsd(e, DARWIN_SYS_read, args);
}

static void hle_open(hle_env *e)
{
    uint32_t args[4] = { e->a[0], e->a[1], e->a[2], 0 };
    route_bsd(e, DARWIN_SYS_open, args);
}

static void hle_close(hle_env *e)
{
    uint32_t args[4] = { e->a[0], 0, 0, 0 };
    route_bsd(e, DARWIN_SYS_close, args);
}

static void hle_unlink(hle_env *e)
{
    uint32_t args[4] = { e->a[0], 0, 0, 0 };
    route_bsd(e, DARWIN_SYS_unlink, args);
}

static void hle_getpid(hle_env *e)
{
    uint32_t args[4] = { 0, 0, 0, 0 };
    route_bsd(e, DARWIN_SYS_getpid, args);
}

static void hle_mmap(hle_env *e)
{
    uint32_t args[4] = { e->a[0], e->a[1], e->a[2], e->a[3] };
    uint32_t r = 0;
    uint8_t x[4];
    x[0] = 0;
    (void)x;
    sosetta_bsd_syscall(e->g, e->ctx, DARWIN_SYS_mmap, args, &r);
    e->ret = r;
}

static void hle_munmap(hle_env *e)
{
    uint32_t args[4] = { e->a[0], e->a[1], 0, 0 };
    route_bsd(e, DARWIN_SYS_munmap, args);
}

static void hle_lseek(hle_env *e)
{
    uint32_t args[4] = { e->a[0], 0, e->a[3], 0 };
    if (e->a[2] != 0) {
        e->ret = gerr(22);
        return;
    }
    sosetta_bsd_syscall(e->g, e->ctx, DARWIN_SYS_lseek, args, &e->ret);
}

static void hle_exit(hle_env *e)
{
    uint32_t args[4] = { e->a[0], 0, 0, 0 };
    route_bsd(e, DARWIN_SYS_exit, args);
}

static void hle_abort(hle_env *e)
{
    e->ctx->should_stop = 1;
    e->ctx->exit_code = 134;
    uc_emu_stop(e->g->uc);
}

static void hle_pthread_exit(hle_env *e)
{
    e->ctx->should_stop = 1;
    e->ctx->exit_code = (int)e->a[0];
    uc_emu_stop(e->g->uc);
}

static void hle_getenv(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_atexit(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_sigaction(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_signal(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_sigsetjmp(hle_env *e)
{
    uint32_t env = e->a[0];
    uint32_t lr = 0;
    uint8_t tmp[4];
    unsigned r;
    uc_reg_read(e->g->uc, UC_PPC_REG_LR, &lr);
    put_be32(tmp, lr);
    g_write(e->g, env, tmp, 4);
    sosetta_guest_get_gpr(e->g, 1, &e->ret);
    put_be32(tmp, e->ret);
    g_write(e->g, env + 4u, tmp, 4);
    for (r = 13; r <= 31; r++) {
        uint32_t v = 0;
        sosetta_guest_get_gpr(e->g, r, &v);
        put_be32(tmp, v);
        g_write(e->g, env + 4u + 4u * (r - 12u), tmp, 4);
    }
    e->ret = 0;
}

static void hle_siglongjmp(hle_env *e)
{
    uint32_t env = e->a[0];
    uint8_t tmp[4];
    unsigned r;
    uint32_t lr = 0;
    uint32_t sp = 0;
    g_read(e->g, env, tmp, 4);
    lr = be32(tmp);
    g_read(e->g, env + 4u, tmp, 4);
    sp = be32(tmp);
    for (r = 13; r <= 31; r++) {
        uint32_t v = 0;
        g_read(e->g, env + 4u + 4u * (r - 12u), tmp, 4);
        v = be32(tmp);
        sosetta_guest_set_gpr(e->g, r, v);
    }
    sosetta_guest_set_gpr(e->g, 1, sp);
    sosetta_guest_set_gpr(e->g, 12, lr);
    e->ret = e->a[1];
}

static void hle_time(hle_env *e)
{
    e->ret = (uint32_t)time(NULL);
}

static void hle_gettimeofday(hle_env *e)
{
    struct timeval tv;
    uint8_t tmp[8];
    gettimeofday(&tv, NULL);
    if (e->a[0]) {
        put_be32(tmp, (uint32_t)tv.tv_sec);
        put_be32(tmp + 4, (uint32_t)tv.tv_usec);
        g_write(e->g, e->a[0], tmp, 8);
    }
    e->ret = 0;
}

static void write_tm(hle_env *e, uint32_t addr, struct tm *tm)
{
    uint8_t tmp[4];
    int fields[9];
    fields[0] = tm->tm_sec;
    fields[1] = tm->tm_min;
    fields[2] = tm->tm_hour;
    fields[3] = tm->tm_mday;
    fields[4] = tm->tm_mon;
    fields[5] = tm->tm_year;
    fields[6] = tm->tm_wday;
    fields[7] = tm->tm_yday;
    fields[8] = tm->tm_isdst;
    {
        int i;
        for (i = 0; i < 9; i++) {
            put_be32(tmp, (uint32_t)fields[i]);
            g_write(e->g, addr + 4u * (uint32_t)i, tmp, 4);
        }
    }
    put_be32(tmp, 0);
    g_write(e->g, addr + 36u, tmp, 4);
    put_be32(tmp, 0);
    g_write(e->g, addr + 40u, tmp, 4);
}

static void hle_gmtime(hle_env *e)
{
    time_t t = (time_t)(int32_t)e->a[0];
    write_tm(e, TM_ADDR, gmtime(&t));
    e->ret = TM_ADDR;
}

static void hle_gmtime_r(hle_env *e)
{
    time_t t = (time_t)(int32_t)e->a[0];
    write_tm(e, e->a[1], gmtime(&t));
    e->ret = e->a[1];
}

static void hle_localtime(hle_env *e)
{
    time_t t = (time_t)(int32_t)e->a[0];
    write_tm(e, TM_ADDR, localtime(&t));
    e->ret = TM_ADDR;
}

static void hle_mach_absolute_time(hle_env *e)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    e->ret = (uint32_t)(tv.tv_sec * 1000000u + tv.tv_usec);
    e->ret_hi = 0;
    e->has_hi = 1;
}

static void hle_mach_timebase_info(hle_env *e)
{
    uint8_t tmp[8];
    put_be32(tmp, 1);
    put_be32(tmp + 4, 1);
    if (e->a[0]) {
        g_write(e->g, e->a[0], tmp, 8);
    }
    e->ret = 0;
}

static void hle_getuid(hle_env *e)
{
    e->ret = (uint32_t)getuid();
}

static void hle_geteuid(hle_env *e)
{
    e->ret = (uint32_t)geteuid();
}

static void hle_getgid(hle_env *e)
{
    e->ret = (uint32_t)getgid();
}

static void hle_getegid(hle_env *e)
{
    e->ret = (uint32_t)getegid();
}

static void hle_isatty(hle_env *e)
{
    e->ret = (e->a[0] < 3u) ? 1u : 0u;
}

static void hle_sysconf(hle_env *e)
{
    switch (e->a[0]) {
    case 1:
        e->ret = 1048576u;
        return;
    case 3:
        e->ret = 100u;
        return;
    case 5:
        e->ret = 256u;
        return;
    case 57:
    case 58:
        e->ret = 1u;
        return;
    default:
        e->ret = 4096u;
        return;
    }
}

static void hle_errno_fn(hle_env *e)
{
    e->ret = ERRNO_ADDR;
}

static void hle_maskrune(hle_env *e)
{
    uint32_t c = e->a[0] & 0xFFu;
    uint32_t m = 0;
    if (isupper((int)c)) m |= 0x01u;
    if (islower((int)c)) m |= 0x02u;
    if (isdigit((int)c)) m |= 0x04u;
    if (isspace((int)c)) m |= 0x08u;
    if (ispunct((int)c)) m |= 0x10u;
    if (iscntrl((int)c)) m |= 0x20u;
    if (isxdigit((int)c)) m |= 0x40u;
    if (c == ' ' || c == '\t') m |= 0x80u;
    e->ret = e->a[1] & m;
}

static void hle_tolower_fn(hle_env *e)
{
    e->ret = (uint32_t)tolower((int)(e->a[0] & 0xFFu));
}

static void hle_fopen(hle_env *e)
{
    char path[4096];
    char mode[32];
    FILE *hf;
    int slot;
    g_read_str(e->g, e->a[0], path, sizeof(path));
    g_read_str(e->g, e->a[1], mode, sizeof(mode));
    hf = fopen(path, mode);
    if (!hf) {
        e->ret = 0;
        return;
    }
    slot = sf_take();
    if (slot < 0) {
        fclose(hf);
        e->ret = 0;
        return;
    }
    sf_kind[slot] = SF_KIND_FILE;
    sf_host[slot] = hf;
    sf_eof[slot] = 0;
    sf_err[slot] = 0;
    sf_fd[slot] = -1;
    e->ret = SF_BASE + (uint32_t)slot * SF_STRIDE;
}

static void hle_fdopen(hle_env *e)
{
    char mode[32];
    FILE *hf;
    int slot;
    g_read_str(e->g, e->a[1], mode, sizeof(mode));
    hf = fdopen((int)(int32_t)e->a[0], mode);
    if (!hf) {
        e->ret = 0;
        return;
    }
    slot = sf_take();
    if (slot < 0) {
        fclose(hf);
        e->ret = 0;
        return;
    }
    sf_kind[slot] = SF_KIND_FILE;
    sf_host[slot] = hf;
    sf_eof[slot] = 0;
    sf_err[slot] = 0;
    sf_fd[slot] = -1;
    e->ret = SF_BASE + (uint32_t)slot * SF_STRIDE;
}

static void hle_freopen(hle_env *e)
{
    hle_fopen(e);
}

static void hle_fclose(hle_env *e)
{
    int slot = sf_slot_of(e->a[0]);
    if (slot < 0) {
        e->ret = gerr(9);
        return;
    }
    if (sf_kind[slot] == SF_KIND_FILE && sf_host[slot]) {
        fclose(sf_host[slot]);
    }
    sf_kind[slot] = SF_KIND_FREE;
    sf_host[slot] = NULL;
    e->ret = 0;
}

static void hle_fflush(hle_env *e)
{
    if (e->a[0] == 0) {
        e->ret = 0;
        return;
    }
    {
        FILE *hf;
        int fd;
        int *eof;
        int *err;
        if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
            e->ret = gerr(9);
            return;
        }
        if (hf) {
            fflush(hf);
        }
        e->ret = 0;
    }
}

static void hle_setvbuf(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_fread(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    uint32_t size = e->a[1];
    uint32_t n = e->a[2];
    static uint8_t tmp[1u << 20];
    size_t got = 0;
    size_t total;
    if (sf_get_stream(e, e->a[3], &hf, &fd, &eof, &err) != 0) {
        e->ret = 0;
        return;
    }
    if (size == 0 || n == 0) {
        e->ret = 0;
        return;
    }
    total = (size_t)size * n;
    if (total > sizeof(tmp)) {
        total = sizeof(tmp);
    }
    if (sf_read(hf, fd, tmp, total, &got) != 0) {
        *err = 1;
        e->ret = 0;
        return;
    }
    g_write(e->g, e->a[0], tmp, got);
    if (got < total) {
        *eof = 1;
    }
    e->ret = size ? (uint32_t)(got / size) : 0;
}

static void hle_fwrite(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    uint32_t size = e->a[1];
    uint32_t n = e->a[2];
    static uint8_t tmp[1u << 20];
    size_t put = 0;
    size_t total;
    if (sf_get_stream(e, e->a[3], &hf, &fd, &eof, &err) != 0) {
        e->ret = 0;
        return;
    }
    total = (size_t)size * n;
    if (total == 0) {
        e->ret = 0;
        return;
    }
    if (total > sizeof(tmp)) {
        total = sizeof(tmp);
    }
    g_read(e->g, e->a[0], tmp, total);
    if (sf_write(hf, fd, tmp, total, &put) != 0) {
        *err = 1;
        e->ret = 0;
        return;
    }
    e->ret = size ? (uint32_t)(put / size) : 0;
}

static void hle_fgetc(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    uint8_t c = 0;
    size_t got = 0;
    if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    if (sf_read(hf, fd, &c, 1, &got) != 0 || got == 0) {
        *eof = 1;
        e->ret = (uint32_t)-1;
        return;
    }
    e->ret = c;
}

static void hle_fputc(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    uint8_t c = (uint8_t)(e->a[0] & 0xFFu);
    size_t put = 0;
    if (sf_get_stream(e, e->a[1], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    if (sf_write(hf, fd, &c, 1, &put) != 0 || put == 0) {
        *err = 1;
        e->ret = (uint32_t)-1;
        return;
    }
    e->ret = (uint32_t)c;
}

static void hle_fgets(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    static char tmp[65536];
    uint32_t n = e->a[1];
    size_t got = 0;
    if (sf_get_stream(e, e->a[2], &hf, &fd, &eof, &err) != 0) {
        e->ret = 0;
        return;
    }
    if (n == 0) {
        e->ret = 0;
        return;
    }
    if (n > sizeof(tmp)) {
        n = sizeof(tmp);
    }
    if (sf_read(hf, fd, tmp, n - 1u, &got) != 0) {
        *err = 1;
        e->ret = 0;
        return;
    }
    if (got == 0) {
        *eof = 1;
        e->ret = 0;
        return;
    }
    {
        char *nl = memchr(tmp, '\n', got);
        size_t out = nl ? (size_t)(nl - tmp) + 1u : got;
        g_write(e->g, e->a[0], tmp, out);
        {
            uint8_t z = 0;
            g_write(e->g, e->a[0] + (uint32_t)out, &z, 1);
        }
        e->ret = e->a[0];
    }
}

static void hle_fputs(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    char s[65536];
    size_t put = 0;
    if (sf_get_stream(e, e->a[1], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    g_read_str(e->g, e->a[0], s, sizeof(s));
    if (sf_write(hf, fd, s, strlen(s), &put) != 0) {
        *err = 1;
        e->ret = (uint32_t)-1;
        return;
    }
    e->ret = 0;
}

static void hle_puts(hle_env *e)
{
    char s[65536];
    size_t put = 0;
    size_t len;
    g_read_str(e->g, e->a[0], s, sizeof(s));
    len = strlen(s);
    write(1, s, len);
    write(1, "\n", 1);
    (void)put;
    e->ret = 0;
}

static void hle_feof(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
        e->ret = 0;
        return;
    }
    if (hf) {
        *eof = feof(hf) ? 1 : 0;
    }
    e->ret = (uint32_t)*eof;
}

static void hle_ferror(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
        e->ret = 0;
        return;
    }
    if (hf) {
        *err = ferror(hf) ? 1 : 0;
    }
    e->ret = (uint32_t)*err;
}

static void hle_fileno(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    if (hf) {
        fd = fileno(hf);
    }
    e->ret = (uint32_t)fd;
}

static void hle_fseek(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    if (sf_get_stream(e, e->a[3], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    if (hf) {
        e->ret = fseek(hf, (long)(int32_t)e->a[1], (int)e->a[2]) == 0 ? 0u : (uint32_t)-1;
    } else {
        e->ret = (uint32_t)lseek(fd, (off_t)(int32_t)e->a[1], (int)e->a[2]);
    }
    *eof = 0;
}

static void hle_fseeko(hle_env *e)
{
    hle_fseek(e);
}

static void hle_ftell(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    if (hf) {
        e->ret = (uint32_t)ftell(hf);
    } else {
        e->ret = (uint32_t)lseek(fd, 0, SEEK_CUR);
    }
}

static void hle_fprintf(hle_env *e)
{
    fmt_target t;
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    t.kind = 1;
    t.hf = hf;
    t.fd = fd;
    t.gbuf = 0;
    t.gcap = 0;
    vfmt(e, &t, e->a[1], 2);
    e->ret = 0;
}

static void hle_printf(hle_env *e)
{
    fmt_target t;
    t.kind = 1;
    t.g = e->g;
    t.hf = NULL;
    t.fd = 1;
    t.gbuf = 0;
    t.gcap = 0;
    vfmt(e, &t, e->a[0], 1);
    e->ret = 0;
}

struct va_list_ppc {
    uint32_t reg_save_area;
    uint32_t overflow_arg_area;
    uint32_t gpr_offs;
    uint32_t fpr_offs;
};

static uint32_t va_next(hle_env *e, struct va_list_ppc *va, int is_double)
{
    uint32_t v = 0;

    if (is_double) {
        uint32_t area = va->reg_save_area + 32u + va->fpr_offs * 8u;
        uint64_t bits = 0;
        if (va->fpr_offs < 13 && g_read(e->g, area, &bits, 8) == 0) {
            memcpy(&v, &bits, 4);
        }
        va->fpr_offs++;
        return v;
    }
    if (va->gpr_offs < 8) {
        uint32_t area = va->reg_save_area + va->gpr_offs * 4u;
        g_read(e->g, area, &v, 4);
        va->gpr_offs++;
        return v;
    }
    g_read(e->g, va->overflow_arg_area, &v, 4);
    va->overflow_arg_area += 4u;
    return v;
}

static void vfmt_va(hle_env *e, fmt_target *t, uint32_t fmt_addr,
                    uint32_t va_ptr)
{
    struct va_list_ppc va;
    char fmt[8192];
    size_t i = 0;

    obuf_reset();
    if (va_ptr == 0 || g_read(e->g, va_ptr, &va, sizeof(va)) != 0) {
        return;
    }
    if (g_read_str(e->g, fmt_addr, fmt, sizeof(fmt)) != 0) {
        return;
    }
    while (fmt[i] != 0) {
        if (fmt[i] != 37) {
            obuf_add(&fmt[i], 1);
            i++;
            continue;
        }
        {
            char spec[32];
            char tmp[512];
            size_t sp = 0;
            size_t j = i;
            int kind = 0;
            uint32_t av;
            double dv = 0.0;
            uint64_t dbits = 0;

            spec[sp++] = 37;
            j++;
            while (j < sizeof(fmt) && strchr("-+ #0", fmt[j]) != NULL &&
                   fmt[j] != 0 && sp < sizeof(spec) - 8) {
                spec[sp++] = fmt[j++];
            }
            while (j < sizeof(fmt) && isdigit((unsigned char)fmt[j]) &&
                   sp < sizeof(spec) - 8) {
                spec[sp++] = fmt[j++];
            }
            if (fmt[j] == 46 && sp < sizeof(spec) - 8) {
                spec[sp++] = fmt[j++];
                while (j < sizeof(fmt) && isdigit((unsigned char)fmt[j]) &&
                       sp < sizeof(spec) - 8) {
                    spec[sp++] = fmt[j++];
                }
            }
            while ((fmt[j] == 'l' || fmt[j] == 'h' || fmt[j] == 'L') &&
                   sp < sizeof(spec) - 8) {
                spec[sp++] = fmt[j++];
            }
            switch (fmt[j]) {
            case 'd': case 'i':
                av = va_next(e, &va, 0);
                snprintf(tmp, sizeof(tmp), spec, (int)(int32_t)av);
                kind = 1;
                break;
            case 'u': case 'x': case 'X': case 'o':
                av = va_next(e, &va, 0);
                snprintf(tmp, sizeof(tmp), spec, av);
                kind = 1;
                break;
            case 'c':
                av = va_next(e, &va, 0);
                snprintf(tmp, sizeof(tmp), spec, (int)(av & 0xFFu));
                kind = 1;
                break;
            case 'p':
                av = va_next(e, &va, 0);
                snprintf(tmp, sizeof(tmp), spec, (uintptr_t)av);
                kind = 1;
                break;
            case 's': {
                char sbuf[4096];
                av = va_next(e, &va, 0);
                if (av == 0) {
                    snprintf(tmp, sizeof(tmp), "(null)");
                } else {
                    g_read_str(e->g, av, sbuf, sizeof(sbuf));
                    snprintf(tmp, sizeof(tmp), spec, sbuf);
                }
                kind = 1;
                break;
            }
            case 'f': case 'F': case 'e': case 'E':
            case 'g': case 'G': {
                uint32_t area = va.reg_save_area + 32u + va.fpr_offs * 8u;
                g_read(e->g, area, &dbits, 8);
                memcpy(&dv, &dbits, sizeof(dv));
                va.fpr_offs++;
                va.gpr_offs += 2;
                snprintf(tmp, sizeof(tmp), spec, dv);
                kind = 1;
                break;
            }
            case 37:
                obuf_add("%", 1);
                i = j + 1;
                continue;
            default:
                obuf_add(&fmt[i], j - i + 1);
                i = j + 1;
                continue;
            }
            if (kind) {
                obuf_add(tmp, strlen(tmp));
            }
            i = j + 1;
        }
    }
    fmt_flush(t);
}

static void hle_vfprintf(hle_env *e)
{
    FILE *hf;
    int fd;
    int *eof;
    int *err;
    fmt_target t;
    if (sf_get_stream(e, e->a[0], &hf, &fd, &eof, &err) != 0) {
        e->ret = gerr(9);
        return;
    }
    t.kind = 1;
    t.g = e->g;
    t.hf = hf;
    t.fd = fd;
    t.gbuf = 0;
    t.gcap = 0;
    vfmt_va(e, &t, e->a[1], e->a[2]);
    e->ret = 0;
}

static void hle_snprintf(hle_env *e)
{
    fmt_target t;
    t.kind = 2;
    t.g = e->g;
    t.hf = NULL;
    t.fd = -1;
    t.gbuf = e->a[0];
    t.gcap = e->a[1];
    vfmt(e, &t, e->a[2], 3);
    e->ret = 0;
}

static void hle_sscanf(hle_env *e)
{
    (void)e;
    e->ret = (uint32_t)-1;
}

static void hle_opendir(hle_env *e)
{
    char path[4096];
    DIR *d;
    int slot;
    g_read_str(e->g, e->a[0], path, sizeof(path));
    d = opendir(path);
    if (!d) {
        e->ret = 0;
        return;
    }
    slot = sf_take();
    if (slot < 0) {
        closedir(d);
        e->ret = 0;
        return;
    }
    sf_kind[slot] = SF_KIND_DIR;
    sf_host[slot] = (FILE *)d;
    e->ret = SF_BASE + (uint32_t)slot * SF_STRIDE;
}

static void hle_closedir(hle_env *e)
{
    int slot = sf_slot_of(e->a[0]);
    if (slot < 0 || sf_kind[slot] != SF_KIND_DIR) {
        e->ret = gerr(9);
        return;
    }
    closedir((DIR *)sf_host[slot]);
    sf_kind[slot] = SF_KIND_FREE;
    sf_host[slot] = NULL;
    e->ret = 0;
}

static void hle_readdir(hle_env *e)
{
    int slot = sf_slot_of(e->a[0]);
    struct dirent *de;
    uint8_t tmp[512];
    uint32_t namlen;
    uint32_t reclen;
    if (slot < 0 || sf_kind[slot] != SF_KIND_DIR) {
        e->ret = 0;
        return;
    }
    de = readdir((DIR *)sf_host[slot]);
    if (!de) {
        e->ret = 0;
        return;
    }
    namlen = (uint32_t)strlen(de->d_name);
    reclen = 8u + namlen + 1u;
    reclen = (reclen + 3u) & ~3u;
    if (reclen > sizeof(tmp)) {
        reclen = sizeof(tmp);
    }
    memset(tmp, 0, reclen);
    put_be32(tmp, (uint32_t)de->d_ino);
    put_be16(tmp + 4, (uint16_t)reclen);
    tmp[6] = (uint8_t)de->d_type;
    tmp[7] = (uint8_t)namlen;
    memcpy(tmp + 8, de->d_name, namlen);
    g_write(e->g, DIRENT_ADDR, tmp, reclen);
    e->ret = DIRENT_ADDR;
}

static void hle_rename(hle_env *e)
{
    char s1[4096];
    char s2[4096];
    g_read_str(e->g, e->a[0], s1, sizeof(s1));
    g_read_str(e->g, e->a[1], s2, sizeof(s2));
    e->ret = rename(s1, s2) == 0 ? 0u : gerr(78);
}

static void hle_mkdir(hle_env *e)
{
    char s[4096];
    g_read_str(e->g, e->a[0], s, sizeof(s));
    e->ret = mkdir(s, (mode_t)e->a[1]) == 0 ? 0u : gerr(78);
}

static void hle_utimes(hle_env *e)
{
    (void)e;
    e->ret = gerr(78);
}

static void hle_fnmatch(hle_env *e)
{
    char pat[1024];
    char s[4096];
    g_read_str(e->g, e->a[0], pat, sizeof(pat));
    g_read_str(e->g, e->a[1], s, sizeof(s));
    e->ret = (uint32_t)fnmatch(pat, s, (int)e->a[2]);
}

static void hle_inet_pton(hle_env *e)
{
    char s[256];
    uint8_t buf[16];
    g_read_str(e->g, e->a[1], s, sizeof(s));
    e->ret = (uint32_t)inet_pton((int)e->a[0], s, buf);
    if (e->ret == 1 && e->a[2]) {
        g_write(e->g, e->a[2], buf, 16);
    }
}

static void hle_inet_ntop(hle_env *e)
{
    char out[64];
    uint8_t buf[16];
    g_read(e->g, e->a[1], buf, 16);
    if (inet_ntop((int)e->a[0], buf, out, sizeof(out)) == NULL) {
        e->ret = 0;
        return;
    }
    g_write(e->g, e->a[2], out, strlen(out) + 1);
    e->ret = e->a[2];
}

static void hle_zlib_version(hle_env *e)
{
    static const char v[] = "1.2.5";
    g_write(e->g, STRBUF_ADDR + 32u, v, sizeof(v));
    e->ret = STRBUF_ADDR + 32u;
}

static void hle_inflate_init(hle_env *e)
{
    (void)e;
    e->ret = (uint32_t)-1;
}

static void hle_pthread_create(hle_env *e)
{
    uint32_t lr = 0;
    uc_reg_read(e->g->uc, UC_PPC_REG_LR, &lr);
    pts.active = 1;
    pts.caller_lr = lr;
    e->has_redirect = 1;
    e->redirect_pc = e->a[2];
    e->call_r3 = e->a[3];
    e->call_lr = TRAP_PTHREAD_RET;
}

static void hle_pthread_self(hle_env *e)
{
    (void)e;
    e->ret = 0x1000u;
}

static void hle_pthread_equal(hle_env *e)
{
    e->ret = (e->a[0] == e->a[1]) ? 1u : 0u;
}

static void hle_ret0(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_gai_strerror(hle_env *e)
{
    static const char s[] = "gai error";
    g_write(e->g, GAI_ADDR, s, sizeof(s));
    e->ret = GAI_ADDR;
}

static void hle_getpwuid(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_getpwuid_r(hle_env *e)
{
    (void)e;
    e->ret = gerr(78);
}

static void hle_gethostbyname(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_sysctlbyname(hle_env *e)
{
    (void)e;
    hle_set_errno(e, 78);
    e->ret = gerr(78);
}

static void hle_strftime(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_setlocale(hle_env *e)
{
    static const char c[] = "C";
    g_write(e->g, GAI_ADDR + 16u, c, sizeof(c));
    e->ret = GAI_ADDR + 16u;
}

static void hle_bsearch(hle_env *e)
{
    uint32_t lr = 0;
    uc_reg_read(e->g->uc, UC_PPC_REG_LR, &lr);
    bs.key = e->a[0];
    bs.base = e->a[1];
    bs.size = e->a[3];
    bs.compar = e->a[4];
    bs.orig_lr = lr;
    bs.lo = 0;
    bs.hi = (int)e->a[2] - 1;
    bs.active = 1;
    if (trace_enabled()) {
        fprintf(stderr, "[sosetta] bsearch key=%u base=%u n=%u size=%u compar=%u lr=%u\n",
                bs.key, bs.base, (unsigned)(bs.hi + 1), bs.size, bs.compar, lr);
    }
    if (bs.hi < bs.lo) {
        bs.active = 0;
        e->ret = 0;
        return;
    }
    bs.mid = bs.lo + (bs.hi - bs.lo) / 2;
    e->has_redirect = 1;
    e->redirect_pc = bs.compar;
    e->call_r3 = bs.key;
    e->call_r4 = bs.base + (uint32_t)bs.mid * bs.size;
}

static void hle_bsearch_return(hle_env *e)
{
    uint32_t r3 = 0;
    uint32_t r4keep = 0;
    uint32_t elem;
    sosetta_guest_get_gpr(e->g, 3, &r3);
    sosetta_guest_get_gpr(e->g, 4, &r4keep);
    e->has_redirect = 1;
    if (!bs.active) {
        e->redirect_pc = bs.orig_lr;
        e->call_r3 = e->ret;
        e->call_r4 = r4keep;
        return;
    }
    elem = bs.base + (uint32_t)bs.mid * bs.size;
    if (r3 == 0) {
        bs.active = 0;
        e->ret = elem;
        if (trace_enabled()) {
            fprintf(stderr, "[sosetta] bsearch found elem=%u lr_resume=%u\n", elem, bs.orig_lr);
        }
        e->redirect_pc = bs.orig_lr;
        e->call_r3 = elem;
        e->call_r4 = r4keep;
        return;
    }
    if ((int32_t)r3 < 0) {
        bs.hi = bs.mid - 1;
    } else {
        bs.lo = bs.mid + 1;
    }
    if (bs.lo > bs.hi) {
        bs.active = 0;
        e->ret = 0;
        if (trace_enabled()) {
            fprintf(stderr, "[sosetta] bsearch exhausted lr_resume=%u\n", bs.orig_lr);
        }
        e->redirect_pc = bs.orig_lr;
        e->call_r3 = 0;
        e->call_r4 = r4keep;
        return;
    }
    bs.mid = bs.lo + (bs.hi - bs.lo) / 2;
    e->redirect_pc = bs.compar;
    e->call_r3 = bs.key;
    e->call_r4 = bs.base + (uint32_t)bs.mid * bs.size;
}

static void hle_qsort(hle_env *e)
{
    (void)e;
    e->ret = 0;
}

static void hle_ftruncate(hle_env *e)
{
    uint32_t args[4] = { e->a[0], e->a[1], 0, 0 };
    route_bsd(e, 201, args);
}

#define FN(name) static void hle_##name(hle_env *e)

FN(nanosleep) { (void)e; e->ret = 0; }
FN(sched_yield) { (void)e; e->ret = 0; }
FN(alarm) { (void)e; e->ret = 0; }
FN(mprotect) { (void)e; e->ret = 0; }
FN(mlock) { (void)e; e->ret = 0; }
FN(fsetxattr) { (void)e; e->ret = 0; }
FN(tcgetattr) { (void)e; e->ret = gerr(25); }
FN(tcsetattr) { (void)e; e->ret = gerr(25); }
FN(once) { (void)e; e->ret = 0; }
FN(inflate) { (void)e; e->ret = (uint32_t)-2; }
FN(inflateEnd) { (void)e; e->ret = 0; }

static void hle_enosys(hle_env *e)
{
    hle_set_errno(e, 78);
    e->ret = gerr(78);
}

struct hle_entry {
    const char *name;
    void (*fn)(hle_env *e);
};

static const struct hle_entry hle_table[] = {
    { "_malloc", hle_malloc },
    { "_calloc", hle_calloc },
    { "_realloc", hle_realloc },
    { "_free", hle_free },
    { "_memcpy", hle_memcpy },
    { "_memmove", hle_memmove },
    { "_memset", hle_memset },
    { "_memcmp", hle_memcmp },
    { "_memchr", hle_memchr },
    { "_strlen", hle_strlen },
    { "_strcpy", hle_strcpy },
    { "_stpcpy", hle_stpcpy },
    { "_strncpy", hle_strncpy },
    { "_strcat", hle_strcat },
    { "_strncat", hle_strncat },
    { "_strcmp", hle_strcmp },
    { "_strncmp", hle_strncmp },
    { "_strcasecmp", hle_strcasecmp },
    { "_strncasecmp", hle_strncasecmp },
    { "_tcgetattr", hle_tcgetattr },
    { "_tcsetattr", hle_tcsetattr },
    { "_gai_strerror", hle_gai_strerror },
    { "_strchr", hle_strchr },
    { "_strrchr", hle_strrchr },
    { "_strstr", hle_strstr },
    { "_strdup", hle_strdup },
    { "_strpbrk", hle_strpbrk },
    { "_strspn", hle_strspn },
    { "_strcspn", hle_strcspn },
    { "_strtok", hle_strtok },
    { "_strtok_r", hle_strtok },
    { "_basename", hle_basename },
    { "_realpath", hle_realpath },
    { "_strerror", hle_strerror },
    { "_strerror_r", hle_strerror_r },
    { "_atoi", hle_atoi },
    { "_strtol", hle_strtol },
    { "_strtoul", hle_strtoul },
    { "_strtoll", hle_strtoll },
    { "_strtod", hle_strtod },
    { "_write", hle_write },
    { "_read", hle_read },
    { "_open", hle_open },
    { "_close", hle_close },
    { "_unlink", hle_unlink },
    { "_getpid", hle_getpid },
    { "_mmap", hle_mmap },
    { "_munmap", hle_munmap },
    { "_lseek", hle_lseek },
    { "_exit", hle_exit },
    { "_abort", hle_abort },
    { "_getenv", hle_getenv },
    { "_atexit", hle_atexit },
    { "_sigaction", hle_sigaction },
    { "_signal", hle_signal },
    { "_sigsetjmp", hle_sigsetjmp },
    { "_siglongjmp", hle_siglongjmp },
    { "_time", hle_time },
    { "_gettimeofday", hle_gettimeofday },
    { "_gmtime", hle_gmtime },
    { "_gmtime_r", hle_gmtime_r },
    { "_localtime", hle_localtime },
    { "_strftime", hle_strftime },
    { "_mach_absolute_time", hle_mach_absolute_time },
    { "_mach_timebase_info", hle_mach_timebase_info },
    { "_getuid", hle_getuid },
    { "_geteuid", hle_geteuid },
    { "_getgid", hle_getgid },
    { "_getegid", hle_getegid },
    { "_isatty", hle_isatty },
    { "_sysconf", hle_sysconf },
    { "___error", hle_errno_fn },
    { "___maskrune", hle_maskrune },
    { "___tolower", hle_tolower_fn },
    { "_fopen", hle_fopen },
    { "_fdopen", hle_fdopen },
    { "_freopen", hle_freopen },
    { "_fclose", hle_fclose },
    { "_fflush", hle_fflush },
    { "_setvbuf", hle_setvbuf },
    { "_fread", hle_fread },
    { "_fwrite", hle_fwrite },
    { "_getc", hle_fgetc },
    { "_fputc", hle_fputc },
    { "_fgets", hle_fgets },
    { "_fputs", hle_fputs },
    { "_puts", hle_puts },
    { "_feof", hle_feof },
    { "_ferror", hle_ferror },
    { "_fileno", hle_fileno },
    { "_fseek", hle_fseek },
    { "_fseeko", hle_fseeko },
    { "_ftell", hle_ftell },
    { "_ftruncate", hle_ftruncate },
    { "_printf", hle_printf },
    { "_fprintf$LDBL128", hle_fprintf },
    { "_snprintf$LDBL128", hle_snprintf },
    { "_vfprintf$LDBL128", hle_vfprintf },
    { "_sscanf$LDBL128", hle_sscanf },
    { "_opendir", hle_opendir },
    { "_closedir", hle_closedir },
    { "_readdir", hle_readdir },
    { "_rename", hle_rename },
    { "_mkdir", hle_mkdir },
    { "_utimes", hle_utimes },
    { "_fnmatch", hle_fnmatch },
    { "_inet_pton", hle_inet_pton },
    { "_inet_ntop", hle_inet_ntop },
    { "_zlibVersion", hle_zlib_version },
    { "_inflate", hle_inflate },
    { "_inflateEnd", hle_inflateEnd },
    { "_inflateInit_", hle_inflate_init },
    { "_inflateInit2_", hle_inflate_init },
    { "_pthread_create", hle_pthread_create },
    { "_pthread_self", hle_pthread_self },
    { "_pthread_equal", hle_pthread_equal },
    { "_pthread_exit", hle_pthread_exit },
    { "_pthread_once", hle_once },
    { "_pthread_join", hle_ret0 },
    { "_pthread_attr_init", hle_ret0 },
    { "_pthread_attr_destroy", hle_ret0 },
    { "_pthread_attr_setdetachstate", hle_ret0 },
    { "_pthread_cond_broadcast", hle_ret0 },
    { "_pthread_cond_destroy", hle_ret0 },
    { "_pthread_cond_init", hle_ret0 },
    { "_pthread_cond_signal", hle_ret0 },
    { "_pthread_cond_timedwait", hle_ret0 },
    { "_pthread_cond_wait", hle_ret0 },
    { "_pthread_mutex_destroy", hle_ret0 },
    { "_pthread_mutex_init", hle_ret0 },
    { "_pthread_mutex_lock", hle_ret0 },
    { "_pthread_mutex_trylock", hle_ret0 },
    { "_pthread_mutex_unlock", hle_ret0 },
    { "_pthread_mutexattr_destroy", hle_ret0 },
    { "_pthread_mutexattr_init", hle_ret0 },
    { "_pthread_getspecific", hle_ret0 },
    { "_pthread_setspecific", hle_ret0 },
    { "_pthread_key_create", hle_ret0 },
    { "_pthread_key_delete", hle_ret0 },
    { "_sched_yield", hle_sched_yield },
    { "_nanosleep", hle_nanosleep },
    { "_alarm", hle_alarm },
    { "_mprotect", hle_mprotect },
    { "_mlock", hle_mlock },
    { "_fsetxattr", hle_fsetxattr },
    { "_socket", hle_socket },
    { "_bind", hle_enosys },
    { "_listen", hle_enosys },
    { "_accept", hle_enosys },
    { "_connect", hle_connect },
    { "_shutdown", hle_enosys },
    { "_setsockopt", hle_enosys },
    { "_getsockopt", hle_getsockopt },
    { "_getsockname", hle_enosys },
    { "_getpeername", hle_enosys },
    { "_send", hle_send },
    { "_sendto", hle_enosys },
    { "_recv", hle_recv },
    { "_recvfrom", hle_enosys },
    { "_sendmsg", hle_enosys },
    { "_recvmsg", hle_enosys },
    { "_socketpair", hle_enosys },
    { "_pipe", hle_enosys },
    { "_poll", hle_enosys },
    { "_select", hle_select },
    { "_ioctl", hle_enosys },
    { "_fcntl", hle_fcntl_real },
    { "_getaddrinfo", hle_getaddrinfo },
    { "_freeaddrinfo", hle_freeaddrinfo },
    { "_getnameinfo", hle_enosys },
    { "_freeifaddrs", hle_enosys },
    { "_getifaddrs", hle_enosys },
    { "_if_nametoindex", hle_enosys },
    { "_dladdr", hle_enosys },
    { "_dlclose", hle_enosys },
    { "_dlerror", hle_enosys },
    { "_dlopen", hle_enosys },
    { "_dlsym", hle_enosys },
    { "_getpwuid", hle_getpwuid },
    { "_getpwuid_r", hle_getpwuid_r },
    { "_gethostbyname", hle_gethostbyname },
    { "_sysctlbyname", hle_sysctlbyname },
    { "_setlocale", hle_setlocale },
    { "_socket", hle_socket },
    { "_connect", hle_connect },
    { "_send", hle_send },
    { "_recv", hle_recv },
    { "_close", hle_close_socket },
    { "_getsockopt", hle_getsockopt },
    { "_select", hle_select },
    { "_fstat", hle_fstat },
    { "_stat", hle_stat },
    { "_getaddrinfo", hle_getaddrinfo },
    { "_freeaddrinfo", hle_freeaddrinfo },
    { "_fcntl", hle_fcntl_real },
    { "_qsort", hle_qsort },
    { "_dyld_func_lookup", hle_dyld_func_lookup },
    { "__dyld_get_image_header", hle_dyld_get_image_header },
    { "__dyld_get_image_name", hle_dyld_get_image_name },
    { "_bsearch", hle_bsearch },
};

#define HLE_TABLE_N (sizeof(hle_table) / sizeof(hle_table[0]))

static int hle_lookup(const char *name)
{
    size_t i;
    for (i = 0; i < HLE_TABLE_N; i++) {
        if (strcmp(hle_table[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static uint32_t hle_ids_used;

static void hle_dyld_func_lookup(hle_env *e)
{
    char name[256];
    uint32_t target = SHIM_RET0;
    g_read_str(e->g, e->a[0], name, sizeof(name));
    if (trace_enabled()) {
        fprintf(stderr, "[sosetta] dyld_func_lookup(%s)\n", name);
    }
    if (strcmp(name, "__dyld_image_count") == 0) {
        target = SHIM_RET1;
    } else if (strcmp(name, "__dyld_get_image_header") == 0) {
        target = TRAP_HEADER;
    } else if (strcmp(name, "__dyld_get_image_name") == 0) {
        target = TRAP_NAME;
    }
    if (e->a[1]) {
        uint8_t tmp[4];
        put_be32(tmp, target);
        g_write(e->g, e->a[1], tmp, 4);
    }
    e->ret = 0;
}

int sosetta_hle_bind(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                     const sosetta_macho *im)
{
    size_t i;

    if (sosetta_guest_map(g, MISC_BASE, MISC_SIZE, VM_PROT_READ | VM_PROT_WRITE) != 0 ||
        sosetta_guest_map(g, RUNE_BASE, RUNE_SIZE, VM_PROT_READ | VM_PROT_WRITE) != 0 ||
        sosetta_guest_map(g, SF_BASE, SF_SIZE, VM_PROT_READ | VM_PROT_WRITE) != 0 ||
        sosetta_guest_map(g, HEAP_BASE, HEAP_SIZE, VM_PROT_READ | VM_PROT_WRITE) != 0) {
        return -1;
    }
    hle_socket_init();
    {
        uint32_t km_ptr = 0;
        uint8_t tmp[4];
        g_read(g, 0x56C580u, &km_ptr, 4);
        if (km_ptr) {
            put_be32(tmp, 0x8fe01000u);
            g_write(g, km_ptr, tmp, 4);
        }
    }
    ctx->errno_addr = ERRNO_ADDR;
    {
        uint8_t z4[4];
        put_be32(z4, 0);
        g_write(g, CTHREAD_ADDR, z4, 4);
        g_write(g, MACHINIT_ADDR, z4, 4);
    }
    heap_init(g);
    memset(sf_kind, 0, sizeof(sf_kind));
    memset(sf_host, 0, sizeof(sf_host));
    sf_kind[0] = SF_KIND_STD;
    sf_kind[1] = SF_KIND_STD;
    sf_kind[2] = SF_KIND_STD;
    sf_fd[0] = 0;
    sf_fd[1] = 1;
    sf_fd[2] = 2;

    if (im->nindirectsyms == 0) {
        return 0;
    }
    hle_ids_used = HLE_TABLE_N;

    for (i = 0; i < im->nsects; i++) {
        const sosetta_sect *s = &im->sects[i];
        uint32_t type = SECTION_TYPE(s->flags);
        uint32_t n;
        uint32_t k;
        if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) {
            continue;
        }
        n = s->size / 4u;
        for (k = 0; k < n; k++) {
            uint32_t symidx;
            const char *name = NULL;
            symidx = be32(im->data + im->indirectsymoff +
                          (s->reserved1 + k) * 4u);
            if ((symidx & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) != 0) {
                continue;
            }
            if (sosetta_macho_sym_name(im, symidx, &name) != 0 || !name) {
                continue;
            }
            if (type == S_LAZY_SYMBOL_POINTERS) {
                int id = hle_lookup(name);
                if (id < 0) {
                    fprintf(stderr,
                            "[sosetta] hle: no impl for %s (id=%u)\n",
                            name, hle_ids_used);
                    id = (int)hle_ids_used++;
                }
                if (hle_ids_used >= HLE_TRAP_SIZE / 4u) {
                    return -1;
                }
                {
                    uint32_t trap = HLE_TRAP_BASE + 4u * (uint32_t)id;
                    uint8_t tmp[4];
                    put_be32(tmp, trap);
                    g_write(g, s->addr + 4u * k, tmp, 4);
                }
            } else {
                uint32_t value = 0;
                int known = 1;
                if (strcmp(name, "___sF") == 0) {
                    value = SF_BASE;
                } else if (strcmp(name, "__DefaultRuneLocale") == 0) {
                    value = RUNE_BASE;
                } else if (strcmp(name, "__cthread_init_routine") == 0) {
                    value = CTHREAD_ADDR;
                } else if (strcmp(name, "_mach_init_routine") == 0) {
                    value = MACHINIT_ADDR;
                } else if (strcmp(name, "_errno") == 0) {
                    value = ERRNO_ADDR;
                } else {
                    known = 0;
                }
                if (known) {
                    uint8_t tmp[4];
                    put_be32(tmp, value);
                    g_write(g, s->addr + 4u * k, tmp, 4);
                }
            }
        }
    }
    if (sosetta_guest_map(g, SHIM_BASE, SHIM_SIZE,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXEC) == 0) {
        uint8_t code[20];
        size_t si;
        put_be32(code, 0x3ca08fe0u);
        put_be32(code + 4, 0x60a51000u);
        put_be32(code + 8, 0x90a40000u);
        put_be32(code + 12, 0x38600000u);
        put_be32(code + 16, 0x4e800020u);
        g_write(g, SHIM_BASE, code, sizeof(code));
        put_be32(code, 0x38600001u);
        put_be32(code + 4, 0x4e800020u);
        g_write(g, SHIM_RET1, code, 8);
        put_be32(code, 0x38600000u);
        put_be32(code + 4, 0x4e800020u);
        g_write(g, SHIM_RET0, code, 8);
        for (si = 0; si < im->nsegs; si++) {
            if (im->segs[si].filesize > 0) {
                hle_image_header = (uint32_t)im->segs[si].vmaddr;
                break;
            }
        }
    }
    for (i = 0; i < im->nsects; i++) {
        const sosetta_sect *s = &im->sects[i];
        if (strcmp(s->sectname, "__dyld") != 0) {
            continue;
        }
        if (s->size >= 8u) {
            uint8_t tmp[4];
            put_be32(tmp, 0x8fe01000u);
            g_write(g, s->addr, tmp, 4);
            put_be32(tmp, SHIM_BASE);
            g_write(g, s->addr + 4u, tmp, 4);
        }
    }
    return 0;
}

void sosetta_hle_set_errno(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                           uint32_t darwin_errno)
{
    uint8_t tmp[4];
    if (!ctx || ctx->errno_addr == 0) {
        return;
    }
    put_be32(tmp, darwin_errno);
    g_write(g, ctx->errno_addr, tmp, 4);
}

void sosetta_hle_call(sosetta_guest *g, sosetta_syscall_ctx *ctx,
                      uint32_t pc, uint32_t id, const uint32_t *a,
                      uint32_t *ret, hle_env_public *out)
{
    hle_env e;
    e.g = g;
    e.ctx = ctx;
    e.a = a;
    e.ret = 0;
    e.has_hi = 0;
    e.ret_hi = 0;
    e.has_fret = 0;
    e.fret = 0;
    e.has_redirect = 0;
    e.redirect_pc = 0;
    e.call_r3 = 0;
    e.call_r4 = 0;
    e.call_lr = TRAP_BSEARCH_RET;
    if (trace_enabled()) {
        uint32_t pc = 0;
        uint32_t lr = 0;
        uint32_t km = 0;
        sosetta_guest_get_pc(g, &pc);
        uc_reg_read(g->uc, UC_PPC_REG_LR, &lr);
        sosetta_guest_read(g, 0x570738u, &km, 4);
        fprintf(stderr,
                "[sosetta] hle call id=%u %s (pc=0x%08x lr=0x%08x km=0x%08x r3=0x%08x)\n",
                id, id < HLE_TABLE_N ? hle_table[id].name : "?", pc, lr, km,
                a[0]);
    }
    if (pc == TRAP_PTHREAD_RET) {
        if (pts.active) {
            pts.active = 0;
            e.has_redirect = 1;
            e.redirect_pc = pts.caller_lr;
            e.call_r3 = 0x2000u;
        }
    } else if (pc == TRAP_BSEARCH_RET) {
        hle_bsearch_return(&e);
    } else if (id < HLE_TABLE_N) {
        hle_table[id].fn(&e);
    } else {
        fprintf(stderr, "[sosetta] hle: no implementation for id %u\n", id);
    }
    if (trace_enabled()) {
        fprintf(stderr,
                "[sosetta] hle ret id=%u %s r3=0x%08x\n",
                id, id < HLE_TABLE_N ? hle_table[id].name : "?", e.ret);
    }
    if (e.has_hi) {
        sosetta_guest_set_gpr(g, 4, e.ret_hi);
    }
    if (e.has_fret) {
        uint64_t bits;
        memcpy(&bits, &e.fret, sizeof(bits));
        uc_reg_write(g->uc, UC_PPC_REG_FPR1, &bits);
    }
    out->has_redirect = e.has_redirect;
    out->redirect_pc = e.redirect_pc;
    out->call_r3 = e.call_r3;
    out->call_r4 = e.call_r4;
    out->call_lr = e.call_lr;
    *ret = e.ret;
}
