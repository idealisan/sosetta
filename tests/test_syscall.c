#define _POSIX_C_SOURCE 200809L

#include "sosetta/cpu.h"
#include "sosetta/syscall.h"
#include "sosetta/endian.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

static void check(int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    } else {
        fprintf(stderr, "ok: %s\n", what);
    }
}

static const uint8_t prog_write[] = {
    0x38, 0x00, 0x00, 0x04,
    0x38, 0x60, 0x00, 0x01,
    0x3C, 0x80, 0x00, 0x00,
    0x60, 0x84, 0x20, 0x00,
    0x38, 0xA0, 0x00, 0x04,
    0x44, 0x00, 0x00, 0x02,
};

static const uint8_t prog_read[] = {
    0x38, 0x00, 0x00, 0x03,
    0x38, 0x60, 0x00, 0x00,
    0x3C, 0x80, 0x00, 0x00,
    0x60, 0x84, 0x20, 0x00,
    0x38, 0xA0, 0x00, 0x04,
    0x44, 0x00, 0x00, 0x02,
    0x38, 0x00, 0x00, 0x01,
    0x38, 0x60, 0x00, 0x00,
    0x44, 0x00, 0x00, 0x02,
};

static const uint8_t prog_badwrite[] = {
    0x38, 0x00, 0x00, 0x04,
    0x38, 0x60, 0x00, 0x01,
    0x3C, 0x80, 0x00, 0x00,
    0x60, 0x84, 0x9A, 0x00,
    0x38, 0xA0, 0x00, 0x04,
    0x44, 0x00, 0x00, 0x02,
};

static sosetta_guest *make_guest(void)
{
    sosetta_guest *g;

    if (sosetta_guest_open(&g) != 0) {
        return NULL;
    }
    if (sosetta_guest_map(g, 0x1000u, 0x1000u, 7u) != 0) {
        sosetta_guest_close(g);
        return NULL;
    }
    if (sosetta_guest_map(g, 0x2000u, 0x1000u, 3u) != 0) {
        sosetta_guest_close(g);
        return NULL;
    }
    return g;
}

static int run_pc(sosetta_guest *g, const uint8_t *code, size_t n,
                  uint32_t until)
{
    if (sosetta_guest_write(g, 0x1000u, code, n) != 0) {
        return -1;
    }
    if (sosetta_guest_set_pc(g, 0x1000u) != 0) {
        return -1;
    }
    g->run_until = until;
    g->run_timeout_us = 5000000u;
    return sosetta_guest_run(g);
}

static void test_write(void)
{
    sosetta_guest *g;
    sosetta_syscall_ctx ctx;
    FILE *f;
    uint32_t r3;
    char out[8];
    ssize_t got;
    int save_out;

    memset(&ctx, 0, sizeof(ctx));
    g = make_guest();
    check(g != NULL, "guest setup");
    if (!g) {
        return;
    }

    check(sosetta_guest_write(g, 0x2000u, "TEST", 4) == 0, "seed guest data");
    check(sosetta_guest_install_syscall(g, &ctx) == 0, "install syscall");

    f = tmpfile();
    check(f != NULL, "tmpfile for stdout");
    if (!f) {
        sosetta_guest_close(g);
        return;
    }
    save_out = dup(1);
    check(save_out >= 0, "save stdout");
    check(dup2(fileno(f), 1) >= 0, "redirect stdout");

    check(run_pc(g, prog_write, sizeof(prog_write), 0x1018u) == 0,
          "run write program");
    check(sosetta_guest_get_gpr(g, 3, &r3) == 0 && r3 == 4u,
          "write returned 4");

    fflush(stdout);
    check(lseek(fileno(f), 0, SEEK_SET) == 0, "rewind capture file");
    got = read(fileno(f), out, 4);
    check(got == 4 && memcmp(out, "TEST", 4) == 0, "guest wrote TEST");

    fclose(f);
    if (save_out >= 0) {
        dup2(save_out, 1);
        close(save_out);
    }
    sosetta_guest_close(g);
}

static void test_read(void)
{
    sosetta_guest *g;
    sosetta_syscall_ctx ctx;
    FILE *f;
    uint8_t buf[8];
    uint32_t r3;
    int save_in;

    memset(&ctx, 0, sizeof(ctx));
    g = make_guest();
    check(g != NULL, "guest setup");
    if (!g) {
        return;
    }
    check(sosetta_guest_install_syscall(g, &ctx) == 0, "install syscall");

    f = tmpfile();
    check(f != NULL, "tmpfile for stdin");
    if (!f) {
        sosetta_guest_close(g);
        return;
    }
    check(fwrite("ABCD", 1, 4, f) == 4, "seed stdin file");
    check(fflush(f) == 0, "flush stdin file");
    check(fseek(f, 0, SEEK_SET) == 0, "rewind stdin file");
    save_in = dup(0);
    check(save_in >= 0, "save stdin");
    check(dup2(fileno(f), 0) >= 0, "redirect stdin");

    check(run_pc(g, prog_read, sizeof(prog_read), 0) == 0,
          "run read program");
    check(ctx.should_stop && ctx.exit_code == 0, "guest exited");
    check(sosetta_guest_get_gpr(g, 3, &r3) == 0, "read gpr3");

    check(sosetta_guest_read(g, 0x2000u, buf, 4) == 0 && memcmp(buf, "ABCD", 4) == 0,
          "guest buffer read ABCD");

    fclose(f);
    if (save_in >= 0) {
        dup2(save_in, 0);
        close(save_in);
    }
    sosetta_guest_close(g);
}

static void test_bad_write(void)
{
    sosetta_guest *g;
    sosetta_syscall_ctx ctx;
    uint32_t r3;

    memset(&ctx, 0, sizeof(ctx));
    g = make_guest();
    check(g != NULL, "guest setup");
    if (!g) {
        return;
    }
    check(sosetta_guest_install_syscall(g, &ctx) == 0, "install syscall");

    check(run_pc(g, prog_badwrite, sizeof(prog_badwrite), 0x1018u) == 0,
          "run badwrite program");
    check(sosetta_guest_get_gpr(g, 3, &r3) == 0 && r3 == (uint32_t)-14,
          "bad write returned -EFAULT");

    sosetta_guest_close(g);
}

static void test_errno_mapping(void)
{
    check(sosetta_syscall_errno_to_darwin(ENOSYS) == 78, "ENOSYS->78");
    check(sosetta_syscall_errno_to_darwin(EFAULT) == 14, "EFAULT->14");
    check(sosetta_syscall_errno_to_darwin(EBADF) == 9, "EBADF->9");
    check(sosetta_syscall_errno_to_darwin(ENOMEM) == 12, "ENOMEM->12");
    check(sosetta_syscall_errno_to_darwin(EINVAL) == 22, "EINVAL->22");
    check(sosetta_syscall_errno_to_darwin(0) == 0, "0->0");
    check(sosetta_syscall_errno_to_darwin(12345) == 12345, "unknown passthrough");
}

int main(void)
{
    test_write();
    test_read();
    test_bad_write();
    test_errno_mapping();

    if (failures) {
        printf("test_syscall: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_syscall: all passed\n");
    return 0;
}