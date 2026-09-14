#include "sosetta/cpu.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        failures++;
    } else {
        printf("ok: %s\n", what);
    }
}

static const uint8_t prog_exit42[] = {
    0x38, 0x00, 0x00, 0x01,
    0x38, 0x60, 0x00, 0x2A,
    0x44, 0x00, 0x00, 0x02,
};

static const uint8_t prog_sc_alone[] = {
    0x44, 0x00, 0x00, 0x02,
};

static void test_gpr_pc(void)
{
    sosetta_guest *g;
    uint32_t v;

    check(sosetta_guest_open(&g) == 0, "guest open");
    check(sosetta_guest_set_gpr(g, 3, 9u) == 0, "set gpr");
    check(sosetta_guest_get_gpr(g, 3, &v) == 0 && v == 9u, "get gpr");
    check(sosetta_guest_set_pc(g, 0x1234u) == 0, "set pc");
    check(sosetta_guest_get_pc(g, &v) == 0 && v == 0x1234u, "get pc");
    sosetta_guest_close(g);
}

static void test_sc_with_hook(void)
{
    sosetta_guest *g;
    sosetta_syscall_ctx ctx;
    uint32_t pc;

    memset(&ctx, 0, sizeof(ctx));
    check(sosetta_guest_open(&g) == 0, "guest open");
    check(sosetta_guest_map(g, 0x1000u, 0x1000u, 7u) == 0, "map code");
    check(sosetta_guest_write(g, 0x1000u, prog_exit42,
                              sizeof(prog_exit42)) == 0, "write code");
    check(sosetta_guest_set_pc(g, 0x1000u) == 0, "set entry pc");
    check(sosetta_guest_install_syscall(g, &ctx) == 0, "install syscall");

    check(sosetta_guest_run(g) == 0, "run returns ok");
    check(ctx.should_stop, "syscall set should_stop");
    check(ctx.exit_code == 42, "exit code 42");
    check(sosetta_guest_get_pc(g, &pc) == 0 && pc == 0x100Cu,
          "pc advanced past sc");
    sosetta_guest_close(g);
}

static void test_sc_without_hook(void)
{
    sosetta_guest *g;
    int rc;

    check(sosetta_guest_open(&g) == 0, "guest open");
    check(sosetta_guest_map(g, 0x1000u, 0x1000u, 7u) == 0, "map code");
    check(sosetta_guest_write(g, 0x1000u, prog_sc_alone,
                              sizeof(prog_sc_alone)) == 0, "write sc");
    check(sosetta_guest_set_pc(g, 0x1000u) == 0, "set entry pc");
    rc = sosetta_guest_run(g);
    check(rc != 0, "sc without hook raises exception");
    sosetta_guest_close(g);
}

int main(void)
{
    test_gpr_pc();
    test_sc_with_hook();
    test_sc_without_hook();

    if (failures) {
        printf("test_cpu: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_cpu: all passed\n");
    return 0;
}