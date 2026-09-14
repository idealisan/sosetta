#define _POSIX_C_SOURCE 200809L

#include "sosetta/runtime.h"
#include "sosetta/endian.h"
#include "macho_builder.h"

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

typedef struct fixture_result {
    uint8_t *file;
    size_t   filelen;
} fixture_result;

static int build_hello(fixture_result *r)
{
    mf_builder b;
    int rc;

    if (mf_default_hello(&b) != 0) {
        return -1;
    }
    rc = mf_build(&b, &r->file, &r->filelen);
    mf_free(&b);
    return rc;
}

static int build_argc(fixture_result *r)
{
    static const uint8_t argc_code[] = {
        0x80, 0x61, 0x00, 0x00,
        0x38, 0x00, 0x00, 0x01,
        0x44, 0x00, 0x00, 0x02,
    };
    mf_builder b;
    int rc;

    mf_init(&b);
    if (!b.cmds || !b.payload || !b.segs) {
        mf_free(&b);
        return -1;
    }
    mf_add_seg(&b, "__TEXT", 0x1000u, 0x1000u,
               VM_PROT_READ | VM_PROT_EXEC, VM_PROT_READ | VM_PROT_EXEC,
               argc_code, (uint32_t)sizeof(argc_code));
    mf_add_thread(&b, 0x1000u, 0u);
    rc = mf_build(&b, &r->file, &r->filelen);
    mf_free(&b);
    return rc;
}

static void test_hello(void)
{
    fixture_result fr = { 0 };
    sosetta_runtime rt;
    char err[256];
    FILE *f;
    char out[32];
    ssize_t got;
    int save_out;

    check(build_hello(&fr) == 0, "build hello fixture");
    if (fr.filelen == 0) {
        return;
    }

    check(sosetta_runtime_open_bytes(&rt, fr.file, fr.filelen,
                                     err, sizeof(err)) == 0,
          "open bytes");
    check(sosetta_runtime_load(&rt) == 0, "load");
    {
        char *argv[] = { "hello.ppc" };
        check(sosetta_runtime_setup_stack(&rt, 1, argv, NULL) == 0,
              "setup stack");
    }

    f = tmpfile();
    check(f != NULL, "tmpfile for integration");
    if (!f) {
        sosetta_runtime_close(&rt);
        free(fr.file);
        return;
    }
    save_out = dup(1);
    check(save_out >= 0, "save stdout");
    check(dup2(fileno(f), 1) >= 0, "capture guest stdout");

    check(sosetta_runtime_run(&rt) == 0, "run hello");
    check(rt.exit_code == 0, "hello exit code 0");

    fflush(stdout);
    check(lseek(fileno(f), 0, SEEK_SET) == 0, "rewind capture");
    got = read(fileno(f), out, sizeof(out));
    check(got == 20 && memcmp(out, "Hello from PowerPC!\n", 20) == 0,
          "hello wrote message");

    fclose(f);
    if (save_out >= 0) {
        dup2(save_out, 1);
        close(save_out);
    }
    sosetta_runtime_close(&rt);
    free(fr.file);
}

static void test_argc(void)
{
    fixture_result fr = { 0 };
    sosetta_runtime rt;
    char err[256];
    char *argv[] = { "argc.ppc", "alpha", "beta" };

    check(build_argc(&fr) == 0, "build argc fixture");
    if (fr.filelen == 0) {
        return;
    }

    check(sosetta_runtime_open_bytes(&rt, fr.file, fr.filelen,
                                     err, sizeof(err)) == 0,
          "open bytes");
    check(sosetta_runtime_load(&rt) == 0, "load");
    check(sosetta_runtime_setup_stack(&rt, 3, argv, NULL) == 0,
              "setup stack");
    check(sosetta_runtime_run(&rt) == 3, "run argc");
    check(rt.exit_code == 3, "argc exit code 3");

    sosetta_runtime_close(&rt);
    free(fr.file);
}

int main(void)
{
    test_hello();
    test_argc();

    if (failures) {
        printf("test_integration: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_integration: all passed\n");
    return 0;
}