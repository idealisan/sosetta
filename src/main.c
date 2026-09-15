#include "sosetta/runtime.h"
#include "sosetta/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *f, const char *prog)
{
    fprintf(f, "usage: %s <powerpc-macho> [guest args...]\n", prog);
    fprintf(f, "       %s --symbols <powerpc-macho> <addr>...\n", prog);
}

static int run_symbols(const char *path, char **addrs, int naddrs)
{
    FILE *f;
    long len;
    uint8_t *buf;
    struct sosetta_debug_symtab st;
    int i;

    f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "sosetta: cannot open file: %s\n", path);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) {
        fclose(f);
        fprintf(stderr, "sosetta: empty file\n");
        return 2;
    }
    buf = malloc((size_t)len);
    if (!buf) {
        fclose(f);
        return 2;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        fprintf(stderr, "sosetta: short read\n");
        return 2;
    }
    fclose(f);

    if (sosetta_debug_symtab_load(buf, (size_t)len, &st) != 0) {
        fprintf(stderr, "sosetta: no symbol table in %s\n", path);
        free(buf);
        return 2;
    }
    fprintf(stderr, "sosetta: %zu symbols\n", st.count);
    for (i = 0; i < naddrs; i++) {
        uint32_t addr = (uint32_t)strtoul(addrs[i], NULL, 0);
        char sym[128];
        sosetta_debug_symtab_sym(&st, addr, sym, sizeof(sym));
        printf("0x%08x = %s\n", addr, sym);
    }
    sosetta_debug_symtab_free(&st);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    sosetta_runtime rt;
    char err[256];
    int code;

    if (argc < 2) {
        usage(stderr, argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout, argv[0]);
        return 0;
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("sosetta 0.1.0\n");
        return 0;
    }
    if (strcmp(argv[1], "--symbols") == 0) {
        if (argc < 4) {
            usage(stderr, argv[0]);
            return 2;
        }
        return run_symbols(argv[2], argv + 3, argc - 3);
    }

    if (sosetta_runtime_open(&rt, argv[1], err, sizeof(err)) != 0) {
        fprintf(stderr, "sosetta: %s\n", err);
        return 2;
    }

    if (sosetta_runtime_load(&rt) != 0) {
        fprintf(stderr, "sosetta: failed to load image\n");
        sosetta_runtime_close(&rt);
        return 2;
    }

    if (sosetta_runtime_setup_stack(&rt, argc - 1, argv + 1, NULL) != 0) {
        fprintf(stderr, "sosetta: failed to set up stack\n");
        sosetta_runtime_close(&rt);
        return 2;
    }

    code = sosetta_runtime_run(&rt);
    if (code < 0) {
        fprintf(stderr, "sosetta: guest execution failed\n");
        sosetta_runtime_close(&rt);
        return 2;
    }

    sosetta_runtime_close(&rt);
    fprintf(stderr, "sosetta: exit code %d\n", code);
    return code & 0xff;
}