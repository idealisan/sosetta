#include "sosetta/runtime.h"

#include <stdio.h>
#include <string.h>

static void usage(FILE *f, const char *prog)
{
    fprintf(f, "usage: %s <powerpc-macho> [guest args...]\n", prog);
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