#include "sosetta/runtime.h"
#include "macho_builder.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    mf_builder b;
    uint8_t *file;
    size_t filelen;
    FILE *out;
    const char *path;

    if (argc < 2) {
        fprintf(stderr, "usage: gen_hello <output.ppc>\n");
        return 1;
    }
    path = argv[1];

    if (mf_default_hello(&b) != 0) {
        fprintf(stderr, "gen_hello: builder init failed\n");
        return 1;
    }
    if (mf_build(&b, &file, &filelen) != 0) {
        fprintf(stderr, "gen_hello: build failed\n");
        mf_free(&b);
        return 1;
    }
    mf_free(&b);

    out = fopen(path, "wb");
    if (!out) {
        fprintf(stderr, "gen_hello: cannot open %s\n", path);
        free(file);
        return 1;
    }
    if (filelen > 0 && fwrite(file, 1, filelen, out) != filelen) {
        fprintf(stderr, "gen_hello: short write\n");
        fclose(out);
        free(file);
        return 1;
    }
    fclose(out);
    free(file);
    return 0;
}