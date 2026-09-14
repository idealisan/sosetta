#include "sosetta/macho.h"
#include "sosetta/endian.h"
#include "macho_builder.h"

#include <stdio.h>
#include <stdlib.h>
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

static void test_thin_parse(void)
{
    mf_builder b;
    uint8_t *file;
    size_t filelen;
    sosetta_macho m;
    char err[128];

    if (mf_default_hello(&b) != 0) {
        check(0, "mf_default_hello init");
        return;
    }
    if (mf_build(&b, &file, &filelen) != 0) {
        check(0, "mf_build");
        mf_free(&b);
        return;
    }

    check(sosetta_macho_parse(file, filelen, &m, err, sizeof(err)) == 0,
          "parse thin image");
    check(!m.is_64, "not 64-bit");
    check(!m.is_fat, "not fat");
    check(m.cputype == CPU_TYPE_POWERPC, "cputype ppc");
    check(m.nsegs == 2, "two segments");
    if (m.nsegs == 2) {
        check(strcmp(m.segs[0].segname, "__TEXT") == 0, "seg0 name");
        check(m.segs[0].vmaddr == 0x1000u, "seg0 vmaddr");
        check(m.segs[0].initprot == (VM_PROT_READ | VM_PROT_EXEC), "seg0 prot");
        check(m.segs[0].filesize == 36u, "seg0 filesize");
        check(m.segs[1].vmaddr == 0x2000u, "seg1 vmaddr");
        check(m.segs[1].filesize == 20u, "seg1 filesize");
    }
    check(m.thread.has_thread, "has thread");
    check(m.thread.entry_pc == 0x1000u, "thread entry pc");

    sosetta_macho_free(&m);
    mf_free(&b);
    free(file);
}

static void test_bad_inputs(void)
{
    sosetta_macho m;
    char err[128];
    const uint8_t tiny[10] = {0};
    uint8_t badmagic[32];
    uint32_t v = 0x78563412u;
    uint32_t i;

    check(sosetta_macho_parse(tiny, sizeof(tiny), &m, err, sizeof(err)) != 0,
          "reject truncated file");
    put_be32(badmagic, v);
    for (i = 4; i < 32; i++) {
        badmagic[i] = 0;
    }
    check(sosetta_macho_parse(badmagic, sizeof(badmagic), &m, err,
                              sizeof(err)) != 0,
          "reject wrong magic");
}

static void test_fat_parse(void)
{
    mf_builder b;
    uint8_t *thin;
    size_t thin_len;
    uint8_t *fat;
    size_t fat_len;
    uint32_t off1, off2, size1, size2;
    sosetta_macho m;
    char err[128];
    uint8_t *p;

    if (mf_default_hello(&b) != 0) {
        check(0, "mf_default_hello init");
        return;
    }
    if (mf_build(&b, &thin, &thin_len) != 0) {
        mf_free(&b);
        check(0, "mf_build");
        return;
    }

    off1 = 8u + 2u * 20u;
    off2 = 8u + 2u * 20u + 28u;
    size1 = 28u;
    size2 = (uint32_t)thin_len;
    fat_len = off2 + thin_len;
    fat = (uint8_t *)calloc(fat_len ? fat_len : 1, 1);

    put_be32(fat, FAT_MAGIC);
    put_be32(fat + 4, 2u);
    p = fat + 8;
    put_be32(p, 7u);
    put_be32(p + 4, 3u);
    put_be32(p + 8, off1);
    put_be32(p + 12, size1);
    put_be32(p + 16, 2u);
    p += 20;
    put_be32(p, CPU_TYPE_POWERPC);
    put_be32(p + 4, 0u);
    put_be32(p + 8, off2);
    put_be32(p + 12, size2);
    put_be32(p + 16, 2u);

    memcpy(fat + off2, thin, thin_len);

    check(sosetta_macho_parse(fat, fat_len, &m, err, sizeof(err)) == 0,
          "parse fat image");
    check(m.is_fat, "detected fat");
    check(m.cputype == CPU_TYPE_POWERPC, "chose ppc slice");
    check(m.nsegs == 2, "slice has two segments");
    check(m.thread.entry_pc == 0x1000u, "slice thread entry pc");

    sosetta_macho_free(&m);
    free(fat);
    mf_free(&b);
    free(thin);
}

int main(void)
{
    test_thin_parse();
    test_bad_inputs();
    test_fat_parse();

    if (failures) {
        printf("test_macho: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_macho: all passed\n");
    return 0;
}