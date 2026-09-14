#include "sosetta/runtime.h"
#include "sosetta/endian.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RUNTIME_PAGE_SIZE 0x1000u
#define RUN_TIMEOUT_US    5000000u

static int has_thread_with_sp(const sosetta_runtime *rt);

static int read_file_all(const char *path, uint8_t **out, size_t *outn,
                         char *errbuf, size_t errsz)
{
    FILE *f;
    long len;
    uint8_t *buf;

    f = fopen(path, "rb");
    if (!f) {
        snprintf(errbuf, errsz, "cannot open file: %s", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        snprintf(errbuf, errsz, "cannot seek: %s", path);
        return -1;
    }
    len = ftell(f);
    if (len < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        snprintf(errbuf, errsz, "cannot read file size: %s", path);
        return -1;
    }

    buf = (uint8_t *)malloc((size_t)len ? (size_t)len : 1);
    if (!buf) {
        fclose(f);
        snprintf(errbuf, errsz, "out of memory");
        return -1;
    }
    if (len > 0 && fread(buf, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        free(buf);
        snprintf(errbuf, errsz, "short read: %s", path);
        return -1;
    }
    fclose(f);

    *out = buf;
    *outn = (size_t)len;
    return 0;
}

static int rt_mem_map(void *data, uint32_t addr, uint32_t size, uint32_t prot)
{
    sosetta_runtime *rt = (sosetta_runtime *)data;

    return sosetta_guest_map(rt->guest, addr, size, prot);
}

static int rt_mem_unmap(void *data, uint32_t addr, uint32_t size)
{
    sosetta_runtime *rt = (sosetta_runtime *)data;
    uint64_t base;
    uint64_t end;
    uc_err err;

    if (!rt->guest || !rt->guest->uc || addr == 0 || size == 0) {
        return -1;
    }
    base = (uint64_t)addr & ~(uint64_t)(RUNTIME_PAGE_SIZE - 1);
    end = (uint64_t)addr + size;
    end = (end + RUNTIME_PAGE_SIZE - 1) & ~(uint64_t)(RUNTIME_PAGE_SIZE - 1);
    if (end <= base) {
        return -1;
    }
    err = uc_mem_unmap(rt->guest->uc, base, end - base);
    return err == UC_ERR_OK ? 0 : -1;
}

int sosetta_runtime_open(sosetta_runtime *rt, const char *path,
                         char *errbuf, size_t errsz)
{
    uint8_t *buf = NULL;
    size_t n = 0;
    int rc;

    memset(rt, 0, sizeof(*rt));
    if (read_file_all(path, &buf, &n, errbuf, errsz) != 0) {
        return -1;
    }
    rc = sosetta_runtime_open_bytes(rt, buf, n, errbuf, errsz);
    free(buf);
    return rc;
}

int sosetta_runtime_open_bytes(sosetta_runtime *rt, const uint8_t *data,
                               size_t size, char *errbuf, size_t errsz)
{
    memset(rt, 0, sizeof(*rt));

    rt->filebuf = (uint8_t *)malloc(size ? size : 1);
    if (!rt->filebuf) {
        snprintf(errbuf, errsz, "out of memory");
        return -1;
    }
    if (size > 0) {
        memcpy(rt->filebuf, data, size);
    }
    rt->filelen = size;

    if (sosetta_macho_parse(rt->filebuf, size, &rt->im, errbuf, errsz) != 0) {
        sosetta_runtime_close(rt);
        return -1;
    }

    rt->sys.stdin_fd = 0;
    rt->sys.stdout_fd = 1;
    rt->sys.stderr_fd = 2;
    rt->sys.map_hint = 0x10000000u;
    return 0;
}

void sosetta_runtime_close(sosetta_runtime *rt)
{
    if (!rt) {
        return;
    }
    if (rt->guest) {
        sosetta_guest_close(rt->guest);
        rt->guest = NULL;
    }
    sosetta_macho_free(&rt->im);
    free(rt->filebuf);
    rt->filebuf = NULL;
}

int sosetta_runtime_load(sosetta_runtime *rt)
{
    sosetta_macho *im = &rt->im;
    size_t i;
    int found_exec = 0;

    if (im->is_64) {
        return -1;
    }

    if (sosetta_guest_open(&rt->guest) != 0) {
        return -1;
    }

    rt->sys.mem_map = rt_mem_map;
    rt->sys.mem_unmap = rt_mem_unmap;
    rt->sys.mem_data = rt;
    if (sosetta_guest_install_syscall(rt->guest, &rt->sys) != 0) {
        return -1;
    }

    for (i = 0; i < im->nsegs; i++) {
        sosetta_seg *s = &im->segs[i];
        uint32_t prot = s->initprot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXEC);

        if (prot == 0) {
            prot = VM_PROT_READ;
        }
        if (sosetta_guest_map(rt->guest, (uint32_t)s->vmaddr,
                              (uint32_t)s->vmsize, prot) != 0) {
            return -1;
        }
        if (s->filesize > 0) {
            if ((uint64_t)s->fileoff + s->filesize > rt->filelen) {
                return -1;
            }
            if (sosetta_guest_write(rt->guest, (uint32_t)s->vmaddr,
                                    rt->filebuf + s->fileoff,
                                    (size_t)s->filesize) != 0) {
                return -1;
            }
        }
        if (s->initprot & VM_PROT_EXEC) {
            found_exec = 1;
        }
    }

    if (im->thread.has_thread) {
        rt->entry_pc = im->thread.entry_pc;
    } else if (found_exec) {
        for (i = 0; i < im->nsegs; i++) {
            if (im->segs[i].initprot & VM_PROT_EXEC) {
                rt->entry_pc = (uint32_t)im->segs[i].vmaddr;
                break;
            }
        }
    } else {
        return -1;
    }

    if (rt->entry_pc == 0) {
        return -1;
    }
    return 0;
}

int sosetta_runtime_setup_stack(sosetta_runtime *rt, int argc, char **argv,
                                char **envp)
{
    uint32_t stack_top;
    uint32_t stack_base;
    uint32_t sp;
    uint32_t top_aligned;
    size_t pool_len = 0;
    size_t pool_pad;
    size_t words_len = 0;
    size_t argw, envw, total_len, actual_len, off;
    int envc = 0;
    int i;
    uint8_t *blk;
    uint32_t *argv_ptr;
    uint32_t *env_ptr;

    while (envp && envp[envc]) {
        envc++;
    }

    if (has_thread_with_sp(rt)) {
        stack_top = rt->im.thread.entry_sp;
    } else {
        stack_top = SOSETTA_STACK_TOP;
    }
    stack_base = (stack_top - SOSETTA_STACK_SIZE) & ~(uint32_t)(RUNTIME_PAGE_SIZE - 1);

    if (sosetta_guest_map(rt->guest, stack_base, stack_top - stack_base,
                          VM_PROT_READ | VM_PROT_WRITE) != 0) {
        return -1;
    }
    rt->stack_top = stack_top;
    rt->stack_base = stack_base;

    for (i = 0; i < argc; i++) {
        pool_len += strlen(argv[i]) + 1;
    }
    for (i = 0; i < envc; i++) {
        pool_len += strlen(envp[i]) + 1;
    }
    pool_pad = (pool_len + 3u) & ~(size_t)3u;
    argw = (size_t)argc + 1;
    envw = (size_t)envc + 1;
    words_len = (1u + argw + envw + 1u) * 4u;
    total_len = words_len + pool_pad;

    top_aligned = stack_top & ~(uint32_t)0x0Fu;
    sp = (top_aligned - (uint32_t)total_len) & ~(uint32_t)0x0Fu;
    if (sp < stack_base) {
        return -1;
    }
    actual_len = top_aligned - sp;

    blk = (uint8_t *)calloc(actual_len, 1);
    argv_ptr = (uint32_t *)calloc(argw, sizeof(*argv_ptr));
    env_ptr = (uint32_t *)calloc(envw, sizeof(*env_ptr));
    if (!blk || !argv_ptr || !env_ptr) {
        free(blk);
        free(argv_ptr);
        free(env_ptr);
        return -1;
    }

    off = 0;
    for (i = 0; i < argc; i++) {
        memcpy(blk + words_len + off, argv[i], strlen(argv[i]) + 1);
        argv_ptr[i] = sp + words_len + (uint32_t)off;
        off += strlen(argv[i]) + 1;
        off = (off + 3u) & ~(size_t)3u;
    }
    for (i = 0; i < envc; i++) {
        memcpy(blk + words_len + off, envp[i], strlen(envp[i]) + 1);
        env_ptr[i] = sp + words_len + (uint32_t)off;
        off += strlen(envp[i]) + 1;
        off = (off + 3u) & ~(size_t)3u;
    }

    off = 0;
    put_be32(blk + off, (uint32_t)argc);
    off += 4;
    for (i = 0; i < argc; i++) {
        put_be32(blk + off, argv_ptr[i]);
        off += 4;
    }
    put_be32(blk + off, 0);
    off += 4;
    for (i = 0; i < envc; i++) {
        put_be32(blk + off, env_ptr[i]);
        off += 4;
    }
    put_be32(blk + off, 0);
    off += 4;
    put_be32(blk + off, 0);
    off += 4;

    if (sosetta_guest_write(rt->guest, sp, blk, actual_len) != 0) {
        free(blk);
        free(argv_ptr);
        free(env_ptr);
        return -1;
    }

    sosetta_guest_set_gpr(rt->guest, 1, sp);

    free(blk);
    free(argv_ptr);
    free(env_ptr);
    return 0;
}

static int has_thread_with_sp(const sosetta_runtime *rt)
{
    return rt->im.thread.has_thread && rt->im.thread.entry_sp != 0;
}

int sosetta_runtime_run(sosetta_runtime *rt)
{
    uint32_t v;

    rt->ran = 1;
    if (sosetta_guest_set_pc(rt->guest, rt->entry_pc) != 0) {
        return -1;
    }

    if (rt->im.thread.has_thread) {
        v = rt->im.thread.cr;
        uc_reg_write(rt->guest->uc, UC_PPC_REG_CR, &v);
        v = rt->im.thread.xer;
        uc_reg_write(rt->guest->uc, UC_PPC_REG_XER, &v);
        v = rt->im.thread.lr;
        uc_reg_write(rt->guest->uc, UC_PPC_REG_LR, &v);
        v = rt->im.thread.ctr;
        uc_reg_write(rt->guest->uc, UC_PPC_REG_CTR, &v);
    }

    rt->guest->run_timeout_us = RUN_TIMEOUT_US;
    if (sosetta_guest_run(rt->guest) != 0) {
        return -1;
    }

    rt->exit_code = rt->sys.exit_code;
    if (!rt->sys.should_stop) {
        return -1;
    }
    return rt->exit_code;
}