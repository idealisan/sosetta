#ifndef SOSETTA_MACHO_H
#define SOSETTA_MACHO_H

#include <stdint.h>
#include <stddef.h>

#define MH_MAGIC        0xfeedfaceu
#define MH_MAGIC_64     0xfeedfacfu
#define FAT_MAGIC       0xcafebabeu

#define CPU_TYPE_POWERPC   0x12u
#define CPU_TYPE_POWERPC64 0x01000012u

#define LC_SEGMENT      0x01u
#define LC_SYMTAB       0x02u
#define LC_UNIXTHREAD   0x05u
#define LC_DYSYMTAB     0x0Bu
#define LC_SEGMENT_64   0x19u

#define PPC_THREAD_STATE        1u
#define PPC_THREAD_STATE_COUNT  42u

#define SG_ZEROFILL 0x01u

#define S_ZEROFILL                 0x01u
#define S_NON_LAZY_SYMBOL_POINTERS 0x06u
#define S_LAZY_SYMBOL_POINTERS     0x07u
#define S_SYMBOL_STUBS             0x08u

#define SECTION_TYPE(x)     ((x) & 0xFFu)
#define INDIRECT_SYMBOL_LOCAL 0x80000000u
#define INDIRECT_SYMBOL_ABS   0x40000000u

#define VM_PROT_READ  0x01u
#define VM_PROT_WRITE 0x02u
#define VM_PROT_EXEC  0x04u

#define SEGNAME_MAX 17
#define SECNAME_MAX 17

typedef struct sosetta_seg {
    char     segname[SEGNAME_MAX];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t flags;
} sosetta_seg;

typedef struct sosetta_sect {
    char     sectname[SECNAME_MAX];
    char     segname[SECNAME_MAX];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
} sosetta_sect;

typedef struct sosetta_thread {
    int      has_thread;
    uint32_t entry_pc;
    uint32_t entry_sp;
    uint32_t cr;
    uint32_t xer;
    uint32_t lr;
    uint32_t ctr;
} sosetta_thread;

typedef struct sosetta_macho {
    const uint8_t *data;
    size_t         size;
    int            is_64;
    int            is_fat;
    uint32_t       cputype;
    uint32_t       cpusubtype;
    uint32_t       filetype;
    uint32_t       flags;
    sosetta_seg   *segs;
    size_t         nsegs;
    sosetta_sect  *sects;
    size_t         nsects;
    uint32_t       symoff;
    uint32_t       nsyms;
    uint32_t       stroff;
    uint32_t       strsize;
    uint32_t       indirectsymoff;
    uint32_t       nindirectsyms;
    uint32_t       iundefsym;
    uint32_t       nundefsym;
    sosetta_thread thread;
} sosetta_macho;

int sosetta_macho_parse(const void *data, size_t size, sosetta_macho *out,
                        char *errbuf, size_t errsz);
void sosetta_macho_free(sosetta_macho *m);
const char *sosetta_macho_strerror(int rc, const char *errbuf, size_t errsz);

int sosetta_macho_sym_name(const sosetta_macho *m, uint32_t symidx,
                           const char **out);
int sosetta_macho_sym_undef(const sosetta_macho *m, uint32_t symidx);

#endif
