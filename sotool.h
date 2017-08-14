#ifndef __sotool_h__
#define __sotool_h__

#include <unistd.h>

#define DT_NEEDED 1
#define DT_PLTRELSZ 2
#define DT_PLTGOT 3
#define DT_HASH 4

#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8

#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_INIT 12

#define DT_FINI 13
#define DT_SONAME 14
#define DT_RPATH 15
#define DT_SYMBOLIC 16

#define DT_REL 17
#define DT_RELSZ 18
#define DT_RELENT 19
#define DT_PLTREL 20

#define DT_DEBUG 21
#define DT_TEXTREL 22
#define DT_JMPREL 23
#define DT_ENCODING 32

typedef struct {
    u8_t  ident[16];    /* The first 4 bytes are the ELF magic */

    u16_t type;         /* == 2, EXEC (executable file) */
    u16_t machine;      /* == 8, MIPS r3000 */
    u32_t version;      /* == 1, default ELF value */
    u32_t entry;        /* program starting point */
    u32_t phoff;        /* program header offset in the file */

    u32_t shoff;        /* section header offset in the file, unused for us, so == 0 */
    u32_t flags;        /* flags, unused for us. */
    u16_t ehsize;       /* this header size ( == 52 ) */
    u16_t phentsize;    /* size of a program header ( == 32 ) */
    u16_t phnum;        /* number of program headers */
    u16_t shentsize;    /* size of a section header, unused here */

    u16_t shnum;        /* number of section headers, unused here */
    u16_t shstrndx;     /* section index of the string table */
} elf_header_t;

typedef struct {
    u32_t type;         /* == 1, PT_LOAD (that is, this section will get loaded */
    u32_t offset;       /* offset in file, on a 4096 bytes boundary */
    u32_t vaddr;        /* virtual address where this section is loaded */
    u32_t paddr;        /* physical address where this section is loaded */
    u32_t filesz;       /* size of that section in the file */
    u32_t memsz;        /* size of that section in memory (rest is zero filled) */
    u32_t flags;        /* PF_X | PF_W | PF_R, that is executable, writable, readable */
    u32_t align;        /* == 0x1000 that is 4096 bytes */
} elf_pheader_t;

typedef struct {
    u32_t name;
    u32_t value;
    u32_t size;
    u8_t info;
    u8_t other;
    u16_t shndx;
} elf_sym_t;

typedef struct {
    u32_t d_tag;
    union {
        u32_t d_val;
        u32_t d_ptr;
    } d_un;
} elf32_dyn_t;

typedef struct {
    u32_t r_offset;
    u32_t r_info;
} elf32_rel_t;


#endif /* __sotool_h__ */