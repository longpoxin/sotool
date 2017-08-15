#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>

#include "sotool.h"


#define PATH_LENGTH 256

#define LOGD printf

static char* so_content = NULL;

typedef struct {
    char so_name[PATH_LENGTH];
    u32_t dynamic;

    u32_t symtab;
    u32_t syment;
    u32_t symcnt;

    u32_t strtab;
    u32_t strsz;

    u32_t rel;
    u32_t rel_count;
    u32_t pltrel;
    u32_t pltrel_count;

    u32_t init;

    u32_t init_array;
    u32_t init_array_count;

    u32_t finit_array;
    u32_t finit_array_count;

    u32_t need;
} soinfo_t;

soinfo_t soinfo;

static void load_so(char* file) {
    FILE* fp = fopen(file, "rb");
     
    if (!fp) {
        LOGD("Can't open file %s!!!\n", file);  
        return;	
    } 

    int size = 0;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    so_content = (char*)malloc(size);
    if (fread(so_content, 1, size, fp) != size) {
        LOGD("Can't read file %s!!!\n", file);  	
    }
    
    fclose(fp); 
}

u32_t vaddr_to_offset(u32_t vaddr, elf_pheader_t* phtab, u32_t phnum) {
    for (int i = 0; i < phnum; ++i) {
        if (phtab[i].type == PT_LOAD && phtab[i].vaddr < vaddr && (phtab[i].vaddr + phtab[i].memsz) > vaddr) {
            return vaddr - phtab[i].vaddr + phtab[i].offset;
        }
    }  

    return 0;
}

void parse_so_info() {
    elf_header_t* header = (elf_header_t*)so_content;
    elf_pheader_t* phtab = (elf_pheader_t*)(header->phoff + so_content);
    u32_t phnum = header->phnum;

    u32_t dynamic_vaddr = 0;
    for (int i = 0; i < phnum; ++i) {
        if (phtab[i].type == PT_DYNAMIC) {
            dynamic_vaddr = phtab[i].vaddr;
            break;
        }
    }

    u32_t dynamic_offset = vaddr_to_offset(dynamic_vaddr, phtab, phnum);
    if (!dynamic_offset) {
        LOGD("[ERROR]:Can't get dynamic_offset, dynamic_vaddr is %x!\n", dynamic_vaddr);
        return;
    }

    elf32_dyn_t* dynamic = (elf32_dyn_t*)(so_content + dynamic_offset);

    u32_t dlneeds[64];
    for (int di = 0; di < 64; ++di) {
        dlneeds[di] = 0;
    }
    u32_t dlneeds_count = 0;

    for (elf32_dyn_t* d = dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_SONAME:
                break;   // symstr has not been parsed.
            case DT_STRTAB:
                soinfo.strtab = d->d_un.d_ptr;
                break;
            case DT_STRSZ:
                soinfo.strsz = d->d_un.d_val;
                break;
            case DT_SYMTAB:
                soinfo.symtab = d->d_un.d_ptr;
                break;
            case DT_REL:
                soinfo.rel  = d->d_un.d_ptr;
                break;
            case DT_RELENT:
                if (d->d_un.d_val != sizeof(elf32_rel_t)) {
                    LOGD("[ERROR]:Invalid DT_RELAENT:%d\n", d->d_un.d_val);
                }
                break;
            case DT_RELSZ:
                soinfo.rel_count = d->d_un.d_val / sizeof(elf32_rel_t);
                break;
            case DT_JMPREL:
                soinfo.pltrel = d->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                soinfo.pltrel_count = d->d_un.d_val / sizeof(elf32_rel_t);
            case DT_PLTREL:
                if (d->d_un.d_val != DT_REL) {
                    LOGD("[ERROR]:Unsupported DT_PLTREL:%d\n", d->d_un.d_val);
                }
                break;
            case DT_INIT:
                soinfo.init = d->d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                soinfo.init_array = d->d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                soinfo.init_array_count = d->d_un.d_val / sizeof(u32_t);
                break;
            case DT_FINI_ARRAY:
                soinfo.finit_array = d->d_un.d_ptr;
                break;
            case DT_FINI_ARRAYSZ:
                soinfo.finit_array_count = d->d_un.d_val / sizeof(u32_t);
                break;
            case DT_NEEDED:
                dlneeds[dlneeds_count++] = d->d_un.d_val;
                break;
        }
    }
}

void print_dynamic_info() {
    LOGD("symtab offset: %x\n", soinfo.symtab);
    LOGD("strtab offset: %x\n", soinfo.strtab);
    LOGD("rel offset: %x, count=%x\n", soinfo.rel, soinfo.rel_count);
    LOGD("pltrel offset: %x, count=%x\n", soinfo.pltrel, soinfo.pltrel_count);
}

void print_rel_info() {
    char* strtab = so_content + soinfo.strtab;
    elf32_sym_t* symtab = (elf32_sym_t*)(so_content + soinfo.symtab);
 
    LOGD("\nall %d rels:\n", soinfo.rel_count);  
    elf32_rel_t* rels = (elf32_rel_t*)(soinfo.rel + so_content);
    for (int i = 0; i < soinfo.rel_count; ++i) {
        u32_t sym_idx = ELF32_R_SYM(rels[i].r_info);
        u32_t type = ELF32_R_TYPE(rels[i].r_info);
        char* name = symtab[sym_idx].name + strtab;
        LOGD("    type=%d, off=%x, name=%s\n", type, rels[i].r_offset, name);
    }  
    LOGD("all %d pltrels\n", soinfo.pltrel_count);  
    rels = (elf32_rel_t*)(soinfo.pltrel + so_content);
    for (int i = 0; i < soinfo.pltrel_count; ++i) {
        u32_t sym_idx = ELF32_R_SYM(rels[i].r_info);
        u32_t type = ELF32_R_TYPE(rels[i].r_info);
        char* name = symtab[sym_idx].name + strtab;
        LOGD("    type=%d, off=%x, name=%s\n", type, rels[i].r_offset, name);
    }   
}

void print_sym_info() {
    char* strtab = so_content + soinfo.strtab;
    elf32_sym_t* symtab = (elf32_sym_t*)(so_content + soinfo.symtab);
    u32_t count = (soinfo.strtab - soinfo.symtab) / sizeof(elf32_sym_t);

    LOGD("\nall %d syms:\n", count);
    for (int i = 0; i < count; ++i) {
        u32_t type = ELF32_ST_TYPE(symtab[i].info);
        char* name = symtab[i].name + strtab;
        u32_t value = symtab[i].value;
        LOGD("    type=%d, value=%x, name=%s\n", type, value, name);
    }
}

struct option long_options[] = {
    {"dynamic",  0, NULL, 'd'},
    {"sym",      1, NULL, 's'},
    {"rel",      1, NULL, 'r'},
    {0,          0, NULL,  0 },
};

int main(int argc, char** argv) {
    char* so_path = argv[1];
    if (argc - optind < 1) {
        LOGD("sotool input\n");
        return 0;
    }

    char dyanmic_flag = 0;
    char rel_flag = 0;
    char sym_flag = 0;
    char c;
    while ((c = getopt_long(argc, argv, "drs", long_options, NULL)) != EOF) {
        switch (c) {
            case 'd':
                dyanmic_flag = 1;
                break;
            case 'r':
                rel_flag = 1;
                break;
            case 's':
                sym_flag = 1;
                break;
            default:
                break;
        }
    }
  
    so_path = argv[optind++];

    load_so(so_path);
    
    parse_so_info();

    if (dyanmic_flag) {
        print_dynamic_info();
    }
    
    if (rel_flag) {
        print_rel_info();
    }

    if (sym_flag) {
        print_sym_info();
    }
}
