#include <stdio.h>


#define LOGD()

static char* so_content = NULL;

struct so_info {
    u32_t dynamic;

    u32_t symtab;
    u32_t syment;
    u32_t symcnt;

    u32_t strtab;
    u32_t strsz;

    u32_t jmprel;
    u32_t pltrel;
    u32_t relcnt;

    u32_t plt;
    u32_t pltsz;

    u32_t init;

    u32_t init_array;
    u32_t init_array_count;

    u32_t finit_array;
    u32_t finit_array_count;

    u32_t hash;
    u32_t need;
} soinfo;

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
    elf_pheader_t* phtab = header->phoff;
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
        LOGD("zxm:dynamic_vaddr=%x, dynamic_offset=%x\n", dynamic_vaddr, dynamic_offset);
        return;
    }

    u32_t* dynamic = (u32_t*)(so_content + dynamic_offset);

    u32_t dlneeds[64];
    for (int di = 0; di < 64; ++di) {
        dlneeds[di] = 0;
    }
    u32_t dlneeds_count = 0;

    for (u32_t* d = dynamic; *d; d++) {
        switch (*d++) {
            case DT_REL:
                soinfo.  = *d;
                break;
            case DT_RELENT:
                rellent = *d;
                break;
            case DT_RELSZ:
                relsz = *d;
                break;
            case DT_JMPREL:
                soinfo.jmprel = *d;
                break;
            case DT_PLTRELSZ:
                pltrelsz = *d;
                break;
            case DT_STRSZ:
                strsz = *d;
                break;
            case DT_NEEDED:
                dlneeds[dlneeds_count++] = *d;
                break;
        }
    }

}

int main() {
    char* so_path;
  
    load_so(so_path);
    
       
	
}
