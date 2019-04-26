//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ELF header
//-----------------------------------------------------------------------------

#ifndef __ELF_H__
#define __ELF_H__

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} __attribute__((__packed__)) Elf32_Phdr;

#define EI_NIDENT 16

typedef struct {
    unsigned char   e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shtrndx;
} __attribute__((__packed__)) Elf32_Ehdr;

#define PT_NULL      0
#define PT_LOAD      1
#define PT_DYNAMIC   2
#define PT_INTERP    3
#define PT_NOTE      4
#define PT_SHLIB     5
#define PT_PHDR      6

#define ELFCLASS32   1
#define ELFCLASS64   2

#define ELFDATA2LSB  1
#define ELFDATA2MSB  2

#define EV_CURRENT   1

#define ET_NONE      0
#define ET_REL       1
#define ET_EXEC      2
#define ET_DYN       3
#define ET_CORE      4

#define EM_ARM       0x28

#define PF_R         4
#define PF_W         2
#define PF_X         1

#endif

