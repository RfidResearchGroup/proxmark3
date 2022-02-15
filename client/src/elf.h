//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// ELF header
//-----------------------------------------------------------------------------

#ifndef __ELF_H__
#define __ELF_H__

#include "common.h"

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} PACKED Elf32_Phdr_t;

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
    uint16_t e_shstrndx;
} PACKED Elf32_Ehdr_t;

typedef struct {
    uint32_t sh_name;      // Section name, index in string tbl
    uint32_t sh_type;      // Type of section
    uint32_t sh_flags;     // Miscellaneous section attributes
    uint32_t sh_addr;      // Section virtual addr at execution
    uint32_t sh_offset;    // Section file offset
    uint32_t sh_size;      // Size of section in bytes
    uint32_t sh_link;      // Index of another section
    uint32_t sh_info;      // Additional section information
    uint32_t sh_addralign; // Section alignment
    uint32_t sh_entsize;   // Entry size if section holds table
} PACKED Elf32_Shdr_t;

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

