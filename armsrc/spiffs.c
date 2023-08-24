//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/pellepl/spiffs
// Copyright (c) 2013-2017 Peter Andersson (pelleplutt1976 at gmail.com)
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
// SPIFFS api for RDV40 Integration
//-----------------------------------------------------------------------------

#define SPIFFS_CFG_PHYS_SZ (1024 * 192)
#define SPIFFS_CFG_PHYS_ERASE_SZ (4 * 1024)
#define SPIFFS_CFG_PHYS_ADDR (0)
#define SPIFFS_CFG_LOG_PAGE_SZ (256)
#define SPIFFS_CFG_LOG_BLOCK_SZ (4 * 1024)
#define LOG_PAGE_SIZE 256
#define RDV40_SPIFFS_WORKBUF_SZ (LOG_PAGE_SIZE * 2)
// Experimental : 4 full pages(LOG_PAGE_SIZE + file descript size) of cache for
// Reading and writing if reading cache is stable, writing cache may need more
// testing regarding power loss, page consistency checks, Garbage collector
// Flushing handling... in doubt, use maximal safetylevel as, in most of the
// case, will ensure a flush by rollbacking to previous Unmounted state
#define RDV40_SPIFFS_CACHE_SZ ((LOG_PAGE_SIZE + 32) * 4)
#define SPIFFS_FD_SIZE (32)
#define RDV40_SPIFFS_MAX_FD (3)
#define RDV40_SPIFFS_FDBUF_SZ (SPIFFS_FD_SIZE * RDV40_SPIFFS_MAX_FD)

#define RDV40_LLERASE_BLOCKSIZE (64*1024)

#define RDV40_SPIFFS_LAZY_HEADER                                                                                       \
    int changed = 0;                                                                                                   \
    if ((level == RDV40_SPIFFS_SAFETY_LAZY) || (level == RDV40_SPIFFS_SAFETY_SAFE)) {                                  \
        changed = rdv40_spiffs_lazy_mount();                                                                           \
    }

#define RDV40_SPIFFS_SAFE_FOOTER                                                                                       \
    if (level == RDV40_SPIFFS_SAFETY_SAFE) {                                                                           \
        changed = rdv40_spiffs_lazy_mount_rollback(changed);                                                           \
    }                                                                                                                  \
    return changed;

#define RDV40_SPIFFS_SAFE_FUNCTION(RDV40_SPIFFS_LLFUNCT)                                                               \
    RDV40_SPIFFS_LAZY_HEADER                                                                                           \
    RDV40_SPIFFS_LLFUNCT                                                                                               \
    RDV40_SPIFFS_SAFE_FOOTER

#include "spiffs.h"
#include "BigBuf.h"
#include "dbprint.h"

///// FLASH LEVEL R/W/E operations  for feeding SPIFFS Driver/////////////////
static s32_t rdv40_spiffs_llread(u32_t addr, u32_t size, u8_t *dst) {

    if (!Flash_ReadData(addr, dst, size)) {
        return 128;
    }
    return SPIFFS_OK;
}

static s32_t rdv40_spiffs_llwrite(u32_t addr, u32_t size, u8_t *src) {

    if (FlashInit() == false) {
        return 129;
    }
    Flash_Write(addr, src, size);
    return SPIFFS_OK;
}

static s32_t rdv40_spiffs_llerase(u32_t addr, u32_t size) {
    if (FlashInit() == false) {
        return 130;
    }

    if (g_dbglevel >= DBG_DEBUG) Dbprintf("LLERASEDBG : Orig addr : %d\n", addr);

    uint8_t block, sector = 0;
    block = addr / RDV40_LLERASE_BLOCKSIZE;
    if (block) {
        addr = addr - (block * RDV40_LLERASE_BLOCKSIZE);
    }

    if (g_dbglevel >= DBG_DEBUG) Dbprintf("LLERASEDBG : Result addr : %d\n", addr);

    sector = addr / SPIFFS_CFG_LOG_BLOCK_SZ;
    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();

    if (g_dbglevel >= DBG_DEBUG) Dbprintf("LLERASEDBG : block : %d, sector : %d \n", block, sector);

    uint8_t erased = Flash_Erase4k(block, sector);
    Flash_CheckBusy(BUSY_TIMEOUT);
    FlashStop();

    // iceman:   SPIFFS_OK expands to 0,    erased is bool from Flash_Erase4k,  which returns TRUE if ok.
    // so this return logic looks wrong.
    return (SPIFFS_OK == erased);
}

////////////////////////////////////////////////////////////////////////////////

////// SPIFFS LOW LEVEL OPERATIONS /////////////////////////////////////////////
static u8_t spiffs_work_buf[RDV40_SPIFFS_WORKBUF_SZ] __attribute__((aligned));
static u8_t spiffs_fds[RDV40_SPIFFS_FDBUF_SZ] __attribute__((aligned));
static u8_t spiffs_cache_buf[RDV40_SPIFFS_CACHE_SZ] __attribute__((aligned));

static spiffs fs;

static enum spiffs_mount_status {
    RDV40_SPIFFS_UNMOUNTED,
    RDV40_SPIFFS_MOUNTED,
    RDV40_SPIFFS_UNKNOWN
} RDV40_SPIFFS_MOUNT_STATUS;

static int rdv40_spiffs_mounted(void) {
    int ret = 0;

    switch (RDV40_SPIFFS_MOUNT_STATUS) {
        case RDV40_SPIFFS_MOUNTED:
            ret = 1;
            break;
        case RDV40_SPIFFS_UNMOUNTED:
        case RDV40_SPIFFS_UNKNOWN:
        default:
            ret = 0;
    }

    return ret;
}

int rdv40_spiffs_mount(void) {
    if (rdv40_spiffs_mounted()) {
        Dbprintf("ERR: SPIFFS already mounted !");
        return SPIFFS_ERR_MOUNTED;
    }

    spiffs_config cfg;
    cfg.hal_read_f = rdv40_spiffs_llread;
    cfg.hal_write_f = rdv40_spiffs_llwrite;
    cfg.hal_erase_f = rdv40_spiffs_llerase;

    // uncached version
    // int ret = SPIFFS_mount(&fs, &cfg, spiffs_work_buf, spiffs_fds,
    // sizeof(spiffs_fds), 0, 0, 0); cached version, experimental
    int ret = SPIFFS_mount(
                  &fs,
                  &cfg,
                  spiffs_work_buf,
                  spiffs_fds,
                  sizeof(spiffs_fds),
                  spiffs_cache_buf,
                  sizeof(spiffs_cache_buf),
                  0
              );

    if (ret == SPIFFS_OK) {
        RDV40_SPIFFS_MOUNT_STATUS = RDV40_SPIFFS_MOUNTED;
    }
    return ret;
}

int rdv40_spiffs_unmount(void) {
    if (!rdv40_spiffs_mounted()) {
        Dbprintf("ERR: SPIFFS not mounted !");
        return SPIFFS_ERR_NOT_MOUNTED;
    }

    SPIFFS_clearerr(&fs);
    SPIFFS_unmount(&fs);

    int ret = SPIFFS_errno(&fs);
    if (ret == SPIFFS_OK) {
        RDV40_SPIFFS_MOUNT_STATUS = RDV40_SPIFFS_UNMOUNTED;
    }
    return ret;
}

int rdv40_spiffs_check(void) {
    rdv40_spiffs_lazy_mount();
    SPIFFS_check(&fs);
    SPIFFS_gc_quick(&fs, 0);
    rdv40_spiffs_lazy_unmount();
    rdv40_spiffs_lazy_mount();
    return SPIFFS_gc(&fs, 8192) == SPIFFS_OK;
}
////////////////////////////////////////////////////////////////////////////////

///// Base RDV40_SPIFFS_SAFETY_NORMAL operations////////////////////////////////

void write_to_spiffs(const char *filename, const uint8_t *src, uint32_t size) {
    spiffs_file fd = SPIFFS_open(&fs, filename, SPIFFS_CREAT | SPIFFS_TRUNC | SPIFFS_RDWR, 0);
    // Note: SPIFFS_write() doesn't declare third parameter as const (but should)
    if (SPIFFS_write(&fs, fd, (void *)src, size) < 0) {
        Dbprintf("wr errno %i\n", SPIFFS_errno(&fs));
    }
    SPIFFS_close(&fs, fd);
}

void append_to_spiffs(const char *filename, const uint8_t *src, uint32_t size) {
    spiffs_file fd = SPIFFS_open(&fs, filename, SPIFFS_APPEND | SPIFFS_RDWR, 0);
    // Note: SPIFFS_write() doesn't declare third parameter as const (but should)
    if (SPIFFS_write(&fs, fd, (void *)src, size) < 0) {
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    }
    SPIFFS_close(&fs, fd);
}

void read_from_spiffs(const char *filename, uint8_t *dst, uint32_t size) {
    spiffs_file fd = SPIFFS_open(&fs, filename, SPIFFS_RDWR, 0);
    if (SPIFFS_read(&fs, fd, dst, size) < 0) {
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    }
    SPIFFS_close(&fs, fd);
}

static void rename_in_spiffs(const char *old_filename, const char *new_filename) {
    if (SPIFFS_rename(&fs, old_filename, new_filename) < 0) {
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    }
}

static void remove_from_spiffs(const char *filename) {
    if (SPIFFS_remove(&fs, filename) < 0) {
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    }
}

uint32_t size_in_spiffs(const char *filename) {
    spiffs_stat s;
    if (SPIFFS_stat(&fs, filename, &s) < 0) {
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
        return 0;
    }
    return s.size;
}

static rdv40_spiffs_fsinfo info_of_spiffs(void) {
    rdv40_spiffs_fsinfo fsinfo;
    fsinfo.blockSize = SPIFFS_CFG_LOG_BLOCK_SZ;
    fsinfo.pageSize = LOG_PAGE_SIZE;
    fsinfo.maxOpenFiles = RDV40_SPIFFS_MAX_FD;
    fsinfo.maxPathLength = SPIFFS_OBJ_NAME_LEN;

    if (SPIFFS_info(&fs, &fsinfo.totalBytes, &fsinfo.usedBytes) < 0) {
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    }

    fsinfo.freeBytes = fsinfo.totalBytes - fsinfo.usedBytes;
    // Rounding without float may be improved
    fsinfo.usedPercent = ((100 * fsinfo.usedBytes) + (fsinfo.totalBytes / 2)) / fsinfo.totalBytes;
    fsinfo.freePercent = (100 - fsinfo.usedPercent);
    return fsinfo;
}

int exists_in_spiffs(const char *filename) {
    spiffs_stat stat;
    int rc = SPIFFS_stat(&fs, filename, &stat);
    return (rc == SPIFFS_OK);
}

static RDV40SpiFFSFileType filetype_in_spiffs(const char *filename) {
    RDV40SpiFFSFileType filetype = RDV40_SPIFFS_FILETYPE_UNKNOWN;
    char symlinked[SPIFFS_OBJ_NAME_LEN];
    sprintf(symlinked, "%s.lnk", filename);

    if (exists_in_spiffs(filename)) {
        filetype = RDV40_SPIFFS_FILETYPE_REAL;
    }

    if (exists_in_spiffs(symlinked)) {
        if (filetype != RDV40_SPIFFS_FILETYPE_UNKNOWN) {
            filetype = RDV40_SPIFFS_FILETYPE_BOTH;
        } else {
            filetype = RDV40_SPIFFS_FILETYPE_SYMLINK;
        }
    }

    if (g_dbglevel >= DBG_DEBUG) {
        switch (filetype) {
            case RDV40_SPIFFS_FILETYPE_REAL:
                Dbprintf("Filetype is " _YELLOW_("RDV40_SPIFFS_FILETYPE_REAL"));
                break;
            case RDV40_SPIFFS_FILETYPE_SYMLINK:
                Dbprintf("Filetype is " _YELLOW_("RDV40_SPIFFS_FILETYPE_SYMLINK"));
                break;
            case RDV40_SPIFFS_FILETYPE_BOTH:
                Dbprintf("Filetype is " _YELLOW_("RDV40_SPIFFS_FILETYPE_BOTH"));
                break;
            case RDV40_SPIFFS_FILETYPE_UNKNOWN:
                Dbprintf("Filetype is " _YELLOW_("RDV40_SPIFFS_FILETYPE_UNKNOWN"));
                break;
        }
    }
    return filetype;
}
/*
static int is_valid_filename(const char *filename) {
    if (filename == NULL) {
        return false;
    }
    uint32_t len = strlen(filename);
    return len > 0 && len < SPIFFS_OBJ_NAME_LEN;
}
*/
static void copy_in_spiffs(const char *src, const char *dst) {
    uint32_t size = size_in_spiffs(src);
    uint8_t *mem = BigBuf_malloc(size);
    read_from_spiffs(src, (uint8_t *)mem, size);
    write_to_spiffs(dst, (uint8_t *)mem, size);
}

////////////////////////////////////////////////////////////////////////////////

////// Abstract Operations for base Safetyness /////////////////////////////////
//
// mount if not already
// As an "hint" to the behavior one should adopt after his or her laziness
// it will return 0 if the call was a noop, either because it did not need to
// change OR because it wasn't ABLE to change :)
//                1 if the mount status actually changed
// so you know what to do IN CASE you wished to set things "back to previous
// state"
int rdv40_spiffs_lazy_mount(void) {
    int changed = 0;
    if (!rdv40_spiffs_mounted()) {
        changed = rdv40_spiffs_mount();
        /* if changed = 0 = SPIFFS_OK then all went well then the change
         * actually occurred :)*/
        changed = !changed;
    }
    return changed;
}

// unmount if not already
int rdv40_spiffs_lazy_unmount(void) {
    int changed = 0;
    if (rdv40_spiffs_mounted()) {
        changed = rdv40_spiffs_unmount();
        changed = !changed;
    }
    return changed;
}

// Before further Reading, it is required to have in mind that UNMOUTING is
// important in some ways Because it is the ONLY operation which ensure that
// -> all Caches and writings are flushed to the FS
// -> all FD are properly closed
// -> Every best effort has been done to ensure consistency and integrity of the
// state reputated to be the actual state of the Filesystem.
//---

// This will "toggle" mount status
// on "changement" conditional
// so it is for the former lazy_ mounting function to actually rollback or not
// depending on the result of the previous This is super lazy implementation as
// it is either a toggle to previous state or again a noop as everything was a
// nonevent If you have a function which NEEDS mounting but you want to exit
// this function in the very state mounting was before your intervention all
// things can now be transparent like
/*
void my_lazy_spiffs_act(){
  uint8_t changed = rdv40_spiffs_lazy_mount();
     [..] Do what you have to do with spiffs
  rdv40_spiffs_lazy_rollback(changed)
}
*/
// The exact same goes for needed unmouting with eventual rollback, you just
// have to use lazy_unmount insted of lazy mount This way, you can ensure
// consistency in operation even with complex chain of mounting and unmounting
// Lets's say you are in a function which needs to mount if not already, and in
// the middle of itself calls function which indeed will need to unmount if not
// already. Well you better use safe or wrapped function which are made to
// rollback to previous state, so you can continue right after to do your
// things.
//
//  As an extreme example: let's imagine that we have a function which is made
//  to FORMAT the whole SPIFFS if a SPECIFIC content is written in the 4 first
//  byte of that file. Also in such a case it should quickly create a bunch of
//  skkeleton to get itself back to a known and wanted state. This behavior has
//  to be done at every "manual" (not a lazy or internal event) mounting, just
//  like an action upon boot.
/*
   void my_spiffs_boot(){
     uint8_t resetret[4];
     // this lazy_mount since needed and can also report back the change on
state implied by eventual mount, if needed rdv40_spiffs_lazy_read((const char
*)".SHOULDRESET",(uint8_t *)resetret,4); if( resetret == "YESS" ) { uint8_t
changed = rdv40_spiffs_lazy_format(void); // this will imply change only if we where
already mounted beforehand, was the case after our reading without further
rollback rdv40_spiffs_lazy_mount_rollback(changed); // so if we were mounted
just get back to this state. If not, just don't.
        [...]
     }
     [...]
}
*/
// Again : This will "toggle" spiffs mount status only if a "change" occurred
// (and should be fed by the result of a spiffs_lazy* function) If everything
// went well, it will return SPIFFS_OK if everything went well, and a report
// back the chain a SPI_ERRNO if not.
int rdv40_spiffs_lazy_mount_rollback(int changed) {
    if (!changed) {
        return SPIFFS_OK;
    }

    if (rdv40_spiffs_mounted()) {
        return rdv40_spiffs_unmount();
    }
    return rdv40_spiffs_mount();
}
///////////////////////////////////////////////////////////////////////////////

// High level functions with SafetyLevel
// Beware that different safety level makes different return behavior
//
// RDV40_SPIFFS_SAFETY_NORMAL : will operate withtout further change on mount
// status RDV40_SPIFFS_SAFETY_LAZY : will ensure mount status already being in
// correct state before ops,
//                            will return !false if mount state had to change
// RDV40_SPIFFS_SAFETY_SAFE : will do same as RDV40_SPIFFS_SAFETY_LAZY
//                            will also safely rollback to previous state IF
//                            mount state had to change will return SPIFFS_OK /
//                            0 / false if everything went well

// TODO : this functions are common enough to be unified with a switchcase
// statement or some function taking function parameters
// TODO : forbid writing to a filename which already exists as lnk !
// TODO : forbid writing to a filename.lnk which already exists without lnk !
// Note: Writing in SPIFFS_WRITE_CHUNK_SIZE (8192) byte chucks helps to ensure "free space" has been erased by GC (Garbage collection)
int rdv40_spiffs_write(const char *filename, const uint8_t *src, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(
        uint32_t idx;
    if (size <= SPIFFS_WRITE_CHUNK_SIZE) {
    // write small file
    write_to_spiffs(filename, src, size);
        size = 0;
    } else { //
        // write first SPIFFS_WRITE_CHUNK_SIZE bytes
        // need to write the first chuck of data, then append
        write_to_spiffs(filename, src, SPIFFS_WRITE_CHUNK_SIZE);
    }
    // append remaing SPIFFS_WRITE_CHUNK_SIZE byte chuncks
    for (idx = 1; idx < (size / SPIFFS_WRITE_CHUNK_SIZE);  idx++) {
    append_to_spiffs(filename, &src[SPIFFS_WRITE_CHUNK_SIZE * idx], SPIFFS_WRITE_CHUNK_SIZE);
    }
    // append remaing bytes
    if (((int64_t)size - (SPIFFS_WRITE_CHUNK_SIZE * idx)) > 0) {
    append_to_spiffs(filename, &src[SPIFFS_WRITE_CHUNK_SIZE * idx], size - (SPIFFS_WRITE_CHUNK_SIZE * idx));
    }
    )
}

int rdv40_spiffs_append(const char *filename, const uint8_t *src, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(
        uint32_t idx;
        // Append any SPIFFS_WRITE_CHUNK_SIZE byte chunks
    for (idx = 0; idx < (size / SPIFFS_WRITE_CHUNK_SIZE);  idx++) {
    append_to_spiffs(filename, &src[SPIFFS_WRITE_CHUNK_SIZE * idx], SPIFFS_WRITE_CHUNK_SIZE);
    }
    // Append remain bytes
    if (((int64_t)size - (SPIFFS_WRITE_CHUNK_SIZE * idx)) > 0) {
    append_to_spiffs(filename, &src[SPIFFS_WRITE_CHUNK_SIZE * idx], size - (SPIFFS_WRITE_CHUNK_SIZE * idx));
    }
    )
}

// todo integrate reading symlinks transparently
int rdv40_spiffs_read(const char *filename, uint8_t *dst, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(
        read_from_spiffs(filename, dst, size);
    )
}

// TODO : forbid writing to a filename which already exists as lnk !
// TODO : forbid writing to a filename.lnk which already exists without lnk !
int rdv40_spiffs_rename(const char *old_filename, const char *new_filename, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                                       //
        rename_in_spiffs(old_filename, new_filename); //
    )
}
int rdv40_spiffs_remove(const char *filename, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(               //
        remove_from_spiffs(filename); //
    )
}

int rdv40_spiffs_copy(const char *src_filename, const char *dst_filename, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                   //
        copy_in_spiffs(src_filename, dst_filename); //
    )
}

int rdv40_spiffs_stat(const char *filename, uint32_t *size_in_bytes, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                      //
        *size_in_bytes = size_in_spiffs(filename); //
    )
}

static int rdv40_spiffs_getfsinfo(rdv40_spiffs_fsinfo *fsinfo, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(         //
        *fsinfo = info_of_spiffs(); //
    )
}

// test for symlink from filename
int rdv40_spiffs_is_symlink(const char *s) {
    int ret = 0;

    if (s != NULL) {
        size_t size = strlen(s);

        if (size >= 4 && s[size - 4] == '.' && s[size - 3] == 'l' && s[size - 2] == 'n' && s[size - 1] == 'k') {
            ret = 1;
        }
    }

    return ret;
}

// since FILENAME can't be longer than 32Bytes as of hard configuration, we're
// safe with Such maximum. So the "size" variable is actually the known/intended
// size of DESTINATION file, may it be known (may we provide a "stat from
// symlink ?")
// ATTENTION : you must NOT provide the whole filename (so please do not include the .lnk extension)
// TODO : integrate in read_function
int rdv40_spiffs_read_as_symlink(const char *filename, uint8_t *dst, uint32_t size, RDV40SpiFFSSafetyLevel level) {

    RDV40_SPIFFS_SAFE_FUNCTION(
        char linkdest[SPIFFS_OBJ_NAME_LEN];
        char linkfilename[SPIFFS_OBJ_NAME_LEN];
        sprintf(linkfilename, "%s.lnk", filename);

        if (g_dbglevel >= DBG_DEBUG)
        Dbprintf("Link real filename is " _YELLOW_("%s"), linkfilename);

        read_from_spiffs((char *)linkfilename, (uint8_t *)linkdest, SPIFFS_OBJ_NAME_LEN);

        if (g_dbglevel >= DBG_DEBUG)
            Dbprintf("Symlink destination is " _YELLOW_("%s"), linkdest);

            read_from_spiffs((char *)linkdest, (uint8_t *)dst, size);
        )
        }

// BEWARE ! This function is DESTRUCTIVE as it will UPDATE an existing symlink
// Since it creates a .lnk extension file it may be minor to mistake the order of arguments
// Still please use this function with care.
// Also, remind that it will NOT check if destination filename actually exists
// As a mnenotechnic, think about the "ln" unix command, which order is the same as "cp" unix command
// in regard of arguments orders.
// Eg :
// rdv40_spiffs_make_symlink((uint8_t *)"hello", (uint8_t *)"world", RDV40_SPIFFS_SAFETY_SAFE)
//   will generate a file named "world.lnk" with the path to file "hello" written in
//   which you can then read back with :
//   rdv40_spiffs_read_as_symlink((uint8_t *)"world",(uint8_t *) buffer, orig_file_size, RDV40_SPIFFS_SAFETY_SAFE);
// TODO : FORBID creating a symlink with a basename (before.lnk) which already exists as a file !
int rdv40_spiffs_make_symlink(const char *linkdest, const char *filename, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(
        char linkfilename[SPIFFS_OBJ_NAME_LEN];
        sprintf(linkfilename, "%s.lnk", filename);
        write_to_spiffs(linkfilename, (const uint8_t *)linkdest, SPIFFS_OBJ_NAME_LEN);
    )
}

// filename and filename.lnk will both the existence-checked
// if filename exists, read will be used, if filename.lnk exists, read_as_symlink will be used
// Both existence is not handled right now and should not happen or create a default fallback behavior
// Still, this case won't happen when the write(s) functions will check for both symlink and real file
// preexistence, avoiding a link being created if filename exists, or avoiding a file being created if
// symlink exists with same name
int rdv40_spiffs_read_as_filetype(const char *filename, uint8_t *dst, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(
        RDV40SpiFFSFileType filetype = filetype_in_spiffs((char *)filename);
    switch (filetype) {
    case RDV40_SPIFFS_FILETYPE_REAL:
        rdv40_spiffs_read(filename, dst, size, level);
            break;
        case RDV40_SPIFFS_FILETYPE_SYMLINK:
            rdv40_spiffs_read_as_symlink(filename, dst, size, level);
            break;
        case RDV40_SPIFFS_FILETYPE_BOTH:
        case RDV40_SPIFFS_FILETYPE_UNKNOWN:
        default:
            break;
    }
    )
}

// TODO regarding reads/write and symlinks :
// Provide a higher level readFile function which
//   - don't need a size to be provided, getting it from STAT call and using bigbuff malloc
//   - send back the whole read file as return Result
// Maybe a good think to implement a VFS api here.

////////////////////////////////////////////////////////////////////////////////

///////// MISC HIGH LEVEL FUNCTIONS ////////////////////////////////////////////
#define SPIFFS_BANNER  DbpString(_CYAN_("Flash Memory FileSystem tree (SPIFFS)"));

void rdv40_spiffs_safe_print_fsinfo(void) {
    rdv40_spiffs_fsinfo fsinfo;
    rdv40_spiffs_getfsinfo(&fsinfo, RDV40_SPIFFS_SAFETY_SAFE);

    Dbprintf("  Logical block size... " _YELLOW_("%d")" bytes", fsinfo.blockSize);
    Dbprintf("  Logical page size.... " _YELLOW_("%d")" bytes", fsinfo.pageSize);
    Dbprintf("  Max open files....... " _YELLOW_("%d")" file descriptors", fsinfo.maxOpenFiles);
    Dbprintf("  Max path length...... " _YELLOW_("%d")" chars", fsinfo.maxPathLength);
    DbpString("");
    Dbprintf("  Filesystem    size       used      available    use%    mounted");
    DbpString("------------------------------------------------------------------");
    Dbprintf("  spiffs        %6d B %6d B    %6d B      " _YELLOW_("%2d%")"    /"
             , fsinfo.totalBytes
             , fsinfo.usedBytes
             , fsinfo.freeBytes
             , fsinfo.usedPercent
            );
    DbpString("");
}

// this function is safe and WILL rollback since it is only a PRINTING function,
// not a function intended to give any sort of struct to manipulate the FS
// objects
// TODO : Fake the Directory availability by splitting strings , buffering,
// maintaining prefix list sorting, unique_checking, THEN outputting precomputed
// tree Other solution would be to add directory support to SPIFFS, but that we
// don't want, as prefix are way easier and lighter in every aspect.
void rdv40_spiffs_safe_print_tree(void) {
    int changed = rdv40_spiffs_lazy_mount();
    spiffs_DIR d;
    struct spiffs_dirent e;
    struct spiffs_dirent *pe = &e;

    SPIFFS_opendir(&fs, "/", &d);
    while ((pe = SPIFFS_readdir(&d, pe))) {

        char resolvedlink[11 + SPIFFS_OBJ_NAME_LEN];
        if (rdv40_spiffs_is_symlink((const char *)pe->name)) {
            char linkdest[SPIFFS_OBJ_NAME_LEN];
            read_from_spiffs((char *)pe->name, (uint8_t *)linkdest, SPIFFS_OBJ_NAME_LEN);
            sprintf(resolvedlink, "(.lnk) --> %s", linkdest);
            // Kind of stripping the .lnk extension
            strtok((char *)pe->name, ".");
        } else {
            memset(resolvedlink, 0, sizeof(resolvedlink));
        }

        Dbprintf("[%04x]\t " _YELLOW_("%i") " B |-- %s%s", pe->obj_id, pe->size, pe->name, resolvedlink);
    }
    SPIFFS_closedir(&d);
    rdv40_spiffs_lazy_mount_rollback(changed);
}

void rdv40_spiffs_safe_wipe(void) {

    int changed = rdv40_spiffs_lazy_mount();

    spiffs_DIR d;
    struct spiffs_dirent e;
    struct spiffs_dirent *pe = &e;
    SPIFFS_opendir(&fs, "/", &d);

    while ((pe = SPIFFS_readdir(&d, pe))) {

        if (rdv40_spiffs_is_symlink((const char *)pe->name)) {

            char linkdest[SPIFFS_OBJ_NAME_LEN];
            read_from_spiffs((char *)pe->name, (uint8_t *)linkdest, SPIFFS_OBJ_NAME_LEN);

            remove_from_spiffs(linkdest);
            Dbprintf(".lnk removed %s", pe->name);

            remove_from_spiffs((char *)pe->name);
            Dbprintf("removed %s", linkdest);

        } else {
            remove_from_spiffs((char *)pe->name);
            Dbprintf("removed %s", pe->name);
        }
    }

    SPIFFS_closedir(&d);
    rdv40_spiffs_lazy_mount_rollback(changed);
}

// Selftest function
void test_spiffs(void) {
    Dbprintf("----------------------------------------------");
    Dbprintf("Testing SPIFFS operations");
    Dbprintf("----------------------------------------------");
    Dbprintf("--  all test are made using lazy safetylevel");

    Dbprintf("  Mounting filesystem (lazy).......");
    int changed = rdv40_spiffs_lazy_mount();

    Dbprintf("  Printing tree..............");
    rdv40_spiffs_safe_print_tree();

    Dbprintf("  Writing 'I love Proxmark3 RDV4' in a testspiffs.txt");

    // Since We lazy_mounted manually before hand, the write safety level will
    // just imply noops
    rdv40_spiffs_write((char *)"testspiffs.txt", (uint8_t *)"I love Proxmark3 RDV4", 21, RDV40_SPIFFS_SAFETY_SAFE);

    Dbprintf("  Printing tree again.......");
    rdv40_spiffs_safe_print_tree();

    Dbprintf("  Making a symlink to testspiffs.txt");
    rdv40_spiffs_make_symlink((char *)"testspiffs.txt", (char *)"linktotestspiffs.txt", RDV40_SPIFFS_SAFETY_SAFE);

    Dbprintf("  Printing tree again.......");
    rdv40_spiffs_safe_print_tree();

    // TODO READBACK, rename,print tree read back, remove, print tree;
    Dbprintf("  Rollbacking The mount status IF things have changed");
    rdv40_spiffs_lazy_mount_rollback(changed);

    Dbprintf(_GREEN_("All done"));
    return;
}

///////////////////////////////////////////////////////////////////////////////
