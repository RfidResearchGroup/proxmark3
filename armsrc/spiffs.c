//-----------------------------------------------------------------------------
// Colin J. Brigato, 2019 - [colin@brigato.fr]
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// SPIFFS api for RDV40 Integration by Colin Brigato
//-----------------------------------------------------------------------------

#define SPIFFS_CFG_PHYS_SZ (1024 * 128)
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
#define RDV40_SPIFFS_MAX_FD (2)
#define RDV40_SPIFFS_FDBUF_SZ (SPIFFS_FD_SIZE * RDV40_SPIFFS_MAX_FD)

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

///// FLASH LEVEL R/W/E operations  for feeding SPIFFS Driver/////////////////
static s32_t rdv40_spiffs_llread(u32_t addr, u32_t size, u8_t *dst) {

    if (!Flash_ReadData(addr, dst, size)) {
        return 128;
    }
    return SPIFFS_OK;
}

static s32_t rdv40_spiffs_llwrite(u32_t addr, u32_t size, u8_t *src) {

    if (!FlashInit()) {
        return 129;
    }
    Flash_Write(addr, src, size);
    return SPIFFS_OK;
}

static s32_t rdv40_spiffs_llerase(u32_t addr, u32_t size) {

    if (!FlashInit()) {
        return 130;
    }

    uint32_t bytes_erased = 0, bytes_remaining = size;
    while (bytes_remaining > 0) {

        addr += bytes_erased;
        Flash_CheckBusy(BUSY_TIMEOUT);
        Flash_WriteEnable();
        FlashSendByte(SECTORERASE);
        Flash_TransferAdresse(addr);
        FlashSendLastByte(0);

        bytes_remaining -= 4096;
        bytes_erased += 4096;
    }

    Flash_CheckBusy(BUSY_TIMEOUT);
    FlashStop();

    return SPIFFS_OK;
}

////////////////////////////////////////////////////////////////////////////////

////// SPIFFS LOW LEVEL OPERATIONS /////////////////////////////////////////////
static u8_t spiffs_work_buf[RDV40_SPIFFS_WORKBUF_SZ];
static u8_t spiffs_fds[RDV40_SPIFFS_FDBUF_SZ];
static u8_t spiffs_cache_buf[RDV40_SPIFFS_CACHE_SZ];

static spiffs fs;

static enum spiffs_mount_status {
    RDV40_SPIFFS_UNMOUNTED,
    RDV40_SPIFFS_MOUNTED,
    RDV40_SPIFFS_UNKNOWN
} RDV40_SPIFFS_MOUNT_STATUS;

int rdv40_spiffs_mounted() {
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

int rdv40_spiffs_mount() {
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
    int ret = SPIFFS_mount(&fs, &cfg, spiffs_work_buf, spiffs_fds, sizeof(spiffs_fds), spiffs_cache_buf,
                           sizeof(spiffs_cache_buf), 0);
    if (ret == SPIFFS_OK) {
        RDV40_SPIFFS_MOUNT_STATUS = RDV40_SPIFFS_MOUNTED;
    }
    return ret;
}

int rdv40_spiffs_unmount() {
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
////////////////////////////////////////////////////////////////////////////////

///// Base RDV40_SPIFFS_SAFETY_NORMAL operations////////////////////////////////

void write_to_spiffs(const char *filename, uint8_t *src, uint32_t size) {
    spiffs_file fd = SPIFFS_open(&fs, filename, SPIFFS_CREAT | SPIFFS_TRUNC | SPIFFS_RDWR, 0);
    if (SPIFFS_write(&fs, fd, src, size) < 0)
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    SPIFFS_close(&fs, fd);
}

void append_to_spiffs(const char *filename, uint8_t *src, uint32_t size) {
    spiffs_file fd = SPIFFS_open(&fs, filename, SPIFFS_APPEND | SPIFFS_RDWR, 0);
    if (SPIFFS_write(&fs, fd, src, size) < 0)
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    SPIFFS_close(&fs, fd);
}

void read_from_spiffs(const char *filename, uint8_t *dst, uint32_t size) {
    spiffs_file fd = SPIFFS_open(&fs, filename, SPIFFS_RDWR, 0);
    if (SPIFFS_read(&fs, fd, dst, size) < 0)
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    SPIFFS_close(&fs, fd);
}

void rename_in_spiffs(const char *old_filename, const char *new_filename) {
    if (SPIFFS_rename(&fs, old_filename, new_filename) < 0)
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
}

void remove_from_spiffs(const char *filename) {
    if (SPIFFS_remove(&fs, filename) < 0)
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
}

spiffs_stat stat_in_spiffs(const char *filename) {
    spiffs_stat s;
    if (SPIFFS_stat(&fs, filename, &s) < 0)
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    return s;
}

uint32_t size_in_spiffs(const char *filename) {
    spiffs_stat s = stat_in_spiffs(filename);
    return s.size;
}

rdv40_spiffs_fsinfo info_of_spiffs() {
    rdv40_spiffs_fsinfo fsinfo;
    fsinfo.blockSize = SPIFFS_CFG_LOG_BLOCK_SZ;
    fsinfo.pageSize = LOG_PAGE_SIZE;
    fsinfo.maxOpenFiles = RDV40_SPIFFS_MAX_FD;
    fsinfo.maxPathLength = SPIFFS_OBJ_NAME_LEN;
    if (SPIFFS_info(&fs, &fsinfo.totalBytes, &fsinfo.usedBytes) < 0)
        Dbprintf("errno %i\n", SPIFFS_errno(&fs));
    fsinfo.freeBytes = fsinfo.totalBytes - fsinfo.usedBytes;
    // Rounding without float may be improved
    fsinfo.usedPercent = ((100 * fsinfo.usedBytes) + (fsinfo.totalBytes / 2)) / fsinfo.totalBytes;
    fsinfo.freePercent = (100 - fsinfo.usedPercent);
    return fsinfo;
}

int exists_in_spiffs(const char *filename) {
    spiffs_stat stat;
    int rc = SPIFFS_stat(&fs, filename, &stat);
    return rc == SPIFFS_OK;
}

RDV40SpiFFSFileType filetype_in_spiffs(const char *filename) {
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
    if (DBGLEVEL > 1) {
        switch (filetype) {
            case RDV40_SPIFFS_FILETYPE_REAL:
                Dbprintf("Filetype is : RDV40_SPIFFS_FILETYPE_REAL");
                break;
            case RDV40_SPIFFS_FILETYPE_SYMLINK:
                Dbprintf("Filetype is : RDV40_SPIFFS_FILETYPE_SYMLINK");
                break;
            case RDV40_SPIFFS_FILETYPE_BOTH:
                Dbprintf("Filetype is : RDV40_SPIFFS_FILETYPE_BOTH");
                break;
            case RDV40_SPIFFS_FILETYPE_UNKNOWN:
                Dbprintf("Filetype is : RDV40_SPIFFS_FILETYPE_UNKNOWN");
                break;
        }
    }
    return filetype;
}

int is_valid_filename(const char *filename) {
    if (filename == NULL) {
        return false;
    }
    uint32_t len = strlen(filename);
    return len > 0 && len < SPIFFS_OBJ_NAME_LEN;
}

void copy_in_spiffs(const char *src, const char *dst) {
    uint32_t size = size_in_spiffs((char *)src);
    uint8_t *mem = BigBuf_malloc(size);
    read_from_spiffs((char *)src, (uint8_t *)mem, size);
    write_to_spiffs((char *)dst, (uint8_t *)mem, size);
}

////////////////////////////////////////////////////////////////////////////////

////// Abstract Operations for base Safetyness /////////////////////////////////
//
// mount if not already
// As an "hint" to the behavior one should adopt after his or her lazyness
// it will return 0 if the call was a noop, either because it did not need to
// change OR because it wasn't ABLE to change :)
//                1 if the mount status actually changed
// so you know what to do IN CASE you wished to set things "back to previous
// state"
int rdv40_spiffs_lazy_mount() {
    int changed = 0;
    if (!rdv40_spiffs_mounted()) {
        changed = rdv40_spiffs_mount();
        /* if changed = 0 = SPIFFS_OK then all went well then the change
         * actually occured :)*/
        changed = !changed;
    }
    return changed;
}

// unmount if not already
int rdv40_spiffs_lazy_unmount() {
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
changed = rdv40_spiffs_lazy_format(); // this will imply change only if we where
already mounted beforehand, was the case after our reading without further
rollback rdv40_spiffs_lazy_mount_rollback(changed); // so if we were mounted
just get back to this state. If not, just don't.
        [...]
     }
     [...]
}
*/
// Again : This will "toggle" spiffs mount status only if a "change" occured
// (and should be fed by the result of a spiffs_lazy* function) If everything
// went well, it will return SPIFFS_OK if everything went well, and a report
// back the chain a SPI_ERRNO if not.
int rdv40_spiffs_lazy_mount_rollback(int changed) {
    if (!changed)
        return SPIFFS_OK;
    if (rdv40_spiffs_mounted())
        return rdv40_spiffs_unmount();
    return rdv40_spiffs_mount();
}
///////////////////////////////////////////////////////////////////////////////

// High level functions with SatefetyLevel
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

// TODO : this functions are common enought to be unified with a switchcase
// statement or some function taking function parameters
// TODO : forbid writing to a filename which already exists as lnk !
// TODO : forbid writing to a filename.lnk which already exists without lnk !
int rdv40_spiffs_write(char *filename, uint8_t *src, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                                  //
        write_to_spiffs((char *)filename, (uint8_t *)src, size); //
    )
}

int rdv40_spiffs_append(char *filename, uint8_t *src, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                                   //
        append_to_spiffs((char *)filename, (uint8_t *)src, size); //
    )
}

// todo integrate reading symlinks transparently
int rdv40_spiffs_read(char *filename, uint8_t *dst, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                                   //
        read_from_spiffs((char *)filename, (uint8_t *)dst, size); //
    )
}

// TODO : forbid writing to a filename which already exists as lnk !
// TODO : forbid writing to a filename.lnk which already exists without lnk !
int rdv40_spiffs_rename(char *old_filename, char *new_filename, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                                       //
        rename_in_spiffs((char *)old_filename, (char *)new_filename); //
    )
}
int rdv40_spiffs_remove(char *filename, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(               //
        remove_from_spiffs((char *)filename); //
    )
}

int rdv40_spiffs_copy(char *src, char *dst, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                   //
        copy_in_spiffs((char *)src, (char *)dst); //
    )
}

int rdv40_spiffs_stat(char *filename, uint32_t *buf, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                      //
        *buf = size_in_spiffs((char *)filename); //
    )
}

int rdv40_spiffs_getfsinfo(rdv40_spiffs_fsinfo *fsinfo, RDV40SpiFFSSafetyLevel level) {
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
// symlinkk ?")
// ATTENTION : you must NOT provide the whole filename (so please do not include the .lnk extension)
// TODO : integrate in read_function
int rdv40_spiffs_read_as_symlink(char *filename, uint8_t *dst, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                 //
        char linkdest[SPIFFS_OBJ_NAME_LEN];     //
        char linkfilename[SPIFFS_OBJ_NAME_LEN]; //
        sprintf(linkfilename, "%s.lnk", filename);
        if (DBGLEVEL > 1) Dbprintf("Linkk real filename is  destination is : %s", linkfilename);
        read_from_spiffs((char *)linkfilename, (uint8_t *)linkdest, SPIFFS_OBJ_NAME_LEN);
        if (DBGLEVEL > 1) Dbprintf("Symlink destination is : %s", linkdest);
            read_from_spiffs((char *)linkdest, (uint8_t *)dst, size); //
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
//   wich you can then read back with :
//   rdv40_spiffs_read_as_symlink((uint8_t *)"world",(uint8_t *) buffer, orig_file_size, RDV40_SPIFFS_SAFETY_SAFE);
// TODO : FORBID creating a symlink with a basename (before.lnk) which already exists as a file !
int rdv40_spiffs_make_symlink(char *linkdest, char *filename, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                 //
        char linkfilename[SPIFFS_OBJ_NAME_LEN]; //
        sprintf(linkfilename, "%s.lnk", filename);
        write_to_spiffs((char *)linkfilename, (uint8_t *)linkdest, SPIFFS_OBJ_NAME_LEN); //
    )
}

// filename and filename.lnk will both the existence-checked
// if filename exists, read will be used, if filename.lnk exists, read_as_symlink will be used
// Both existence is not handled right now and should not happen or create a default fallback behavior
// Still, this case won't happend when the write(s) functions will check for both symlink and real file
// preexistance, avoiding a link being created if filename exists, or avoiding a file being created if
// symlink exists with same name
int rdv40_spiffs_read_as_filetype(char *filename, uint8_t *dst, uint32_t size, RDV40SpiFFSSafetyLevel level) {
    RDV40_SPIFFS_SAFE_FUNCTION(                                              //
        RDV40SpiFFSFileType filetype = filetype_in_spiffs((char *)filename); //
    switch (filetype) {
    case RDV40_SPIFFS_FILETYPE_REAL:
        rdv40_spiffs_read((char *)filename, (uint8_t *)dst, size, level);
            break;
        case RDV40_SPIFFS_FILETYPE_SYMLINK:
            rdv40_spiffs_read_as_symlink((char *)filename, (uint8_t *)dst, size, level);
            break;
        case RDV40_SPIFFS_FILETYPE_BOTH:
        case RDV40_SPIFFS_FILETYPE_UNKNOWN:
        default:
            ;
    } //
    )
}

// TODO regarding reads/write and symlinks :
// Provide a higher level readFile function which
//   - don't need a size to be provided, getting it from STAT call and using bigbuff malloc
//   - send back the whole readed file as return Result
// Maybe a good think to implement a VFS api here.

////////////////////////////////////////////////////////////////////////////////

///////// MISC HIGH LEVEL FUNCTIONS ////////////////////////////////////////////

void rdv40_spiffs_safe_print_fsinfos() {
    rdv40_spiffs_fsinfo fsinfo;
    rdv40_spiffs_getfsinfo(&fsinfo, RDV40_SPIFFS_SAFETY_SAFE);
    DbpString(_BLUE_("Flash Memory FileSystem Infos (SPIFFS)"));
    Dbprintf("-------------------------------------");
    Dbprintf("* Filesystem Logical Block Size.........%d bytes", fsinfo.blockSize);
    Dbprintf("* Filesystem Logical Page Size..........%d bytes", fsinfo.pageSize);
    Dbprintf("--");
    Dbprintf("* Filesystem Max Open Files.............%d file descriptors", fsinfo.maxOpenFiles);
    Dbprintf("* Filesystem Max Path Length............%d chars", fsinfo.maxPathLength);
    Dbprintf("--");
    Dbprintf("Filesystem\tSize\tUsed\tAvailable\tUse%\tMounted on");
    Dbprintf("spiffs\t%dB\t%dB\t%dB\t\t%d%\t/", fsinfo.totalBytes, fsinfo.usedBytes, fsinfo.freeBytes,
             fsinfo.usedPercent);
}

// this function is safe and WILL rollback since it is only a PRINTING function,
// not a function intended to give any sort of struct to manipulate the FS
// objects
// TODO : Fake the Directory availability by spliting strings , buffering,
// maintaining prefix list sorting, unique_checking, THEN outputing precomputed
// tree Other solutio nwould be to add directory support to SPIFFS, but that we
// dont want, as prefix are way easier and lighter in every aspect.
void rdv40_spiffs_safe_print_tree(uint8_t banner) {

    int changed = rdv40_spiffs_lazy_mount();
    spiffs_DIR d;
    struct spiffs_dirent e;
    struct spiffs_dirent *pe = &e;
    if (banner) {
        DbpString(_BLUE_("Flash Memory FileSystem tree (SPIFFS)"));
        Dbprintf("-------------------------------------");
    }
    SPIFFS_opendir(&fs, "/", &d);
    Dbprintf("    \t         \t/");
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

        Dbprintf("[%04x]\t %ibytes \t|-- %s%s", pe->obj_id, pe->size, pe->name, resolvedlink);
    }
    SPIFFS_closedir(&d);

    rdv40_spiffs_lazy_mount_rollback(changed);
}

void test_spiffs() {
    Dbprintf("---------------------------");
    Dbprintf("Testing SPIFFS operations");
    Dbprintf("---------------------------");
    Dbprintf("(all test are made using lazy safetylevel)");
    Dbprintf("* Mounting filesystem (lazy).......");
    int changed = rdv40_spiffs_lazy_mount();
    Dbprintf("* Printing tree..............");
    rdv40_spiffs_safe_print_tree(false);
    Dbprintf("* Writing 'I love Proxmark' in a testspiffs.txt");
    // Since We lazy_mounted manually before hand, the wrte safety level will
    // just imply noops
    rdv40_spiffs_write((char *)"testspiffs.txt", (uint8_t *)"I love Proxmark", 15, RDV40_SPIFFS_SAFETY_SAFE);
    Dbprintf("* Printing tree again.......");
    rdv40_spiffs_safe_print_tree(false);
    Dbprintf("* Making a symlink to testspiffs.txt");
    rdv40_spiffs_make_symlink((char *)"testspiffs.txt", (char *)"linktotestspiffs.txt", RDV40_SPIFFS_SAFETY_SAFE);
    Dbprintf("* Printing tree again.......");
    rdv40_spiffs_safe_print_tree(false);
    // TODO READBACK, rename,print tree read back, remove, print tree;
    Dbprintf("* Rollbacking The mount status IF things have changed");
    rdv40_spiffs_lazy_mount_rollback(changed);
    Dbprintf("All done");
    return;
}

///////////////////////////////////////////////////////////////////////////////
