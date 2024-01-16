/*
 * ht2crack2buildtable.c
 * This builds the 1.2TB table and sorts it.
 */

#include "ht2crackutils.h"
#include <stdlib.h>

// DATAMAX is the size of each bucket (bytes).  There are 65536 buckets so choose a value such that
// DATAMAX * 65536 < RAM available.  For ex, if you want to use 12GB of RAM (for a 16GB machine
// leaving some RAM free for OS and other stuff), DATAMAX = 12GB / 65536 = 196608.  Round this down
// to a power of 10; DATAMAX = 196600.
#define DATAMAX 196600 // around 192K rounded down to a power of 10

// NUM_BUILD_THREADS and NUM_SORT_THREADS are the number of threads to run concurrently.  These should
// ideally be equal to the number of virtual cores you have available.  A quad-core machine will
// likely have 8 virtual cores, so set them to 8.
//
// If sorting fails with a 'bus error' then that is likely because your disk I/O can't keep up with
// the read/write demands of the multi-threaded sorting.  In this case, reduce the number of sorting
// threads.  This will most likely only be a problem with network disks; SATA should be okay;
// USB2/3 should keep up.
//
// These MUST be a power of 2 for the maths to work - you have been warned!
// Also, sort threads MUST be <= build threads or a horrible buffer overflow will happen!
#define NUM_BUILD_THREADS 8
#define NUM_SORT_THREADS 8

// DATASIZE is the number of bytes in an entry.  This is 10; 4 bytes of keystream (2 are in the filepath) +
// 6 bytes of PRNG state.
#define DATASIZE 10

int debug = 0;

// table entry for a bucket
struct table {
    char path[32];
    pthread_mutex_t mutex;
    unsigned char *data;
    unsigned char *ptr;
};


// actual table
struct table *t;

// jump table 1
uint64_t d[48];
int nsteps;

// jump table 2
uint64_t d2[48];
int nsteps2;

// create table entry
static void create_table(struct table *tt, int d_1, int d_2) {
    if (!tt) {
        printf("create_table: t is NULL\n");
        exit(1);
    }

    // create some space
    tt->data = (unsigned char *)calloc(1, DATAMAX);
    if (!(tt->data)) {
        printf("create_table: cannot calloc data\n");
        exit(1);
    }

    // set data ptr to start of data table
    tt->ptr = tt->data;

    // init the mutex
    if (pthread_mutex_init(&(tt->mutex), NULL)) {
        printf("create_table: cannot init mutex\n");
        exit(1);
    }

    // create the path
//    snprintf(tt->path, sizeof(tt->path), "/Volumes/2tb/%02X/%02X.bin", d_1 & 0xff, d_2 & 0xff);
    snprintf(tt->path, sizeof(tt->path), "table/%02x/%02x.bin", d_1 & 0xff, d_2 & 0xff);
}


// create all table entries
static void create_tables(struct table *tt) {
    int i, j;

    if (!tt) {
        printf("create_tables: t is NULL\n");
        exit(1);
    }

    for (i = 0; i < 0x100; i++) {
        for (j = 0; j < 0x100; j++) {
            create_table(tt + ((i * 0x100) + j), i, j);
        }
    }
}


// free the table memory
static void free_tables(struct table *tt) {
    if (!tt) {
        printf("free_tables: tt is NULL\n");
        exit(1);
    }

    for (int i = 0; i < 0x10000; i++) {
        struct table *ttmp = tt + i;
        free(ttmp->data);
    }
}



// write (partial) table to file
static void writetable(struct table *t1) {
    int fd;

    if (debug) printf("writetable %s\n", t1->path);

    fd = open(t1->path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd <= 0) {
        printf("writetable cannot open file %s for appending\n", t1->path);
        exit(1);
    }

    if (debug) printf("writetable %s opened\n", t1->path);

    if (write(fd, t1->data, t1->ptr - t1->data) < (t1->ptr - t1->data)) {
        printf("writetable cannot write all of the data\n");
        exit(1);
    }

    if (debug) printf("writetable %s written\n", t1->path);

    close(fd);
}


// store value in table
static void store(unsigned char *data) {
    unsigned char d_1, d_2;
    int offset;
    struct table *t1;

    // use the first two bytes as an index
    d_1 = data[0];
    d_2 = data[1];
    offset = (d_1 * 0x100) + d_2;

    if (debug) printf("store, d1=%02X, d2=%02X, offset = %d\n", d_1, d_2, offset);

    // get pointer to table entry
    t1 = t + offset;

    // wait for a lock on this entry
    if (pthread_mutex_lock(&(t1->mutex))) {
        printf("store: cannot lock mutex at offset %d\n", offset);
        exit(1);
    }

    if (debug) printf("store, offset = %d, got lock\n", offset);

    // store the entry
    memcpy(t1->ptr, data + 2, 10);

    if (debug) printf("store, offset = %d, copied data\n", offset);

    // update the ptr
    t1->ptr += 10;

    // check if table is full
    if ((t1->ptr - t1->data) >= DATAMAX) {
        // write the table to disk
        writetable(t1);
        // reset ptr
        t1->ptr = t1->data;
    }

    if (debug) printf("store, offset = %d, after possible write\n", offset);

    // release the lock
    if (pthread_mutex_unlock(&(t1->mutex))) {
        printf("store: cannot unlock mutex at offset %d\n", offset);
        exit(1);
    }

    if (debug) printf("store, offset = %d, unlocked\n", offset);

}

// writes the ks (keystream) and s (state)
static void write_ks_s(uint32_t ks1, uint32_t ks2, uint64_t shiftreg) {
    unsigned char buf[16];

    // create buffer
    writebuf(buf, ks1, 3);
    writebuf(buf + 3, ks2, 3);
    writebuf(buf + 6, shiftreg, 6);

    // store buffer
    store(buf);
}


// builds the di table for jumping
static void builddi(int steps, int table) {
    uint64_t statemask;
    int i;
    Hitag_State mystate;
    uint64_t *thisd = NULL;

    statemask = 1;

    // select jump table
    if (table == 1) {
        nsteps = steps;
        thisd = d;
    } else if (table == 2) {
        nsteps2 = steps;
        thisd = d2;
    } else {
        printf("builddi: invalid table num\n");
        exit(1);
    }

    // build di states
    for (i = 0; i < 48; i++) {
        mystate.shiftreg = statemask;
        buildlfsr(&mystate);
        hitag2_nstep(&mystate, steps);
        thisd[i] = mystate.shiftreg;

        statemask = statemask << 1;
    }
}

// jump function - quickly jumps a load of steps
static void jumpnsteps(Hitag_State *hstate, int table) {
    uint64_t output = 0;
    uint64_t bitmask;
    int i;
    uint64_t *thisd = NULL;


    // select jump table
    if (table == 1) {
        thisd = d;
    } else if (table == 2) {
        thisd = d2;
    } else {
        printf("jumpnsteps: invalid table num\n");
        exit(1);
    }

    // xor all di.si where di is a d state and si is a bit
    // we do this by multiplying di by si:
    // if si is 1, di.si = di; if si is 0, di.si = 0

    bitmask = 1;
    for (i = 0; i < 48; i++) {
        if (hstate->shiftreg & bitmask) {
            output = output ^ thisd[i];
        }

        bitmask = bitmask << 1;
    }

    hstate->shiftreg = output;
    buildlfsr(hstate);
}


// thread to build a part of the table
static void *buildtable(void *dd) {
    Hitag_State hstate;
    Hitag_State hstate2;
    unsigned long maxentries = 1;
    int index = (int)(long)dd;
    int tnum = NUM_BUILD_THREADS;

    /* set random state */
    hstate.shiftreg = 0x123456789abc;
    buildlfsr(&hstate);

    /* jump to offset using jump table 2 (2048) */
    for (unsigned long i = 0; i < index; i++) {
        jumpnsteps(&hstate, 2);
    }

    /* set max entries - this is a fraction of 2^37 depending on how many threads we are running.
       1 thread  = 2^37
       2 threads = 2^36
       4 threads = 2^35
       8 threads = 2^34
       etc
    */
    maxentries = maxentries << 37;
    while (!(tnum & 0x1)) {
        maxentries = maxentries >> 1;
        tnum = tnum >> 1;
    }

    /* make the entries */
    for (unsigned long i = 0; i < maxentries; i++) {

        // copy the current state
        hstate2.shiftreg = hstate.shiftreg;
        hstate2.lfsr = hstate.lfsr;

        // get 48 bits of keystream from hstate2
        // this is split into 2 x 24 bit
        uint32_t ks1 = hitag2_nstep(&hstate2, 24);
        uint32_t ks2 = hitag2_nstep(&hstate2, 24);

        write_ks_s(ks1, ks2, hstate.shiftreg);

        // jump hstate forward 2048 * NUM_BUILD_THREADS states using di table
        // this is because we're running NUM_BUILD_THREADS threads at once, from NUM_BUILD_THREADS
        // different offsets that are 2048 states apart.
        jumpnsteps(&hstate, 1);
    }

    return NULL;
}


// make 'table/' (unsorted) and 'sorted/' dir structures
static void makedirs(void) {
    char path[32];
    int i;

    if (mkdir("table", 0755)) {
        printf("cannot make dir table\n");
        exit(1);
    }
    if (mkdir("sorted", 0755)) {
        printf("cannot make dir sorted\n");
        exit(1);
    }

    for (i = 0; i < 0x100; i++) {
        snprintf(path, sizeof(path), "table/%02x", i);
        if (mkdir(path, 0755)) {
            printf("cannot make dir %s\n", path);
            exit(1);
        }
        snprintf(path, sizeof(path), "sorted/%02x", i);
        if (mkdir(path, 0755)) {
            printf("cannot make dir %s\n", path);
            exit(1);
        }
    }
}

static int datacmp(const void *p1, const void *p2, void *dummy) {
    unsigned char *d_1 = (unsigned char *)p1;
    unsigned char *d_2 = (unsigned char *)p2;

    return memcmp(d_1, d_2, DATASIZE);
}

static void *sorttable(void *dd) {
    int i, j;
    int fdin;
    int fdout;
    char infile[64];
    char outfile[64];
    unsigned char *data = NULL;
    struct stat filestat;
    int index = (int)(long)dd;
    int space = 0x100 / NUM_SORT_THREADS;

    // create table - 50MB should be enough
    unsigned char *table = (unsigned char *)calloc(1, 50UL * 1024UL * 1024UL);
    if (!table) {
        printf("sorttable: cannot calloc table\n");
        exit(1);
    }

    // loop over our first byte values
    for (i = (index * space); i < ((index + 1) * space); i++) {
        // loop over all second byte values
        for (j = 0; j < 0x100; j++) {

            printf("sorttable: processing bytes 0x%02x/0x%02x\n", i, j);

            // open file, stat it and mmap it
            snprintf(infile, sizeof(infile), "table/%02x/%02x.bin", i, j);

            fdin = open(infile, O_RDONLY);
            if (fdin <= 0) {
                printf("cannot open file %s\n", infile);
                exit(1);
            }

            if (fstat(fdin, &filestat)) {
                printf("cannot stat file %s\n", infile);
                exit(1);
            }

            data = mmap((caddr_t)0, filestat.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
            if (data == MAP_FAILED) {
                printf("cannot mmap file %s\n", infile);
                exit(1);
            }

            // copy data into table
            memcpy(table, data, filestat.st_size);

            uint64_t numentries = filestat.st_size / DATASIZE;

            // unmap file and close it
            if (munmap(data, filestat.st_size)) {
                printf("cannot munmap %s\n", infile);
                exit(1);
            }

            close(fdin);

            // sort it
            void *dummy = NULL; // clang
            qsort_r(table, numentries, DATASIZE, datacmp, dummy);

            // write to file
            snprintf(outfile, sizeof(outfile), "sorted/%02x/%02x.bin", i, j);
            fdout = open(outfile, O_WRONLY | O_CREAT, 0644);
            if (fdout <= 0) {
                printf("cannot create outfile %s\n", outfile);
                exit(1);
            }
            if (write(fdout, table, numentries * DATASIZE)) {
                printf("writetable cannot write all of the data\n");
                exit(1);
            }
            close(fdout);

            // remove input file
            if (unlink(infile)) {
                printf("cannot remove file %s\n", infile);
                exit(1);
            }
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    pthread_t threads[NUM_BUILD_THREADS];
    void *status;

    // make the table of tables
    t = (struct table *)malloc(sizeof(struct table) * 65536);
    if (!t) {
        printf("malloc failed\n");
        exit(1);
    }

    // init the table
    create_tables(t);

    // create the directories
    makedirs();

    // build the jump table for incremental steps
    builddi(2048 * NUM_BUILD_THREADS, 1);

    // build the jump table for setting the offset
    builddi(2048, 2);

    // start the threads
    for (long i = 0; i < NUM_BUILD_THREADS; i++) {
        int ret = pthread_create(&(threads[i]), NULL, buildtable, (void *)(i));
        if (ret) {
            printf("cannot start buildtable thread %ld\n", i);
            exit(1);
        }
    }

    if (debug) printf("main, started buildtable threads\n");

    // wait for threads to finish
    for (long i = 0; i < NUM_BUILD_THREADS; i++) {
        int ret = pthread_join(threads[i], &status);
        if (ret) {
            printf("cannot join buildtable thread %ld\n", i);
            exit(1);
        }
        printf("buildtable thread %ld finished\n", i);
    }

    // write all remaining files
    for (long i = 0; i < 0x10000; i++) {
        struct table *t1 = t + i;
        if (t1->ptr > t1->data) {
            writetable(t1);
        }
    }

    // dump the memory
    free_tables(t);
    free(t);



    // now for the sorting


    // start the threads
    for (long i = 0; i < NUM_SORT_THREADS; i++) {
        int ret = pthread_create(&(threads[i]), NULL, sorttable, (void *)(i));
        if (ret) {
            printf("cannot start sorttable thread %ld\n", i);
            exit(1);
        }
    }

    if (debug) printf("main, started sorttable threads\n");

    // wait for threads to finish
    for (long i = 0; i < NUM_SORT_THREADS; i++) {
        int ret = pthread_join(threads[i], &status);
        if (ret) {
            printf("cannot join sorttable thread %ld\n", i);
            exit(1);
        }
        printf("sorttable thread %ld finished\n", i);
    }

    pthread_exit(NULL);

    return 0;
}




