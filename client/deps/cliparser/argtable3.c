/*******************************************************************************
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#define ARG_AMALGAMATION

/*******************************************************************************
 * argtable3_private: Declares private types, constants, and interfaces
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 2013-2019 Tom G. Huang
 * <tomghuang@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#ifndef ARG_UTILS_H
#define ARG_UTILS_H

#include <stdlib.h>

#define ARG_ENABLE_TRACE 0
#define ARG_ENABLE_LOG 1

#ifdef __cplusplus
extern "C" {
#endif

enum { ARG_ERR_MINCOUNT = 1, ARG_ERR_MAXCOUNT, ARG_ERR_BADINT, ARG_ERR_OVERFLOW, ARG_ERR_BADDOUBLE, ARG_ERR_BADDATE, ARG_ERR_REGNOMATCH };

typedef void(arg_panicfn)(const char* fmt, ...);

#if defined(_MSC_VER)
#define ARG_TRACE(x)                                               \
    __pragma(warning(push)) __pragma(warning(disable : 4127)) do { \
        if (ARG_ENABLE_TRACE)                                      \
            dbg_printf x;                                          \
    }                                                              \
    while (0)                                                      \
    __pragma(warning(pop))

#define ARG_LOG(x)                                                 \
    __pragma(warning(push)) __pragma(warning(disable : 4127)) do { \
        if (ARG_ENABLE_LOG)                                        \
            dbg_printf x;                                          \
    }                                                              \
    while (0)                                                      \
    __pragma(warning(pop))
#else
#define ARG_TRACE(x)          \
    do {                      \
        if (ARG_ENABLE_TRACE) \
            dbg_printf x;     \
    } while (0)

#define ARG_LOG(x)          \
    do {                    \
        if (ARG_ENABLE_LOG) \
            dbg_printf x;   \
    } while (0)
#endif

extern void dbg_printf(const char* fmt, ...);
extern void arg_set_panic(arg_panicfn* proc);
extern void* xmalloc(size_t size);
extern void* xcalloc(size_t count, size_t size);
extern void* xrealloc(void* ptr, size_t size);
extern void xfree(void* ptr);

struct arg_hashtable_entry {
    void *k, *v;
    unsigned int h;
    struct arg_hashtable_entry* next;
};

typedef struct arg_hashtable {
    unsigned int tablelength;
    struct arg_hashtable_entry** table;
    unsigned int entrycount;
    unsigned int loadlimit;
    unsigned int primeindex;
    unsigned int (*hashfn)(const void* k);
    int (*eqfn)(const void* k1, const void* k2);
} arg_hashtable_t;

/**
 * @brief Create a hash table.
 *
 * @param   minsize   minimum initial size of hash table
 * @param   hashfn    function for hashing keys
 * @param   eqfn      function for determining key equality
 * @return            newly created hash table or NULL on failure
 */
arg_hashtable_t* arg_hashtable_create(unsigned int minsize, unsigned int (*hashfn)(const void*), int (*eqfn)(const void*, const void*));

/**
 * @brief This function will cause the table to expand if the insertion would take
 * the ratio of entries to table size over the maximum load factor.
 *
 * This function does not check for repeated insertions with a duplicate key.
 * The value returned when using a duplicate key is undefined -- when
 * the hash table changes size, the order of retrieval of duplicate key
 * entries is reversed.
 * If in doubt, remove before insert.
 *
 * @param   h   the hash table to insert into
 * @param   k   the key - hash table claims ownership and will free on removal
 * @param   v   the value - does not claim ownership
 * @return      non-zero for successful insertion
 */
void arg_hashtable_insert(arg_hashtable_t* h, void* k, void* v);

#define ARG_DEFINE_HASHTABLE_INSERT(fnname, keytype, valuetype) \
    int fnname(arg_hashtable_t* h, keytype* k, valuetype* v) { return arg_hashtable_insert(h, k, v); }

/**
 * @brief Search the specified key in the hash table.
 *
 * @param   h   the hash table to search
 * @param   k   the key to search for  - does not claim ownership
 * @return      the value associated with the key, or NULL if none found
 */
void* arg_hashtable_search(arg_hashtable_t* h, const void* k);

#define ARG_DEFINE_HASHTABLE_SEARCH(fnname, keytype, valuetype) \
    valuetype* fnname(arg_hashtable_t* h, keytype* k) { return (valuetype*)(arg_hashtable_search(h, k)); }

/**
 * @brief Remove the specified key from the hash table.
 *
 * @param   h   the hash table to remove the item from
 * @param   k   the key to search for  - does not claim ownership
 */
void arg_hashtable_remove(arg_hashtable_t* h, const void* k);

#define ARG_DEFINE_HASHTABLE_REMOVE(fnname, keytype, valuetype) \
    valuetype* fnname(arg_hashtable_t* h, keytype* k) { return (valuetype*)(arg_hashtable_remove(h, k)); }

/**
 * @brief Return the number of keys in the hash table.
 *
 * @param   h   the hash table
 * @return      the number of items stored in the hash table
 */
unsigned int arg_hashtable_count(arg_hashtable_t* h);

/**
 * @brief Change the value associated with the key.
 *
 * function to change the value associated with a key, where there already
 * exists a value bound to the key in the hash table.
 * Source due to Holger Schemel.
 *
 * @name        hashtable_change
 * @param   h   the hash table
 * @param       key
 * @param       value
 */
int arg_hashtable_change(arg_hashtable_t* h, void* k, void* v);

/**
 * @brief Free the hash table and the memory allocated for each key-value pair.
 *
 * @param   h            the hash table
 * @param   free_values  whether to call 'free' on the remaining values
 */
void arg_hashtable_destroy(arg_hashtable_t* h, int free_values);

typedef struct arg_hashtable_itr {
    arg_hashtable_t* h;
    struct arg_hashtable_entry* e;
    struct arg_hashtable_entry* parent;
    unsigned int index;
} arg_hashtable_itr_t;

arg_hashtable_itr_t* arg_hashtable_itr_create(arg_hashtable_t* h);

void arg_hashtable_itr_destroy(arg_hashtable_itr_t* itr);

/**
 * @brief Return the value of the (key,value) pair at the current position.
 */
extern void* arg_hashtable_itr_key(arg_hashtable_itr_t* i);

/**
 * @brief Return the value of the (key,value) pair at the current position.
 */
extern void* arg_hashtable_itr_value(arg_hashtable_itr_t* i);

/**
 * @brief Advance the iterator to the next element. Returns zero if advanced to end of table.
 */
int arg_hashtable_itr_advance(arg_hashtable_itr_t* itr);

/**
 * @brief Remove current element and advance the iterator to the next element.
 */
int arg_hashtable_itr_remove(arg_hashtable_itr_t* itr);

/**
 * @brief Search and overwrite the supplied iterator, to point to the entry matching the supplied key.
 *
 * @return  Zero if not found.
 */
int arg_hashtable_itr_search(arg_hashtable_itr_t* itr, arg_hashtable_t* h, void* k);

#define ARG_DEFINE_HASHTABLE_ITERATOR_SEARCH(fnname, keytype) \
    int fnname(arg_hashtable_itr_t* i, arg_hashtable_t* h, keytype* k) { return (arg_hashtable_iterator_search(i, h, k)); }

#ifdef __cplusplus
}
#endif

#endif
/*******************************************************************************
 * arg_utils: Implements memory, panic, and other utility functions
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 2013-2019 Tom G. Huang
 * <tomghuang@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void panic(const char* fmt, ...);
static arg_panicfn* s_panic = panic;

void dbg_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static void panic(const char* fmt, ...) {
    va_list args;
    char* s;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    s = getenv("EF_DUMPCORE");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

    if (s != NULL && *s != '\0') {
        abort();
    } else {
        exit(EXIT_FAILURE);
    }
}

void arg_set_panic(arg_panicfn* proc) {
    s_panic = proc;
}

void* xmalloc(size_t size) {
    void* ret = malloc(size);
    if (!ret) {
        s_panic("Out of memory!\n");
    }
    return ret;
}

void* xcalloc(size_t count, size_t size) {
    size_t allocated_count = count && size ? count : 1;
    size_t allocated_size = count && size ? size : 1;
    void* ret = calloc(allocated_count, allocated_size);
    if (!ret) {
        s_panic("Out of memory!\n");
    }
    return ret;
}

void* xrealloc(void* ptr, size_t size) {
    size_t allocated_size = size ? size : 1;
    void* ret = realloc(ptr, allocated_size);
    if (!ret) {
        s_panic("Out of memory!\n");
    }
    return ret;
}

void xfree(void* ptr) {
    free(ptr);
}

static void merge(void* data, int esize, int i, int j, int k, arg_comparefn* comparefn) {
    char* a = (char*)data;
    char* m;
    int ipos, jpos, mpos;

    /* Initialize the counters used in merging. */
    ipos = i;
    jpos = j + 1;
    mpos = 0;

    /* Allocate storage for the merged elements. */
    m = (char*)xmalloc(esize * ((k - i) + 1));

    /* Continue while either division has elements to merge. */
    while (ipos <= j || jpos <= k) {
        if (ipos > j) {
            /* The left division has no more elements to merge. */
            while (jpos <= k) {
                memcpy(&m[mpos * esize], &a[jpos * esize], esize);
                jpos++;
                mpos++;
            }

            continue;
        } else if (jpos > k) {
            /* The right division has no more elements to merge. */
            while (ipos <= j) {
                memcpy(&m[mpos * esize], &a[ipos * esize], esize);
                ipos++;
                mpos++;
            }

            continue;
        }

        /* Append the next ordered element to the merged elements. */
        if (comparefn(&a[ipos * esize], &a[jpos * esize]) < 0) {
            memcpy(&m[mpos * esize], &a[ipos * esize], esize);
            ipos++;
            mpos++;
        } else {
            memcpy(&m[mpos * esize], &a[jpos * esize], esize);
            jpos++;
            mpos++;
        }
    }

    /* Prepare to pass back the merged data. */
    memcpy(&a[i * esize], m, esize * ((k - i) + 1));
    xfree(m);
}

void arg_mgsort(void* data, int size, int esize, int i, int k, arg_comparefn* comparefn) {
    int j;

    /* Stop the recursion when no more divisions can be made. */
    if (i < k) {
        /* Determine where to divide the elements. */
        j = (int)(((i + k - 1)) / 2);

        /* Recursively sort the two divisions. */
        arg_mgsort(data, size, esize, i, j, comparefn);
        arg_mgsort(data, size, esize, j + 1, k, comparefn);
        merge(data, esize, i, j, k, comparefn);
    }
}
/*******************************************************************************
 * arg_hashtable: Implements the hash table utilities
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 2013-2019 Tom G. Huang
 * <tomghuang@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * This hash table module is adapted from the C hash table implementation by
 * Christopher Clark. Here is the copyright notice from the library:
 *
 * Copyright (c) 2002, Christopher Clark
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of the original author; nor the names of any contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Credit for primes table: Aaron Krowne
 * http://br.endernet.org/~akrowne/
 * http://planetmath.org/encyclopedia/GoodHashTablePrimes.html
 */
static const unsigned int primes[] = {53,       97,       193,      389,       769,       1543,      3079,      6151,      12289,
                                      24593,    49157,    98317,    196613,    393241,    786433,    1572869,   3145739,   6291469,
                                      12582917, 25165843, 50331653, 100663319, 201326611, 402653189, 805306457, 1610612741};
const unsigned int prime_table_length = sizeof(primes) / sizeof(primes[0]);
const float max_load_factor = (float)0.65;

static unsigned int enhanced_hash(arg_hashtable_t* h, const void* k) {
    /*
     * Aim to protect against poor hash functions by adding logic here.
     * The logic is taken from Java 1.4 hash table source.
     */
    unsigned int i = h->hashfn(k);
    i += ~(i << 9);
    i ^= ((i >> 14) | (i << 18)); /* >>> */
    i += (i << 4);
    i ^= ((i >> 10) | (i << 22)); /* >>> */
    return i;
}

static unsigned int index_for(unsigned int tablelength, unsigned int hashvalue) {
    return (hashvalue % tablelength);
}

arg_hashtable_t* arg_hashtable_create(unsigned int minsize, unsigned int (*hashfn)(const void*), int (*eqfn)(const void*, const void*)) {
    arg_hashtable_t* h;
    unsigned int pindex;
    unsigned int size = primes[0];

    /* Check requested hash table isn't too large */
    if (minsize > (1u << 30))
        return NULL;

    /*
     * Enforce size as prime. The reason is to avoid clustering of values
     * into a small number of buckets (yes, distribution). A more even
     *  distributed hash table will perform more consistently.
     */
    for (pindex = 0; pindex < prime_table_length; pindex++) {
        if (primes[pindex] > minsize) {
            size = primes[pindex];
            break;
        }
    }

    h = (arg_hashtable_t*)xmalloc(sizeof(arg_hashtable_t));
    h->table = (struct arg_hashtable_entry**)xmalloc(sizeof(struct arg_hashtable_entry*) * size);
    memset(h->table, 0, size * sizeof(struct arg_hashtable_entry*));
    h->tablelength = size;
    h->primeindex = pindex;
    h->entrycount = 0;
    h->hashfn = hashfn;
    h->eqfn = eqfn;
    h->loadlimit = (unsigned int)ceil(size * max_load_factor);
    return h;
}

static int arg_hashtable_expand(arg_hashtable_t* h) {
    /* Double the size of the table to accommodate more entries */
    struct arg_hashtable_entry** newtable;
    struct arg_hashtable_entry* e;
    unsigned int newsize;
    unsigned int i;
    unsigned int index;

    /* Check we're not hitting max capacity */
    if (h->primeindex == (prime_table_length - 1))
        return 0;
    newsize = primes[++(h->primeindex)];

    newtable = (struct arg_hashtable_entry**)xmalloc(sizeof(struct arg_hashtable_entry*) * newsize);
    memset(newtable, 0, newsize * sizeof(struct arg_hashtable_entry*));
    /*
     * This algorithm is not 'stable': it reverses the list
     * when it transfers entries between the tables
     */
    for (i = 0; i < h->tablelength; i++) {
        while (NULL != (e = h->table[i])) {
            h->table[i] = e->next;
            index = index_for(newsize, e->h);
            e->next = newtable[index];
            newtable[index] = e;
        }
    }

    xfree(h->table);
    h->table = newtable;
    h->tablelength = newsize;
    h->loadlimit = (unsigned int)ceil(newsize * max_load_factor);
    return -1;
}

unsigned int arg_hashtable_count(arg_hashtable_t* h) {
    return h->entrycount;
}

void arg_hashtable_insert(arg_hashtable_t* h, void* k, void* v) {
    /* This method allows duplicate keys - but they shouldn't be used */
    unsigned int index;
    struct arg_hashtable_entry* e;
    if ((h->entrycount + 1) > h->loadlimit) {
        /*
         * Ignore the return value. If expand fails, we should
         * still try cramming just this value into the existing table
         * -- we may not have memory for a larger table, but one more
         * element may be ok. Next time we insert, we'll try expanding again.
         */
        arg_hashtable_expand(h);
    }
    e = (struct arg_hashtable_entry*)xmalloc(sizeof(struct arg_hashtable_entry));
    e->h = enhanced_hash(h, k);
    index = index_for(h->tablelength, e->h);
    e->k = k;
    e->v = v;
    e->next = h->table[index];
    h->table[index] = e;
    h->entrycount++;
}

void* arg_hashtable_search(arg_hashtable_t* h, const void* k) {
    struct arg_hashtable_entry* e;
    unsigned int hashvalue;
    unsigned int index;

    hashvalue = enhanced_hash(h, k);
    index = index_for(h->tablelength, hashvalue);
    e = h->table[index];
    while (e != NULL) {
        /* Check hash value to short circuit heavier comparison */
        if ((hashvalue == e->h) && (h->eqfn(k, e->k)))
            return e->v;
        e = e->next;
    }
    return NULL;
}

void arg_hashtable_remove(arg_hashtable_t* h, const void* k) {
    /*
     * TODO: consider compacting the table when the load factor drops enough,
     *       or provide a 'compact' method.
     */

    struct arg_hashtable_entry* e;
    struct arg_hashtable_entry** pE;
    unsigned int hashvalue;
    unsigned int index;

    hashvalue = enhanced_hash(h, k);
    index = index_for(h->tablelength, hashvalue);
    pE = &(h->table[index]);
    e = *pE;
    while (NULL != e) {
        /* Check hash value to short circuit heavier comparison */
        if ((hashvalue == e->h) && (h->eqfn(k, e->k))) {
            *pE = e->next;
            h->entrycount--;
            xfree(e->k);
            xfree(e->v);
            xfree(e);
            return;
        }
        pE = &(e->next);
        e = e->next;
    }
}

void arg_hashtable_destroy(arg_hashtable_t* h, int free_values) {
    unsigned int i;
    struct arg_hashtable_entry *e, *f;
    struct arg_hashtable_entry** table = h->table;
    if (free_values) {
        for (i = 0; i < h->tablelength; i++) {
            e = table[i];
            while (NULL != e) {
                f = e;
                e = e->next;
                xfree(f->k);
                xfree(f->v);
                xfree(f);
            }
        }
    } else {
        for (i = 0; i < h->tablelength; i++) {
            e = table[i];
            while (NULL != e) {
                f = e;
                e = e->next;
                xfree(f->k);
                xfree(f);
            }
        }
    }
    xfree(h->table);
    xfree(h);
}

arg_hashtable_itr_t* arg_hashtable_itr_create(arg_hashtable_t* h) {
    unsigned int i;
    unsigned int tablelength;

    arg_hashtable_itr_t* itr = (arg_hashtable_itr_t*)xmalloc(sizeof(arg_hashtable_itr_t));
    itr->h = h;
    itr->e = NULL;
    itr->parent = NULL;
    tablelength = h->tablelength;
    itr->index = tablelength;
    if (0 == h->entrycount)
        return itr;

    for (i = 0; i < tablelength; i++) {
        if (h->table[i] != NULL) {
            itr->e = h->table[i];
            itr->index = i;
            break;
        }
    }
    return itr;
}

void arg_hashtable_itr_destroy(arg_hashtable_itr_t* itr) {
    xfree(itr);
}

void* arg_hashtable_itr_key(arg_hashtable_itr_t* i) {
    return i->e->k;
}

void* arg_hashtable_itr_value(arg_hashtable_itr_t* i) {
    return i->e->v;
}

int arg_hashtable_itr_advance(arg_hashtable_itr_t* itr) {
    unsigned int j;
    unsigned int tablelength;
    struct arg_hashtable_entry** table;
    struct arg_hashtable_entry* next;

    if (itr->e == NULL)
        return 0; /* stupidity check */

    next = itr->e->next;
    if (NULL != next) {
        itr->parent = itr->e;
        itr->e = next;
        return -1;
    }

    tablelength = itr->h->tablelength;
    itr->parent = NULL;
    if (tablelength <= (j = ++(itr->index))) {
        itr->e = NULL;
        return 0;
    }

    table = itr->h->table;
    while (NULL == (next = table[j])) {
        if (++j >= tablelength) {
            itr->index = tablelength;
            itr->e = NULL;
            return 0;
        }
    }

    itr->index = j;
    itr->e = next;
    return -1;
}

int arg_hashtable_itr_remove(arg_hashtable_itr_t* itr) {
    struct arg_hashtable_entry* remember_e;
    struct arg_hashtable_entry* remember_parent;
    int ret;

    /* Do the removal */
    if ((itr->parent) == NULL) {
        /* element is head of a chain */
        itr->h->table[itr->index] = itr->e->next;
    } else {
        /* element is mid-chain */
        itr->parent->next = itr->e->next;
    }
    /* itr->e is now outside the hashtable */
    remember_e = itr->e;
    itr->h->entrycount--;
    xfree(remember_e->k);
    xfree(remember_e->v);

    /* Advance the iterator, correcting the parent */
    remember_parent = itr->parent;
    ret = arg_hashtable_itr_advance(itr);
    if (itr->parent == remember_e) {
        itr->parent = remember_parent;
    }
    xfree(remember_e);
    return ret;
}

int arg_hashtable_itr_search(arg_hashtable_itr_t* itr, arg_hashtable_t* h, void* k) {
    struct arg_hashtable_entry* e;
    struct arg_hashtable_entry* parent;
    unsigned int hashvalue;
    unsigned int index;

    hashvalue = enhanced_hash(h, k);
    index = index_for(h->tablelength, hashvalue);

    e = h->table[index];
    parent = NULL;
    while (e != NULL) {
        /* Check hash value to short circuit heavier comparison */
        if ((hashvalue == e->h) && (h->eqfn(k, e->k))) {
            itr->index = index;
            itr->e = e;
            itr->parent = parent;
            itr->h = h;
            return -1;
        }
        parent = e;
        e = e->next;
    }
    return 0;
}

int arg_hashtable_change(arg_hashtable_t* h, void* k, void* v) {
    struct arg_hashtable_entry* e;
    unsigned int hashvalue;
    unsigned int index;

    hashvalue = enhanced_hash(h, k);
    index = index_for(h->tablelength, hashvalue);
    e = h->table[index];
    while (e != NULL) {
        /* Check hash value to short circuit heavier comparison */
        if ((hashvalue == e->h) && (h->eqfn(k, e->k))) {
            xfree(e->v);
            e->v = v;
            return -1;
        }
        e = e->next;
    }
    return 0;
}
/*******************************************************************************
 * arg_dstr: Implements the dynamic string utilities
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 2013-2019 Tom G. Huang
 * <tomghuang@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif

#define START_VSNBUFF 16

/*
 * This dynamic string module is adapted from TclResult.c in the Tcl library.
 * Here is the copyright notice from the library:
 *
 * This software is copyrighted by the Regents of the University of
 * California, Sun Microsystems, Inc., Scriptics Corporation, ActiveState
 * Corporation and other parties.  The following terms apply to all files
 * associated with the software unless explicitly disclaimed in
 * individual files.
 *
 * The authors hereby grant permission to use, copy, modify, distribute,
 * and license this software and its documentation for any purpose, provided
 * that existing copyright notices are retained in all copies and that this
 * notice is included verbatim in any distributions. No written agreement,
 * license, or royalty fee is required for any of the authorized uses.
 * Modifications to this software may be copyrighted by their authors
 * and need not follow the licensing terms described here, provided that
 * the new terms are clearly indicated on the first page of each file where
 * they apply.
 *
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY
 * DERIVATIVES THEREOF, EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.  THIS SOFTWARE
 * IS PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE
 * NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * GOVERNMENT USE: If you are acquiring this software on behalf of the
 * U.S. government, the Government shall have only "Restricted Rights"
 * in the software and related documentation as defined in the Federal
 * Acquisition Regulations (FARs) in Clause 52.227.19 (c) (2).  If you
 * are acquiring the software on behalf of the Department of Defense, the
 * software shall be classified as "Commercial Computer Software" and the
 * Government shall have only "Restricted Rights" as defined in Clause
 * 252.227-7014 (b) (3) of DFARs.  Notwithstanding the foregoing, the
 * authors grant the U.S. Government and others acting in its behalf
 * permission to use and distribute the software in accordance with the
 * terms specified in this license.
 */

typedef struct _internal_arg_dstr {
    char* data;
    arg_dstr_freefn* free_proc;
    char sbuf[ARG_DSTR_SIZE + 1];
    char* append_data;
    int append_data_size;
    int append_used;
} _internal_arg_dstr_t;

static void setup_append_buf(arg_dstr_t res, int newSpace);

arg_dstr_t arg_dstr_create(void) {
    _internal_arg_dstr_t* h = (_internal_arg_dstr_t*)xmalloc(sizeof(_internal_arg_dstr_t));
    memset(h, 0, sizeof(_internal_arg_dstr_t));
    h->sbuf[0] = 0;
    h->data = h->sbuf;
    h->free_proc = ARG_DSTR_STATIC;
    return h;
}

void arg_dstr_destroy(arg_dstr_t ds) {
    if (ds == NULL)
        return;

    arg_dstr_reset(ds);
    xfree(ds);
    return;
}

void arg_dstr_set(arg_dstr_t ds, char* str, arg_dstr_freefn* free_proc) {
    int length;
    register arg_dstr_freefn* old_free_proc = ds->free_proc;
    char* old_result = ds->data;

    if (str == NULL) {
        ds->sbuf[0] = 0;
        ds->data = ds->sbuf;
        ds->free_proc = ARG_DSTR_STATIC;
    } else if (free_proc == ARG_DSTR_VOLATILE) {
        length = (int)strlen(str);
        if (length > ARG_DSTR_SIZE) {
            ds->data = (char*)xmalloc((unsigned)length + 1);
            ds->free_proc = ARG_DSTR_DYNAMIC;
        } else {
            ds->data = ds->sbuf;
            ds->free_proc = ARG_DSTR_STATIC;
        }
        strcpy(ds->data, str);
    } else {
        ds->data = str;
        ds->free_proc = free_proc;
    }

    /*
     * If the old result was dynamically-allocated, free it up. Do it here,
     * rather than at the beginning, in case the new result value was part of
     * the old result value.
     */

    if ((old_free_proc != 0) && (old_result != ds->data)) {
        if (old_free_proc == ARG_DSTR_DYNAMIC) {
            xfree(old_result);
        } else {
            (*old_free_proc)(old_result);
        }
    }

    if ((ds->append_data != NULL) && (ds->append_data_size > 0)) {
        xfree(ds->append_data);
        ds->append_data = NULL;
        ds->append_data_size = 0;
    }
}

char* arg_dstr_cstr(arg_dstr_t ds) /* Interpreter whose result to return. */
{
    return ds->data;
}

void arg_dstr_cat(arg_dstr_t ds, const char* str) {
    setup_append_buf(ds, (int)strlen(str) + 1);
    memcpy(ds->data + strlen(ds->data), str, strlen(str));
}

void arg_dstr_catc(arg_dstr_t ds, char c) {
    setup_append_buf(ds, 2);
    memcpy(ds->data + strlen(ds->data), &c, 1);
}

/*
 * The logic of the `arg_dstr_catf` function is adapted from the `bformat`
 * function in The Better String Library by Paul Hsieh. Here is the copyright
 * notice from the library:
 *
 * Copyright (c) 2014, Paul Hsieh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of bstrlib nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
void arg_dstr_catf(arg_dstr_t ds, const char* fmt, ...) {
    va_list arglist;
    char* buff;
    int n, r;
    size_t slen;

    if (fmt == NULL)
        return;

    /* Since the length is not determinable beforehand, a search is
       performed using the truncating "vsnprintf" call (to avoid buffer
       overflows) on increasing potential sizes for the output result. */

    if ((n = (int)(2 * strlen(fmt))) < START_VSNBUFF)
        n = START_VSNBUFF;

    buff = (char*)xmalloc(n + 2);
    memset(buff, 0, n + 2);

    for (;;) {
        va_start(arglist, fmt);
        r = vsnprintf(buff, n + 1, fmt, arglist);
        va_end(arglist);

        slen = strlen(buff);
        if (slen < (size_t)n)
            break;

        if (r > n)
            n = r;
        else
            n += n;

        xfree(buff);
        buff = (char*)xmalloc(n + 2);
        memset(buff, 0, n + 2);
    }

    arg_dstr_cat(ds, buff);
    xfree(buff);
}

static void setup_append_buf(arg_dstr_t ds, int new_space) {
    int total_space;

    /*
     * Make the append buffer larger, if that's necessary, then copy the
     * data into the append buffer and make the append buffer the official
     * data.
     */
    if (ds->data != ds->append_data) {
        /*
         * If the buffer is too big, then free it up so we go back to a
         * smaller buffer. This avoids tying up memory forever after a large
         * operation.
         */
        if (ds->append_data_size > 500) {
            xfree(ds->append_data);
            ds->append_data = NULL;
            ds->append_data_size = 0;
        }
        ds->append_used = (int)strlen(ds->data);
    } else if (ds->data[ds->append_used] != 0) {
        /*
         * Most likely someone has modified a result created by
         * arg_dstr_cat et al. so that it has a different size. Just
         * recompute the size.
         */
        ds->append_used = (int)strlen(ds->data);
    }

    total_space = new_space + ds->append_used;
    if (total_space >= ds->append_data_size) {
        char* newbuf;

        if (total_space < 100) {
            total_space = 200;
        } else {
            total_space *= 2;
        }
        newbuf = (char*)xmalloc((unsigned)total_space);
        memset(newbuf, 0, total_space);
        strcpy(newbuf, ds->data);
        if (ds->append_data != NULL) {
            xfree(ds->append_data);
        }
        ds->append_data = newbuf;
        ds->append_data_size = total_space;
    } else if (ds->data != ds->append_data) {
        strcpy(ds->append_data, ds->data);
    }

    arg_dstr_free(ds);
    ds->data = ds->append_data;
}

void arg_dstr_free(arg_dstr_t ds) {
    if (ds->free_proc != NULL) {
        if (ds->free_proc == ARG_DSTR_DYNAMIC) {
            xfree(ds->data);
        } else {
            (*ds->free_proc)(ds->data);
        }
        ds->free_proc = NULL;
    }
}

void arg_dstr_reset(arg_dstr_t ds) {
    arg_dstr_free(ds);
    if ((ds->append_data != NULL) && (ds->append_data_size > 0)) {
        xfree(ds->append_data);
        ds->append_data = NULL;
        ds->append_data_size = 0;
    }

    ds->data = ds->sbuf;
    ds->sbuf[0] = 0;
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
/*	$Id: getopt.h,v 1.1 2009/10/16 19:50:28 rodney Exp rodney $ */
/*	$OpenBSD: getopt.h,v 1.1 2002/12/03 20:24:29 millert Exp $	*/
/*	$NetBSD: getopt.h,v 1.4 2000/07/07 10:43:54 ad Exp $	*/

/*
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#if ARG_REPLACE_GETOPT == 1

#ifndef _GETOPT_H_
#define _GETOPT_H_

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#define no_argument 0
#define required_argument 1
#define optional_argument 2

struct option {
    /* name of long option */
    const char* name;
    /*
     * one of no_argument, required_argument, and optional_argument:
     * whether option takes an argument
     */
    int has_arg;
    /* if not NULL, set *flag to val when option found */
    int* flag;
    /* if flag not NULL, value to set *flag to; else return value */
    int val;
};

#ifdef __cplusplus
extern "C" {
#endif

int getopt_long(int, char* const*, const char*, const struct option*, int*);
int getopt_long_only(int, char* const*, const char*, const struct option*, int*);
#ifndef _GETOPT_DEFINED
#define _GETOPT_DEFINED
int getopt(int, char* const*, const char*);
int getsubopt(char**, char* const*, char**);

extern char* optarg; /* getopt(3) external variables */
extern int opterr;
extern int optind;
extern int optopt;
extern int optreset;
extern char* suboptarg; /* getsubopt(3) external variable */
#endif                  /* _GETOPT_DEFINED */

#ifdef __cplusplus
}
#endif
#endif /* !_GETOPT_H_ */

#else
#include <getopt.h>
#endif /* ARG_REPLACE_GETOPT */
/*	$Id: getopt_long.c,v 1.1 2009/10/16 19:50:28 rodney Exp rodney $	*/
/*	$OpenBSD: getopt_long.c,v 1.23 2007/10/31 12:34:57 chl Exp $	*/
/*	$NetBSD: getopt_long.c,v 1.15 2002/01/31 22:43:40 tv Exp $	*/

/*
 * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/*
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "getopt.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if ARG_REPLACE_GETOPT == 1
int opterr = 1;   /* if error message should be printed */
int optind = 1;   /* index into parent argv vector */
int optopt = '?'; /* character checked for validity */
int optreset;     /* reset getopt */
char* optarg;     /* argument associated with option */
#endif            /* ARG_REPLACE_GETOPT */

#define PRINT_ERROR ((opterr) && (*options != ':'))

#define FLAG_PERMUTE 0x01  /* permute non-options to the end of argv */
#define FLAG_ALLARGS 0x02  /* treat non-options as args to option "-1" */
#define FLAG_LONGONLY 0x04 /* operate as getopt_long_only */

/* return values */
#define BADCH (int)'?'
#define BADARG ((*options == ':') ? (int)':' : (int)'?')
#define INORDER (int)1

#define EMSG ""

#if ARG_REPLACE_GETOPT == 1
static int getopt_internal(int, char* const*, const char*, const struct option*, int*, int);
#endif /* ARG_REPLACE_GETOPT */
static int parse_long_options(char* const*, const char*, const struct option*, int*, int);
static int gcd(int, int);
static void permute_args(int, int, int, char* const*);

static char* place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static int nonopt_start = -1; /* first non option argument (for permute) */
static int nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
static const char recargchar[] = "option requires an argument -- %c";
static const char recargstring[] = "option requires an argument -- %s";
static const char ambig[] = "ambiguous option -- %.*s";
static const char noarg[] = "option doesn't take an argument -- %.*s";
static const char illoptchar[] = "unknown option -- %c";
static const char illoptstring[] = "unknown option -- %s";

#ifdef _WIN32

/* 
 * Windows needs warnx().  We change the definition though:
 *  1. (another) global is defined, opterrmsg, which holds the error message
 *  2. errors are always printed out on stderr w/o the program name
 * Note that opterrmsg always gets set no matter what opterr is set to.  The
 * error message will not be printed if opterr is 0 as usual.
 */

#include <stdarg.h>
#include <stdio.h>

#define MAX_OPTERRMSG_SIZE 128

extern char opterrmsg[MAX_OPTERRMSG_SIZE];
char opterrmsg[MAX_OPTERRMSG_SIZE]; /* buffer for the last error message */

static void warnx(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    /* 
     * Make sure opterrmsg is always zero-terminated despite the _vsnprintf()
     * implementation specifics and manually suppress the warning.
     */
    memset(opterrmsg, 0, sizeof(opterrmsg));
    if (fmt != NULL)
#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
        _vsnprintf_s(opterrmsg, sizeof(opterrmsg), sizeof(opterrmsg) - 1, fmt, ap);
#else
        _vsnprintf(opterrmsg, sizeof(opterrmsg) - 1, fmt, ap);
#endif

    va_end(ap);

#ifdef _MSC_VER
#pragma warning(suppress : 6053)
#endif
    fprintf(stderr, "%s\n", opterrmsg);
}

#else
#include <err.h>
#endif /*_WIN32*/

/*
 * Compute the greatest common divisor of a and b.
 */
static int gcd(int a, int b) {
    int c;

    c = a % b;
    while (c != 0) {
        a = b;
        b = c;
        c = a % b;
    }

    return (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void permute_args(int panonopt_start, int panonopt_end, int opt_end, char* const* nargv) {
    int cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
    char* swap;

    /*
     * compute lengths of blocks and number and size of cycles
     */
    nnonopts = panonopt_end - panonopt_start;
    nopts = opt_end - panonopt_end;
    ncycle = gcd(nnonopts, nopts);
    cyclelen = (opt_end - panonopt_start) / ncycle;

    for (i = 0; i < ncycle; i++) {
        cstart = panonopt_end + i;
        pos = cstart;
        for (j = 0; j < cyclelen; j++) {
            if (pos >= panonopt_end)
                pos -= nnonopts;
            else
                pos += nopts;
            swap = nargv[pos];
            /* LINTED const cast */
            ((char**)nargv)[pos] = nargv[cstart];
            /* LINTED const cast */
            ((char**)nargv)[cstart] = swap;
        }
    }
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
static int parse_long_options(char* const* nargv, const char* options, const struct option* long_options, int* idx, int short_too) {
    char *current_argv, *has_equal;
    size_t current_argv_len;
    int i, match;

    current_argv = place;
    match = -1;

    optind++;

    if ((has_equal = strchr(current_argv, '=')) != NULL) {
        /* argument found (--option=arg) */
        current_argv_len = has_equal - current_argv;
        has_equal++;
    } else
        current_argv_len = strlen(current_argv);

    for (i = 0; long_options[i].name; i++) {
        /* find matching long option */
        if (strncmp(current_argv, long_options[i].name, current_argv_len))
            continue;

        if (strlen(long_options[i].name) == current_argv_len) {
            /* exact match */
            match = i;
            break;
        }
        /*
         * If this is a known short option, don't allow
         * a partial match of a single character.
         */
        if (short_too && current_argv_len == 1)
            continue;

        if (match == -1) /* partial match */
            match = i;
        else {
            /* ambiguous abbreviation */
            if (PRINT_ERROR)
                warnx(ambig, (int)current_argv_len, current_argv);
            optopt = 0;
            return (BADCH);
        }
    }
    if (match != -1) { /* option found */
        if (long_options[match].has_arg == no_argument && has_equal) {
            if (PRINT_ERROR)
                warnx(noarg, (int)current_argv_len, current_argv);
            /*
             * XXX: GNU sets optopt to val regardless of flag
             */
            if (long_options[match].flag == NULL)
                optopt = long_options[match].val;
            else
                optopt = 0;
            return (BADARG);
        }
        if (long_options[match].has_arg == required_argument || long_options[match].has_arg == optional_argument) {
            if (has_equal)
                optarg = has_equal;
            else if (long_options[match].has_arg == required_argument) {
                /*
                 * optional argument doesn't use next nargv
                 */
                optarg = nargv[optind++];
            }
        }
        if ((long_options[match].has_arg == required_argument) && (optarg == NULL)) {
            /*
             * Missing argument; leading ':' indicates no error
             * should be generated.
             */
            if (PRINT_ERROR)
                warnx(recargstring, current_argv);
            /*
             * XXX: GNU sets optopt to val regardless of flag
             */
            if (long_options[match].flag == NULL)
                optopt = long_options[match].val;
            else
                optopt = 0;
            --optind;
            return (BADARG);
        }
    } else { /* unknown option */
        if (short_too) {
            --optind;
            return (-1);
        }
        if (PRINT_ERROR)
            warnx(illoptstring, current_argv);
        optopt = 0;
        return (BADCH);
    }
    if (idx)
        *idx = match;
    if (long_options[match].flag) {
        *long_options[match].flag = long_options[match].val;
        return (0);
    } else
        return (long_options[match].val);
}

#if ARG_REPLACE_GETOPT == 1
/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
static int getopt_internal(int nargc, char* const* nargv, const char* options, const struct option* long_options, int* idx, int flags) {
    char* oli; /* option letter list index */
    int optchar, short_too;
    static int posixly_correct = -1;

    if (options == NULL)
        return (-1);

    /*
     * Disable GNU extensions if POSIXLY_CORRECT is set or options
     * string begins with a '+'.
     */
    if (posixly_correct == -1)
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
        posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (posixly_correct || *options == '+')
        flags &= ~FLAG_PERMUTE;
    else if (*options == '-')
        flags |= FLAG_ALLARGS;
    if (*options == '+' || *options == '-')
        options++;

    /*
     * XXX Some GNU programs (like cvs) set optind to 0 instead of
     * XXX using optreset.  Work around this braindamage.
     */
    if (optind == 0)
        optind = optreset = 1;

    optarg = NULL;
    if (optreset)
        nonopt_start = nonopt_end = -1;
start:
    if (optreset || !*place) { /* update scanning pointer */
        optreset = 0;
        if (optind >= nargc) { /* end of argument vector */
            place = EMSG;
            if (nonopt_end != -1) {
                /* do permutation, if we have to */
                permute_args(nonopt_start, nonopt_end, optind, nargv);
                optind -= nonopt_end - nonopt_start;
            } else if (nonopt_start != -1) {
                /*
                 * If we skipped non-options, set optind
                 * to the first of them.
                 */
                optind = nonopt_start;
            }
            nonopt_start = nonopt_end = -1;
            return (-1);
        }
        if (*(place = nargv[optind]) != '-' || (place[1] == '\0' && strchr(options, '-') == NULL)) {
            place = EMSG; /* found non-option */
            if (flags & FLAG_ALLARGS) {
                /*
                 * GNU extension:
                 * return non-option as argument to option 1
                 */
                optarg = nargv[optind++];
                return (INORDER);
            }
            if (!(flags & FLAG_PERMUTE)) {
                /*
                 * If no permutation wanted, stop parsing
                 * at first non-option.
                 */
                return (-1);
            }
            /* do permutation */
            if (nonopt_start == -1)
                nonopt_start = optind;
            else if (nonopt_end != -1) {
                permute_args(nonopt_start, nonopt_end, optind, nargv);
                nonopt_start = optind - (nonopt_end - nonopt_start);
                nonopt_end = -1;
            }
            optind++;
            /* process next argument */
            goto start;
        }
        if (nonopt_start != -1 && nonopt_end == -1)
            nonopt_end = optind;

        /*
         * If we have "-" do nothing, if "--" we are done.
         */
        if (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
            optind++;
            place = EMSG;
            /*
             * We found an option (--), so if we skipped
             * non-options, we have to permute.
             */
            if (nonopt_end != -1) {
                permute_args(nonopt_start, nonopt_end, optind, nargv);
                optind -= nonopt_end - nonopt_start;
            }
            nonopt_start = nonopt_end = -1;
            return (-1);
        }
    }

    /*
     * Check long options if:
     *  1) we were passed some
     *  2) the arg is not just "-"
     *  3) either the arg starts with -- we are getopt_long_only()
     */
    if (long_options != NULL && place != nargv[optind] && (*place == '-' || (flags & FLAG_LONGONLY))) {
        short_too = 0;
        if (*place == '-')
            place++; /* --foo long option */
        else if (*place != ':' && strchr(options, *place) != NULL)
            short_too = 1; /* could be short option too */

        optchar = parse_long_options(nargv, options, long_options, idx, short_too);
        if (optchar != -1) {
            place = EMSG;
            return (optchar);
        }
    }

    if ((optchar = (int)*place++) == (int)':' || (optchar == (int)'-' && *place != '\0') || (oli = strchr(options, optchar)) == NULL) {
        /*
         * If the user specified "-" and  '-' isn't listed in
         * options, return -1 (non-option) as per POSIX.
         * Otherwise, it is an unknown option character (or ':').
         */
        if (optchar == (int)'-' && *place == '\0')
            return (-1);
        if (!*place)
            ++optind;
        if (PRINT_ERROR)
            warnx(illoptchar, optchar);
        optopt = optchar;
        return (BADCH);
    }
    if (long_options != NULL && optchar == 'W' && oli[1] == ';') {
        /* -W long-option */
        if (*place) /* no space */
            /* NOTHING */;
        else if (++optind >= nargc) { /* no arg */
            place = EMSG;
            if (PRINT_ERROR)
                warnx(recargchar, optchar);
            optopt = optchar;
            return (BADARG);
        } else /* white space */
            place = nargv[optind];
        optchar = parse_long_options(nargv, options, long_options, idx, 0);
        place = EMSG;
        return (optchar);
    }
    if (*++oli != ':') { /* doesn't take argument */
        if (!*place)
            ++optind;
    } else { /* takes (optional) argument */
        optarg = NULL;
        if (*place) /* no white space */
            optarg = place;
        else if (oli[1] != ':') {    /* arg not optional */
            if (++optind >= nargc) { /* no arg */
                place = EMSG;
                if (PRINT_ERROR)
                    warnx(recargchar, optchar);
                optopt = optchar;
                return (BADARG);
            } else
                optarg = nargv[optind];
        }
        place = EMSG;
        ++optind;
    }
    /* dump back option letter */
    return (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
int getopt(int nargc, char* const* nargv, const char* options) {
    /*
     * We don't pass FLAG_PERMUTE to getopt_internal() since
     * the BSD getopt(3) (unlike GNU) has never done this.
     *
     * Furthermore, since many privileged programs call getopt()
     * before dropping privileges it makes sense to keep things
     * as simple (and bug-free) as possible.
     */
    return (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
}
#endif /* ARG_REPLACE_GETOPT */

/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
int getopt_long(int nargc, char* const* nargv, const char* options, const struct option* long_options, int* idx) {
    return (getopt_internal(nargc, nargv, options, long_options, idx, FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
int getopt_long_only(int nargc, char* const* nargv, const char* options, const struct option* long_options, int* idx) {
    return (getopt_internal(nargc, nargv, options, long_options, idx, FLAG_PERMUTE | FLAG_LONGONLY));
}
/*******************************************************************************
 * arg_date: Implements the date command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>
#include <string.h>

char* arg_strptime(const char* buf, const char* fmt, struct tm* tm);

static void arg_date_resetfn(struct arg_date* parent) {
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    parent->count = 0;
}

static int arg_date_scanfn(struct arg_date* parent, const char* argval) {
    int errorcode = 0;

    if (parent->count == parent->hdr.maxcount) {
        errorcode = ARG_ERR_MAXCOUNT;
    } else if (!argval) {
        /* no argument value was given, leave parent->tmval[] unaltered but still count it */
        parent->count++;
    } else {
        const char* pend;
        struct tm tm = parent->tmval[parent->count];

        /* parse the given argument value, store result in parent->tmval[] */
        pend = arg_strptime(argval, parent->format, &tm);
        if (pend && pend[0] == '\0')
            parent->tmval[parent->count++] = tm;
        else
            errorcode = ARG_ERR_BADDATE;
    }

    ARG_TRACE(("%s:scanfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static int arg_date_checkfn(struct arg_date* parent) {
    int errorcode = (parent->count < parent->hdr.mincount) ? ARG_ERR_MINCOUNT : 0;

    ARG_TRACE(("%s:checkfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static void arg_date_errorfn(struct arg_date* parent, arg_dstr_t ds, int errorcode, const char* argval, const char* progname) {
    const char* shortopts = parent->hdr.shortopts;
    const char* longopts = parent->hdr.longopts;
    const char* datatype = parent->hdr.datatype;

    /* make argval NULL safe */
    argval = argval ? argval : "";

    arg_dstr_catf(ds, "%s: ", progname);
    switch (errorcode) {
        case ARG_ERR_MINCOUNT:
            arg_dstr_cat(ds, "missing option ");
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;

        case ARG_ERR_MAXCOUNT:
            arg_dstr_cat(ds, "excess option ");
            arg_print_option_ds(ds, shortopts, longopts, argval, "\n");
            break;

        case ARG_ERR_BADDATE: {
            struct tm tm;
            char buff[200];

            arg_dstr_catf(ds, "illegal timestamp format \"%s\"\n", argval);
            memset(&tm, 0, sizeof(tm));
            arg_strptime("1999-12-31 23:59:59", "%F %H:%M:%S", &tm);
            strftime(buff, sizeof(buff), parent->format, &tm);
            arg_dstr_catf(ds, "correct format is \"%s\"\n", buff);
            break;
        }
    }
}

struct arg_date* arg_date0(const char* shortopts, const char* longopts, const char* format, const char* datatype, const char* glossary) {
    return arg_daten(shortopts, longopts, format, datatype, 0, 1, glossary);
}

struct arg_date* arg_date1(const char* shortopts, const char* longopts, const char* format, const char* datatype, const char* glossary) {
    return arg_daten(shortopts, longopts, format, datatype, 1, 1, glossary);
}

struct arg_date*
arg_daten(const char* shortopts, const char* longopts, const char* format, const char* datatype, int mincount, int maxcount, const char* glossary) {
    size_t nbytes;
    struct arg_date* result;

    /* foolproof things by ensuring maxcount is not less than mincount */
    maxcount = (maxcount < mincount) ? mincount : maxcount;

    /* default time format is the national date format for the locale */
    if (!format)
        format = "%x";

    nbytes = sizeof(struct arg_date)         /* storage for struct arg_date */
             + maxcount * sizeof(struct tm); /* storage for tmval[maxcount] array */

    /* allocate storage for the arg_date struct + tmval[] array.    */
    /* we use calloc because we want the tmval[] array zero filled. */
    result = (struct arg_date*)xcalloc(1, nbytes);

    /* init the arg_hdr struct */
    result->hdr.flag = ARG_HASVALUE;
    result->hdr.shortopts = shortopts;
    result->hdr.longopts = longopts;
    result->hdr.datatype = datatype ? datatype : format;
    result->hdr.glossary = glossary;
    result->hdr.mincount = mincount;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_date_resetfn;
    result->hdr.scanfn = (arg_scanfn*)arg_date_scanfn;
    result->hdr.checkfn = (arg_checkfn*)arg_date_checkfn;
    result->hdr.errorfn = (arg_errorfn*)arg_date_errorfn;

    /* store the tmval[maxcount] array immediately after the arg_date struct */
    result->tmval = (struct tm*)(result + 1);

    /* init the remaining arg_date member variables */
    result->count = 0;
    result->format = format;

    ARG_TRACE(("arg_daten() returns %p\n", result));
    return result;
}

/*-
 * Copyright (c) 1997, 1998, 2005, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code was contributed to The NetBSD Foundation by Klaus Klein.
 * Heavily optimised by David Laight
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <string.h>
#include <time.h>

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define ALT_E 0x01
#define ALT_O 0x02
#define LEGAL_ALT(x)           \
    {                          \
        if (alt_format & ~(x)) \
            return (0);        \
    }
#define TM_YEAR_BASE (1900)

static int conv_num(const char**, int*, int, int);

static const char* day[7] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};

static const char* abday[7] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

static const char* mon[12] = {"January", "February", "March",     "April",   "May",      "June",
                              "July",    "August",   "September", "October", "November", "December"};

static const char* abmon[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static const char* am_pm[2] = {"AM", "PM"};

static int arg_strcasecmp(const char* s1, const char* s2) {
    const unsigned char* us1 = (const unsigned char*)s1;
    const unsigned char* us2 = (const unsigned char*)s2;
    while (tolower(*us1) == tolower(*us2++))
        if (*us1++ == '\0')
            return 0;

    return tolower(*us1) - tolower(*--us2);
}

static int arg_strncasecmp(const char* s1, const char* s2, size_t n) {
    if (n != 0) {
        const unsigned char* us1 = (const unsigned char*)s1;
        const unsigned char* us2 = (const unsigned char*)s2;
        do {
            if (tolower(*us1) != tolower(*us2++))
                return tolower(*us1) - tolower(*--us2);

            if (*us1++ == '\0')
                break;
        } while (--n != 0);
    }

    return 0;
}

char* arg_strptime(const char* buf, const char* fmt, struct tm* tm) {
    char c;
    const char* bp;
    size_t len = 0;
    int alt_format, i, split_year = 0;

    bp = buf;

    while ((c = *fmt) != '\0') {
        /* Clear `alternate' modifier prior to new conversion. */
        alt_format = 0;

        /* Eat up white-space. */
        if (isspace(c)) {
            while (isspace(*bp))
                bp++;

            fmt++;
            continue;
        }

        if ((c = *fmt++) != '%')
            goto literal;

    again:
        switch (c = *fmt++) {
            case '%': /* "%%" is converted to "%". */
            literal:
                if (c != *bp++)
                    return (0);
                break;

            /*
             * "Alternative" modifiers. Just set the appropriate flag
             * and start over again.
             */
            case 'E': /* "%E?" alternative conversion modifier. */
                LEGAL_ALT(0);
                alt_format |= ALT_E;
                goto again;

            case 'O': /* "%O?" alternative conversion modifier. */
                LEGAL_ALT(0);
                alt_format |= ALT_O;
                goto again;

            /*
             * "Complex" conversion rules, implemented through recursion.
             */
            case 'c': /* Date and time, using the locale's format. */
                LEGAL_ALT(ALT_E);
                bp = arg_strptime(bp, "%x %X", tm);
                if (!bp)
                    return (0);
                break;

            case 'D': /* The date as "%m/%d/%y". */
                LEGAL_ALT(0);
                bp = arg_strptime(bp, "%m/%d/%y", tm);
                if (!bp)
                    return (0);
                break;

            case 'R': /* The time as "%H:%M". */
                LEGAL_ALT(0);
                bp = arg_strptime(bp, "%H:%M", tm);
                if (!bp)
                    return (0);
                break;

            case 'r': /* The time in 12-hour clock representation. */
                LEGAL_ALT(0);
                bp = arg_strptime(bp, "%I:%M:%S %p", tm);
                if (!bp)
                    return (0);
                break;

            case 'T': /* The time as "%H:%M:%S". */
                LEGAL_ALT(0);
                bp = arg_strptime(bp, "%H:%M:%S", tm);
                if (!bp)
                    return (0);
                break;

            case 'X': /* The time, using the locale's format. */
                LEGAL_ALT(ALT_E);
                bp = arg_strptime(bp, "%H:%M:%S", tm);
                if (!bp)
                    return (0);
                break;

            case 'x': /* The date, using the locale's format. */
                LEGAL_ALT(ALT_E);
                bp = arg_strptime(bp, "%m/%d/%y", tm);
                if (!bp)
                    return (0);
                break;

            /*
             * "Elementary" conversion rules.
             */
            case 'A': /* The day of week, using the locale's form. */
            case 'a':
                LEGAL_ALT(0);
                for (i = 0; i < 7; i++) {
                    /* Full name. */
                    len = strlen(day[i]);
                    if (arg_strncasecmp(day[i], bp, len) == 0)
                        break;

                    /* Abbreviated name. */
                    len = strlen(abday[i]);
                    if (arg_strncasecmp(abday[i], bp, len) == 0)
                        break;
                }

                /* Nothing matched. */
                if (i == 7)
                    return (0);

                tm->tm_wday = i;
                bp += len;
                break;

            case 'B': /* The month, using the locale's form. */
            case 'b':
            case 'h':
                LEGAL_ALT(0);
                for (i = 0; i < 12; i++) {
                    /* Full name. */
                    len = strlen(mon[i]);
                    if (arg_strncasecmp(mon[i], bp, len) == 0)
                        break;

                    /* Abbreviated name. */
                    len = strlen(abmon[i]);
                    if (arg_strncasecmp(abmon[i], bp, len) == 0)
                        break;
                }

                /* Nothing matched. */
                if (i == 12)
                    return (0);

                tm->tm_mon = i;
                bp += len;
                break;

            case 'C': /* The century number. */
                LEGAL_ALT(ALT_E);
                if (!(conv_num(&bp, &i, 0, 99)))
                    return (0);

                if (split_year) {
                    tm->tm_year = (tm->tm_year % 100) + (i * 100);
                } else {
                    tm->tm_year = i * 100;
                    split_year = 1;
                }
                break;

            case 'd': /* The day of month. */
            case 'e':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_mday, 1, 31)))
                    return (0);
                break;

            case 'k': /* The hour (24-hour clock representation). */
                LEGAL_ALT(0);
            /* FALLTHROUGH */
            case 'H':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_hour, 0, 23)))
                    return (0);
                break;

            case 'l': /* The hour (12-hour clock representation). */
                LEGAL_ALT(0);
            /* FALLTHROUGH */
            case 'I':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_hour, 1, 12)))
                    return (0);
                if (tm->tm_hour == 12)
                    tm->tm_hour = 0;
                break;

            case 'j': /* The day of year. */
                LEGAL_ALT(0);
                if (!(conv_num(&bp, &i, 1, 366)))
                    return (0);
                tm->tm_yday = i - 1;
                break;

            case 'M': /* The minute. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_min, 0, 59)))
                    return (0);
                break;

            case 'm': /* The month. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &i, 1, 12)))
                    return (0);
                tm->tm_mon = i - 1;
                break;

            case 'p': /* The locale's equivalent of AM/PM. */
                LEGAL_ALT(0);
                /* AM? */
                if (arg_strcasecmp(am_pm[0], bp) == 0) {
                    if (tm->tm_hour > 11)
                        return (0);

                    bp += strlen(am_pm[0]);
                    break;
                }
                /* PM? */
                else if (arg_strcasecmp(am_pm[1], bp) == 0) {
                    if (tm->tm_hour > 11)
                        return (0);

                    tm->tm_hour += 12;
                    bp += strlen(am_pm[1]);
                    break;
                }

                /* Nothing matched. */
                return (0);

            case 'S': /* The seconds. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_sec, 0, 61)))
                    return (0);
                break;

            case 'U': /* The week of year, beginning on sunday. */
            case 'W': /* The week of year, beginning on monday. */
                LEGAL_ALT(ALT_O);
                /*
                 * XXX This is bogus, as we can not assume any valid
                 * information present in the tm structure at this
                 * point to calculate a real value, so just check the
                 * range for now.
                 */
                if (!(conv_num(&bp, &i, 0, 53)))
                    return (0);
                break;

            case 'w': /* The day of week, beginning on sunday. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_wday, 0, 6)))
                    return (0);
                break;

            case 'Y': /* The year. */
                LEGAL_ALT(ALT_E);
                if (!(conv_num(&bp, &i, 0, 9999)))
                    return (0);

                tm->tm_year = i - TM_YEAR_BASE;
                break;

            case 'y': /* The year within 100 years of the epoch. */
                LEGAL_ALT(ALT_E | ALT_O);
                if (!(conv_num(&bp, &i, 0, 99)))
                    return (0);

                if (split_year) {
                    tm->tm_year = ((tm->tm_year / 100) * 100) + i;
                    break;
                }
                split_year = 1;
                if (i <= 68)
                    tm->tm_year = i + 2000 - TM_YEAR_BASE;
                else
                    tm->tm_year = i + 1900 - TM_YEAR_BASE;
                break;

            /*
             * Miscellaneous conversions.
             */
            case 'n': /* Any kind of white-space. */
            case 't':
                LEGAL_ALT(0);
                while (isspace(*bp))
                    bp++;
                break;

            default: /* Unknown/unsupported conversion. */
                return (0);
        }
    }

    /* LINTED functional specification */
    return ((char*)bp);
}

static int conv_num(const char** buf, int* dest, int llim, int ulim) {
    int result = 0;

    /* The limit also determines the number of valid digits. */
    int rulim = ulim;

    if (**buf < '0' || **buf > '9')
        return (0);

    do {
        result *= 10;
        result += *(*buf)++ - '0';
        rulim /= 10;
    } while ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

    if (result < llim || result > ulim)
        return (0);

    *dest = result;
    return (1);
}
/*******************************************************************************
 * arg_dbl: Implements the double command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>

static void arg_dbl_resetfn(struct arg_dbl* parent) {
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    parent->count = 0;
}

static int arg_dbl_scanfn(struct arg_dbl* parent, const char* argval) {
    int errorcode = 0;

    if (parent->count == parent->hdr.maxcount) {
        /* maximum number of arguments exceeded */
        errorcode = ARG_ERR_MAXCOUNT;
    } else if (!argval) {
        /* a valid argument with no argument value was given. */
        /* This happens when an optional argument value was invoked. */
        /* leave parent argument value unaltered but still count the argument. */
        parent->count++;
    } else {
        double val;
        char* end;

        /* extract double from argval into val */
        val = strtod(argval, &end);

        /* if success then store result in parent->dval[] array otherwise return error*/
        if (*end == 0)
            parent->dval[parent->count++] = val;
        else
            errorcode = ARG_ERR_BADDOUBLE;
    }

    ARG_TRACE(("%s:scanfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static int arg_dbl_checkfn(struct arg_dbl* parent) {
    int errorcode = (parent->count < parent->hdr.mincount) ? ARG_ERR_MINCOUNT : 0;

    ARG_TRACE(("%s:checkfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static void arg_dbl_errorfn(struct arg_dbl* parent, arg_dstr_t ds, int errorcode, const char* argval, const char* progname) {
    const char* shortopts = parent->hdr.shortopts;
    const char* longopts = parent->hdr.longopts;
    const char* datatype = parent->hdr.datatype;

    /* make argval NULL safe */
    argval = argval ? argval : "";

    arg_dstr_catf(ds, "%s: ", progname);
    switch (errorcode) {
        case ARG_ERR_MINCOUNT:
            arg_dstr_cat(ds, "missing option ");
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;

        case ARG_ERR_MAXCOUNT:
            arg_dstr_cat(ds, "excess option ");
            arg_print_option_ds(ds, shortopts, longopts, argval, "\n");
            break;

        case ARG_ERR_BADDOUBLE:
            arg_dstr_catf(ds, "invalid argument \"%s\" to option ", argval);
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;
    }
}

struct arg_dbl* arg_dbl0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_dbln(shortopts, longopts, datatype, 0, 1, glossary);
}

struct arg_dbl* arg_dbl1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_dbln(shortopts, longopts, datatype, 1, 1, glossary);
}

struct arg_dbl* arg_dbln(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary) {
    size_t nbytes;
    struct arg_dbl* result;
    size_t addr;
    size_t rem;

    /* foolproof things by ensuring maxcount is not less than mincount */
    maxcount = (maxcount < mincount) ? mincount : maxcount;

    nbytes = sizeof(struct arg_dbl)             /* storage for struct arg_dbl */
             + (maxcount + 1) * sizeof(double); /* storage for dval[maxcount] array plus one extra for padding to memory boundary */

    result = (struct arg_dbl*)xmalloc(nbytes);

    /* init the arg_hdr struct */
    result->hdr.flag = ARG_HASVALUE;
    result->hdr.shortopts = shortopts;
    result->hdr.longopts = longopts;
    result->hdr.datatype = datatype ? datatype : "<double>";
    result->hdr.glossary = glossary;
    result->hdr.mincount = mincount;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_dbl_resetfn;
    result->hdr.scanfn = (arg_scanfn*)arg_dbl_scanfn;
    result->hdr.checkfn = (arg_checkfn*)arg_dbl_checkfn;
    result->hdr.errorfn = (arg_errorfn*)arg_dbl_errorfn;

    /* Store the dval[maxcount] array on the first double boundary that
     * immediately follows the arg_dbl struct. We do the memory alignment
     * purely for SPARC and Motorola systems. They require floats and
     * doubles to be aligned on natural boundaries.
     */
    addr = (size_t)(result + 1);
    rem = addr % sizeof(double);
    result->dval = (double*)(addr + sizeof(double) - rem);
    ARG_TRACE(("addr=%p, dval=%p, sizeof(double)=%d rem=%d\n", addr, result->dval, (int)sizeof(double), (int)rem));

    result->count = 0;

    ARG_TRACE(("arg_dbln() returns %p\n", result));
    return result;
}
/*******************************************************************************
 * arg_end: Implements the error handling utilities
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>

static void arg_end_resetfn(struct arg_end* parent) {
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    parent->count = 0;
}

static void arg_end_errorfn(void* parent, arg_dstr_t ds, int error, const char* argval, const char* progname) {
    /* suppress unreferenced formal parameter warning */
    (void)parent;

    progname = progname ? progname : "";
    argval = argval ? argval : "";

    arg_dstr_catf(ds, "%s: ", progname);
    switch (error) {
        case ARG_ELIMIT:
            arg_dstr_cat(ds, "too many errors to display");
            break;
        case ARG_EMALLOC:
            arg_dstr_cat(ds, "insufficient memory");
            break;
        case ARG_ENOMATCH:
            arg_dstr_catf(ds, "unexpected argument \"%s\"", argval);
            break;
        case ARG_EMISSARG:
            arg_dstr_catf(ds, "option \"%s\" requires an argument", argval);
            break;
        case ARG_ELONGOPT:
            arg_dstr_catf(ds, "invalid option \"%s\"", argval);
            break;
        default:
            arg_dstr_catf(ds, "invalid option \"-%c\"", error);
            break;
    }

    arg_dstr_cat(ds, "\n");
}

struct arg_end* arg_end(int maxcount) {
    size_t nbytes;
    struct arg_end* result;

    nbytes = sizeof(struct arg_end) + maxcount * sizeof(int) /* storage for int error[maxcount] array*/
             + maxcount * sizeof(void*)                      /* storage for void* parent[maxcount] array */
             + maxcount * sizeof(char*);                     /* storage for char* argval[maxcount] array */

    result = (struct arg_end*)xmalloc(nbytes);

    /* init the arg_hdr struct */
    result->hdr.flag = ARG_TERMINATOR;
    result->hdr.shortopts = NULL;
    result->hdr.longopts = NULL;
    result->hdr.datatype = NULL;
    result->hdr.glossary = NULL;
    result->hdr.mincount = 1;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_end_resetfn;
    result->hdr.scanfn = NULL;
    result->hdr.checkfn = NULL;
    result->hdr.errorfn = (arg_errorfn*)arg_end_errorfn;

    /* store error[maxcount] array immediately after struct arg_end */
    result->error = (int*)(result + 1);

    /* store parent[maxcount] array immediately after error[] array */
    result->parent = (void**)(result->error + maxcount);

    /* store argval[maxcount] array immediately after parent[] array */
    result->argval = (const char**)(result->parent + maxcount);

    ARG_TRACE(("arg_end(%d) returns %p\n", maxcount, result));
    return result;
}

void arg_print_errors_ds(arg_dstr_t ds, struct arg_end* end, const char* progname) {
    int i;
    ARG_TRACE(("arg_errors()\n"));
    for (i = 0; i < end->count; i++) {
        struct arg_hdr* errorparent = (struct arg_hdr*)(end->parent[i]);
        if (errorparent->errorfn)
            errorparent->errorfn(end->parent[i], ds, end->error[i], end->argval[i], progname);
    }
}

void arg_print_errors(FILE* fp, struct arg_end* end, const char* progname) {
    arg_dstr_t ds = arg_dstr_create();
    arg_print_errors_ds(ds, end, progname);
    fputs(arg_dstr_cstr(ds), fp);
    arg_dstr_destroy(ds);
}
/*******************************************************************************
 * arg_file: Implements the file command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#define FILESEPARATOR1 '\\'
#define FILESEPARATOR2 '/'
#else
#define FILESEPARATOR1 '/'
#define FILESEPARATOR2 '/'
#endif

static void arg_file_resetfn(struct arg_file* parent) {
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    parent->count = 0;
}

/* Returns ptr to the base filename within *filename */
static const char* arg_basename(const char* filename) {
    const char *result = NULL, *result1, *result2;

    /* Find the last occurrence of eother file separator character. */
    /* Two alternative file separator chars are supported as legal  */
    /* file separators but not both together in the same filename.  */
    result1 = (filename ? strrchr(filename, FILESEPARATOR1) : NULL);
    result2 = (filename ? strrchr(filename, FILESEPARATOR2) : NULL);

    if (result2)
        result = result2 + 1; /* using FILESEPARATOR2 (the alternative file separator) */

    if (result1)
        result = result1 + 1; /* using FILESEPARATOR1 (the preferred file separator) */

    if (!result)
        result = filename; /* neither file separator was found so basename is the whole filename */

    /* special cases of "." and ".." are not considered basenames */
    if (result && (strcmp(".", result) == 0 || strcmp("..", result) == 0))
        result = filename + strlen(filename);

    return result;
}

/* Returns ptr to the file extension within *basename */
static const char* arg_extension(const char* basename) {
    /* find the last occurrence of '.' in basename */
    const char* result = (basename ? strrchr(basename, '.') : NULL);

    /* if no '.' was found then return pointer to end of basename */
    if (basename && !result)
        result = basename + strlen(basename);

    /* special case: basenames with a single leading dot (eg ".foo") are not considered as true extensions */
    if (basename && result == basename)
        result = basename + strlen(basename);

    /* special case: empty extensions (eg "foo.","foo..") are not considered as true extensions */
    if (basename && result && result[1] == '\0')
        result = basename + strlen(basename);

    return result;
}

static int arg_file_scanfn(struct arg_file* parent, const char* argval) {
    int errorcode = 0;

    if (parent->count == parent->hdr.maxcount) {
        /* maximum number of arguments exceeded */
        errorcode = ARG_ERR_MAXCOUNT;
    } else if (!argval) {
        /* a valid argument with no argument value was given. */
        /* This happens when an optional argument value was invoked. */
        /* leave parent arguiment value unaltered but still count the argument. */
        parent->count++;
    } else {
        parent->filename[parent->count] = argval;
        parent->basename[parent->count] = arg_basename(argval);
        parent->extension[parent->count] =
                arg_extension(parent->basename[parent->count]); /* only seek extensions within the basename (not the file path)*/
        parent->count++;
    }

    ARG_TRACE(("%s4:scanfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static int arg_file_checkfn(struct arg_file* parent) {
    int errorcode = (parent->count < parent->hdr.mincount) ? ARG_ERR_MINCOUNT : 0;

    ARG_TRACE(("%s:checkfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static void arg_file_errorfn(struct arg_file* parent, arg_dstr_t ds, int errorcode, const char* argval, const char* progname) {
    const char* shortopts = parent->hdr.shortopts;
    const char* longopts = parent->hdr.longopts;
    const char* datatype = parent->hdr.datatype;

    /* make argval NULL safe */
    argval = argval ? argval : "";

    arg_dstr_catf(ds, "%s: ", progname);
    switch (errorcode) {
        case ARG_ERR_MINCOUNT:
            arg_dstr_cat(ds, "missing option ");
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;

        case ARG_ERR_MAXCOUNT:
            arg_dstr_cat(ds, "excess option ");
            arg_print_option_ds(ds, shortopts, longopts, argval, "\n");
            break;

        default:
            arg_dstr_catf(ds, "unknown error at \"%s\"\n", argval);
    }
}

struct arg_file* arg_file0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_filen(shortopts, longopts, datatype, 0, 1, glossary);
}

struct arg_file* arg_file1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_filen(shortopts, longopts, datatype, 1, 1, glossary);
}

struct arg_file* arg_filen(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary) {
    size_t nbytes;
    struct arg_file* result;
    int i;

    /* foolproof things by ensuring maxcount is not less than mincount */
    maxcount = (maxcount < mincount) ? mincount : maxcount;

    nbytes = sizeof(struct arg_file)     /* storage for struct arg_file */
             + sizeof(char*) * maxcount  /* storage for filename[maxcount] array */
             + sizeof(char*) * maxcount  /* storage for basename[maxcount] array */
             + sizeof(char*) * maxcount; /* storage for extension[maxcount] array */

    result = (struct arg_file*)xmalloc(nbytes);

    /* init the arg_hdr struct */
    result->hdr.flag = ARG_HASVALUE;
    result->hdr.shortopts = shortopts;
    result->hdr.longopts = longopts;
    result->hdr.glossary = glossary;
    result->hdr.datatype = datatype ? datatype : "<file>";
    result->hdr.mincount = mincount;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_file_resetfn;
    result->hdr.scanfn = (arg_scanfn*)arg_file_scanfn;
    result->hdr.checkfn = (arg_checkfn*)arg_file_checkfn;
    result->hdr.errorfn = (arg_errorfn*)arg_file_errorfn;

    /* store the filename,basename,extension arrays immediately after the arg_file struct */
    result->filename = (const char**)(result + 1);
    result->basename = result->filename + maxcount;
    result->extension = result->basename + maxcount;
    result->count = 0;

    /* foolproof the string pointers by initialising them with empty strings */
    for (i = 0; i < maxcount; i++) {
        result->filename[i] = "";
        result->basename[i] = "";
        result->extension[i] = "";
    }

    ARG_TRACE(("arg_filen() returns %p\n", result));
    return result;
}
/*******************************************************************************
 * arg_int: Implements the int command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>

static void arg_int_resetfn(struct arg_int* parent) {
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    parent->count = 0;
}

/* strtol0x() is like strtol() except that the numeric string is    */
/* expected to be prefixed by "0X" where X is a user supplied char. */
/* The string may optionally be prefixed by white space and + or -  */
/* as in +0X123 or -0X123.                                          */
/* Once the prefix has been scanned, the remainder of the numeric   */
/* string is converted using strtol() with the given base.          */
/* eg: to parse hex str="-0X12324", specify X='X' and base=16.      */
/* eg: to parse oct str="+0o12324", specify X='O' and base=8.       */
/* eg: to parse bin str="-0B01010", specify X='B' and base=2.       */
/* Failure of conversion is indicated by result where *endptr==str. */
static long int strtol0X(const char* str, const char** endptr, char X, int base) {
    long int val;          /* stores result */
    int s = 1;             /* sign is +1 or -1 */
    const char* ptr = str; /* ptr to current position in str */

    /* skip leading whitespace */
    while (isspace(*ptr))
        ptr++;
    /* printf("1) %s\n",ptr); */

    /* scan optional sign character */
    switch (*ptr) {
        case '+':
            ptr++;
            s = 1;
            break;
        case '-':
            ptr++;
            s = -1;
            break;
        default:
            s = 1;
            break;
    }
    /* printf("2) %s\n",ptr); */

    /* '0X' prefix */
    if ((*ptr++) != '0') {
        /* printf("failed to detect '0'\n"); */
        *endptr = str;
        return 0;
    }
    /* printf("3) %s\n",ptr); */
    if (toupper(*ptr++) != toupper(X)) {
        /* printf("failed to detect '%c'\n",X); */
        *endptr = str;
        return 0;
    }
    /* printf("4) %s\n",ptr); */

    /* attempt conversion on remainder of string using strtol() */
    val = strtol(ptr, (char**)endptr, base);
    if (*endptr == ptr) {
        /* conversion failed */
        *endptr = str;
        return 0;
    }

    /* success */
    return s * val;
}

/* Returns 1 if str matches suffix (case insensitive).    */
/* Str may contain trailing whitespace, but nothing else. */
static int detectsuffix(const char* str, const char* suffix) {
    /* scan pairwise through strings until mismatch detected */
    while (toupper(*str) == toupper(*suffix)) {
        /* printf("'%c' '%c'\n", *str, *suffix); */

        /* return 1 (success) if match persists until the string terminator */
        if (*str == '\0')
            return 1;

        /* next chars */
        str++;
        suffix++;
    }
    /* printf("'%c' '%c' mismatch\n", *str, *suffix); */

    /* return 0 (fail) if the matching did not consume the entire suffix */
    if (*suffix != 0)
        return 0; /* failed to consume entire suffix */

    /* skip any remaining whitespace in str */
    while (isspace(*str))
        str++;

    /* return 1 (success) if we have reached end of str else return 0 (fail) */
    return (*str == '\0') ? 1 : 0;
}

static int arg_int_scanfn(struct arg_int* parent, const char* argval) {
    int errorcode = 0;

    if (parent->count == parent->hdr.maxcount) {
        /* maximum number of arguments exceeded */
        errorcode = ARG_ERR_MAXCOUNT;
    } else if (!argval) {
        /* a valid argument with no argument value was given. */
        /* This happens when an optional argument value was invoked. */
        /* leave parent arguiment value unaltered but still count the argument. */
        parent->count++;
    } else {
        long int val;
        const char* end;

        /* attempt to extract hex integer (eg: +0x123) from argval into val conversion */
        val = strtol0X(argval, &end, 'X', 16);
        if (end == argval) {
            /* hex failed, attempt octal conversion (eg +0o123) */
            val = strtol0X(argval, &end, 'O', 8);
            if (end == argval) {
                /* octal failed, attempt binary conversion (eg +0B101) */
                val = strtol0X(argval, &end, 'B', 2);
                if (end == argval) {
                    /* binary failed, attempt decimal conversion with no prefix (eg 1234) */
                    val = strtol(argval, (char**)&end, 10);
                    if (end == argval) {
                        /* all supported number formats failed */
                        return ARG_ERR_BADINT;
                    }
                }
            }
        }

        /* Safety check for integer overflow. WARNING: this check    */
        /* achieves nothing on machines where size(int)==size(long). */
        if (val > INT_MAX || val < INT_MIN)
            errorcode = ARG_ERR_OVERFLOW;

        /* Detect any suffixes (KB,MB,GB) and multiply argument value appropriately. */
        /* We need to be mindful of integer overflows when using such big numbers.   */
        if (detectsuffix(end, "KB")) /* kilobytes */
        {
            if (val > (INT_MAX / 1024) || val < (INT_MIN / 1024))
                errorcode = ARG_ERR_OVERFLOW; /* Overflow would occur if we proceed */
            else
                val *= 1024;                /* 1KB = 1024 */
        } else if (detectsuffix(end, "MB")) /* megabytes */
        {
            if (val > (INT_MAX / 1048576) || val < (INT_MIN / 1048576))
                errorcode = ARG_ERR_OVERFLOW; /* Overflow would occur if we proceed */
            else
                val *= 1048576;             /* 1MB = 1024*1024 */
        } else if (detectsuffix(end, "GB")) /* gigabytes */
        {
            if (val > (INT_MAX / 1073741824) || val < (INT_MIN / 1073741824))
                errorcode = ARG_ERR_OVERFLOW; /* Overflow would occur if we proceed */
            else
                val *= 1073741824; /* 1GB = 1024*1024*1024 */
        } else if (!detectsuffix(end, ""))
            errorcode = ARG_ERR_BADINT; /* invalid suffix detected */

        /* if success then store result in parent->ival[] array */
        if (errorcode == 0)
            parent->ival[parent->count++] = (int)val;
    }

    /* printf("%s:scanfn(%p,%p) returns %d\n",__FILE__,parent,argval,errorcode); */
    return errorcode;
}

static int arg_int_checkfn(struct arg_int* parent) {
    int errorcode = (parent->count < parent->hdr.mincount) ? ARG_ERR_MINCOUNT : 0;
    /*printf("%s:checkfn(%p) returns %d\n",__FILE__,parent,errorcode);*/
    return errorcode;
}

static void arg_int_errorfn(struct arg_int* parent, arg_dstr_t ds, int errorcode, const char* argval, const char* progname) {
    const char* shortopts = parent->hdr.shortopts;
    const char* longopts = parent->hdr.longopts;
    const char* datatype = parent->hdr.datatype;

    /* make argval NULL safe */
    argval = argval ? argval : "";

    arg_dstr_catf(ds, "%s: ", progname);
    switch (errorcode) {
        case ARG_ERR_MINCOUNT:
            arg_dstr_cat(ds, "missing option ");
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;

        case ARG_ERR_MAXCOUNT:
            arg_dstr_cat(ds, "excess option ");
            arg_print_option_ds(ds, shortopts, longopts, argval, "\n");
            break;

        case ARG_ERR_BADINT:
            arg_dstr_catf(ds, "invalid argument \"%s\" to option ", argval);
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;

        case ARG_ERR_OVERFLOW:
            arg_dstr_cat(ds, "integer overflow at option ");
            arg_print_option_ds(ds, shortopts, longopts, datatype, " ");
            arg_dstr_catf(ds, "(%s is too large)\n", argval);
            break;
    }
}

struct arg_int* arg_int0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_intn(shortopts, longopts, datatype, 0, 1, glossary);
}

struct arg_int* arg_int1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_intn(shortopts, longopts, datatype, 1, 1, glossary);
}

struct arg_int* arg_intn(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary) {
    size_t nbytes;
    struct arg_int* result;

    /* foolproof things by ensuring maxcount is not less than mincount */
    maxcount = (maxcount < mincount) ? mincount : maxcount;

    nbytes = sizeof(struct arg_int)    /* storage for struct arg_int */
             + maxcount * sizeof(int); /* storage for ival[maxcount] array */

    result = (struct arg_int*)xmalloc(nbytes);

    /* init the arg_hdr struct */
    result->hdr.flag = ARG_HASVALUE;
    result->hdr.shortopts = shortopts;
    result->hdr.longopts = longopts;
    result->hdr.datatype = datatype ? datatype : "<int>";
    result->hdr.glossary = glossary;
    result->hdr.mincount = mincount;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_int_resetfn;
    result->hdr.scanfn = (arg_scanfn*)arg_int_scanfn;
    result->hdr.checkfn = (arg_checkfn*)arg_int_checkfn;
    result->hdr.errorfn = (arg_errorfn*)arg_int_errorfn;

    /* store the ival[maxcount] array immediately after the arg_int struct */
    result->ival = (int*)(result + 1);
    result->count = 0;

    ARG_TRACE(("arg_intn() returns %p\n", result));
    return result;
}
/*******************************************************************************
 * arg_lit: Implements the literature command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>

static void arg_lit_resetfn(struct arg_lit* parent) {
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    parent->count = 0;
}

static int arg_lit_scanfn(struct arg_lit* parent, const char* argval) {
    int errorcode = 0;
    if (parent->count < parent->hdr.maxcount)
        parent->count++;
    else
        errorcode = ARG_ERR_MAXCOUNT;

    ARG_TRACE(("%s:scanfn(%p,%s) returns %d\n", __FILE__, parent, argval, errorcode));
    return errorcode;
}

static int arg_lit_checkfn(struct arg_lit* parent) {
    int errorcode = (parent->count < parent->hdr.mincount) ? ARG_ERR_MINCOUNT : 0;
    ARG_TRACE(("%s:checkfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static void arg_lit_errorfn(struct arg_lit* parent, arg_dstr_t ds, int errorcode, const char* argval, const char* progname) {
    const char* shortopts = parent->hdr.shortopts;
    const char* longopts = parent->hdr.longopts;
    const char* datatype = parent->hdr.datatype;

    switch (errorcode) {
        case ARG_ERR_MINCOUNT:
            arg_dstr_catf(ds, "%s: missing option ", progname);
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            arg_dstr_cat(ds, "\n");
            break;

        case ARG_ERR_MAXCOUNT:
            arg_dstr_catf(ds, "%s: extraneous option ", progname);
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;
    }

    ARG_TRACE(("%s:errorfn(%p, %p, %d, %s, %s)\n", __FILE__, parent, ds, errorcode, argval, progname));
}

struct arg_lit* arg_lit0(const char* shortopts, const char* longopts, const char* glossary) {
    return arg_litn(shortopts, longopts, 0, 1, glossary);
}

struct arg_lit* arg_lit1(const char* shortopts, const char* longopts, const char* glossary) {
    return arg_litn(shortopts, longopts, 1, 1, glossary);
}

struct arg_lit* arg_litn(const char* shortopts, const char* longopts, int mincount, int maxcount, const char* glossary) {
    struct arg_lit* result;

    /* foolproof things by ensuring maxcount is not less than mincount */
    maxcount = (maxcount < mincount) ? mincount : maxcount;

    result = (struct arg_lit*)xmalloc(sizeof(struct arg_lit));

    /* init the arg_hdr struct */
    result->hdr.flag = 0;
    result->hdr.shortopts = shortopts;
    result->hdr.longopts = longopts;
    result->hdr.datatype = NULL;
    result->hdr.glossary = glossary;
    result->hdr.mincount = mincount;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_lit_resetfn;
    result->hdr.scanfn = (arg_scanfn*)arg_lit_scanfn;
    result->hdr.checkfn = (arg_checkfn*)arg_lit_checkfn;
    result->hdr.errorfn = (arg_errorfn*)arg_lit_errorfn;

    /* init local variables */
    result->count = 0;

    ARG_TRACE(("arg_litn() returns %p\n", result));
    return result;
}
/*******************************************************************************
 * arg_rem: Implements the rem command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>

struct arg_rem* arg_rem(const char* datatype, const char* glossary) {
    struct arg_rem* result = (struct arg_rem*)xmalloc(sizeof(struct arg_rem));

    result->hdr.flag = 0;
    result->hdr.shortopts = NULL;
    result->hdr.longopts = NULL;
    result->hdr.datatype = datatype;
    result->hdr.glossary = glossary;
    result->hdr.mincount = 1;
    result->hdr.maxcount = 1;
    result->hdr.parent = result;
    result->hdr.resetfn = NULL;
    result->hdr.scanfn = NULL;
    result->hdr.checkfn = NULL;
    result->hdr.errorfn = NULL;

    ARG_TRACE(("arg_rem() returns %p\n", result));
    return result;
}
/*******************************************************************************
 * arg_rex: Implements the regex command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifndef _TREX_H_
#define _TREX_H_

/*
 * This module uses the T-Rex regular expression library to implement the regex
 * logic. Here is the copyright notice of the library:
 *
 * Copyright (C) 2003-2006 Alberto Demichelis
 *
 * This software is provided 'as-is', without any express
 * or implied warranty. In no event will the authors be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for
 * any purpose, including commercial applications, and to alter
 * it and redistribute it freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented;
 *      you must not claim that you wrote the original software.
 *      If you use this software in a product, an acknowledgment
 *      in the product documentation would be appreciated but
 *      is not required.
 *
 *   2. Altered source versions must be plainly marked as such,
 *      and must not be misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any
 *      source distribution.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define TRexChar char
#define MAX_CHAR 0xFF
#define _TREXC(c) (c)
#define trex_strlen strlen
#define trex_printf printf

#ifndef TREX_API
#define TREX_API extern
#endif

#define TRex_True 1
#define TRex_False 0

#define TREX_ICASE ARG_REX_ICASE

typedef unsigned int TRexBool;
typedef struct TRex TRex;

typedef struct {
    const TRexChar* begin;
    int len;
} TRexMatch;

TREX_API TRex* trex_compile(const TRexChar* pattern, const TRexChar** error, int flags);
TREX_API void trex_free(TRex* exp);
TREX_API TRexBool trex_match(TRex* exp, const TRexChar* text);
TREX_API TRexBool trex_search(TRex* exp, const TRexChar* text, const TRexChar** out_begin, const TRexChar** out_end);
TREX_API TRexBool
trex_searchrange(TRex* exp, const TRexChar* text_begin, const TRexChar* text_end, const TRexChar** out_begin, const TRexChar** out_end);
TREX_API int trex_getsubexpcount(TRex* exp);
TREX_API TRexBool trex_getsubexp(TRex* exp, int n, TRexMatch* subexp);

#ifdef __cplusplus
}
#endif

#endif

struct privhdr {
    const char* pattern;
    int flags;
};

static void arg_rex_resetfn(struct arg_rex* parent) {
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    parent->count = 0;
}

static int arg_rex_scanfn(struct arg_rex* parent, const char* argval) {
    int errorcode = 0;
    const TRexChar* error = NULL;
    TRex* rex = NULL;
    TRexBool is_match = TRex_False;

    if (parent->count == parent->hdr.maxcount) {
        /* maximum number of arguments exceeded */
        errorcode = ARG_ERR_MAXCOUNT;
    } else if (!argval) {
        /* a valid argument with no argument value was given. */
        /* This happens when an optional argument value was invoked. */
        /* leave parent argument value unaltered but still count the argument. */
        parent->count++;
    } else {
        struct privhdr* priv = (struct privhdr*)parent->hdr.priv;

        /* test the current argument value for a match with the regular expression */
        /* if a match is detected, record the argument value in the arg_rex struct */

        rex = trex_compile(priv->pattern, &error, priv->flags);
        is_match = trex_match(rex, argval);
        if (!is_match)
            errorcode = ARG_ERR_REGNOMATCH;
        else
            parent->sval[parent->count++] = argval;

        trex_free(rex);
    }

    ARG_TRACE(("%s:scanfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static int arg_rex_checkfn(struct arg_rex* parent) {
    int errorcode = (parent->count < parent->hdr.mincount) ? ARG_ERR_MINCOUNT : 0;
#if 0
    struct privhdr *priv = (struct privhdr*)parent->hdr.priv;

    /* free the regex "program" we constructed in resetfn */
    regfree(&(priv->regex));

    /*printf("%s:checkfn(%p) returns %d\n",__FILE__,parent,errorcode);*/
#endif
    return errorcode;
}

static void arg_rex_errorfn(struct arg_rex* parent, arg_dstr_t ds, int errorcode, const char* argval, const char* progname) {
    const char* shortopts = parent->hdr.shortopts;
    const char* longopts = parent->hdr.longopts;
    const char* datatype = parent->hdr.datatype;

    /* make argval NULL safe */
    argval = argval ? argval : "";

    arg_dstr_catf(ds, "%s: ", progname);
    switch (errorcode) {
        case ARG_ERR_MINCOUNT:
            arg_dstr_cat(ds, "missing option ");
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;

        case ARG_ERR_MAXCOUNT:
            arg_dstr_cat(ds, "excess option ");
            arg_print_option_ds(ds, shortopts, longopts, argval, "\n");
            break;

        case ARG_ERR_REGNOMATCH:
            arg_dstr_cat(ds, "illegal value  ");
            arg_print_option_ds(ds, shortopts, longopts, argval, "\n");
            break;

        default: {
        #if 0
            char errbuff[256];
            regerror(errorcode, NULL, errbuff, sizeof(errbuff));
            printf("%s\n", errbuff);
        #endif
        } break;
    }
}

struct arg_rex* arg_rex0(const char* shortopts, const char* longopts, const char* pattern, const char* datatype, int flags, const char* glossary) {
    return arg_rexn(shortopts, longopts, pattern, datatype, 0, 1, flags, glossary);
}

struct arg_rex* arg_rex1(const char* shortopts, const char* longopts, const char* pattern, const char* datatype, int flags, const char* glossary) {
    return arg_rexn(shortopts, longopts, pattern, datatype, 1, 1, flags, glossary);
}

struct arg_rex* arg_rexn(const char* shortopts,
                         const char* longopts,
                         const char* pattern,
                         const char* datatype,
                         int mincount,
                         int maxcount,
                         int flags,
                         const char* glossary) {
    size_t nbytes;
    struct arg_rex* result;
    struct privhdr* priv;
    int i;
    const TRexChar* error = NULL;
    TRex* rex = NULL;

    if (!pattern) {
        printf("argtable: ERROR - illegal regular expression pattern \"(NULL)\"\n");
        printf("argtable: Bad argument table.\n");
        return NULL;
    }

    /* foolproof things by ensuring maxcount is not less than mincount */
    maxcount = (maxcount < mincount) ? mincount : maxcount;

    nbytes = sizeof(struct arg_rex)      /* storage for struct arg_rex */
             + sizeof(struct privhdr)    /* storage for private arg_rex data */
             + maxcount * sizeof(char*); /* storage for sval[maxcount] array */

    /* init the arg_hdr struct */
    result = (struct arg_rex*)xmalloc(nbytes);
    result->hdr.flag = ARG_HASVALUE;
    result->hdr.shortopts = shortopts;
    result->hdr.longopts = longopts;
    result->hdr.datatype = datatype ? datatype : pattern;
    result->hdr.glossary = glossary;
    result->hdr.mincount = mincount;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_rex_resetfn;
    result->hdr.scanfn = (arg_scanfn*)arg_rex_scanfn;
    result->hdr.checkfn = (arg_checkfn*)arg_rex_checkfn;
    result->hdr.errorfn = (arg_errorfn*)arg_rex_errorfn;

    /* store the arg_rex_priv struct immediately after the arg_rex struct */
    result->hdr.priv = result + 1;
    priv = (struct privhdr*)(result->hdr.priv);
    priv->pattern = pattern;
    priv->flags = flags;

    /* store the sval[maxcount] array immediately after the arg_rex_priv struct */
    result->sval = (const char**)(priv + 1);
    result->count = 0;

    /* foolproof the string pointers by initializing them to reference empty strings */
    for (i = 0; i < maxcount; i++)
        result->sval[i] = "";

    /* here we construct and destroy a regex representation of the regular
     * expression for no other reason than to force any regex errors to be
     * trapped now rather than later. If we don't, then errors may go undetected
     * until an argument is actually parsed.
     */

    rex = trex_compile(priv->pattern, &error, priv->flags);
    if (rex == NULL) {
        ARG_LOG(("argtable: %s \"%s\"\n", error ? error : _TREXC("undefined"), priv->pattern));
        ARG_LOG(("argtable: Bad argument table.\n"));
    }

    trex_free(rex);

    ARG_TRACE(("arg_rexn() returns %p\n", result));
    return result;
}

/* see copyright notice in trex.h */
#include <ctype.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#ifdef _UINCODE
#define scisprint iswprint
#define scstrlen wcslen
#define scprintf wprintf
#define _SC(x) L(x)
#else
#define scisprint isprint
#define scstrlen strlen
#define scprintf printf
#define _SC(x) (x)
#endif

#ifdef _DEBUG
#include <stdio.h>

static const TRexChar* g_nnames[] = {_SC("NONE"),    _SC("OP_GREEDY"), _SC("OP_OR"),     _SC("OP_EXPR"),   _SC("OP_NOCAPEXPR"),
                                     _SC("OP_DOT"),  _SC("OP_CLASS"),  _SC("OP_CCLASS"), _SC("OP_NCLASS"), _SC("OP_RANGE"),
                                     _SC("OP_CHAR"), _SC("OP_EOL"),    _SC("OP_BOL"),    _SC("OP_WB")};

#endif
#define OP_GREEDY (MAX_CHAR + 1)  /*  * + ? {n} */
#define OP_OR (MAX_CHAR + 2)
#define OP_EXPR (MAX_CHAR + 3)       /* parentesis () */
#define OP_NOCAPEXPR (MAX_CHAR + 4)  /* parentesis (?:) */
#define OP_DOT (MAX_CHAR + 5)
#define OP_CLASS (MAX_CHAR + 6)
#define OP_CCLASS (MAX_CHAR + 7)
#define OP_NCLASS (MAX_CHAR + 8)  /* negates class the [^ */
#define OP_RANGE (MAX_CHAR + 9)
#define OP_CHAR (MAX_CHAR + 10)
#define OP_EOL (MAX_CHAR + 11)
#define OP_BOL (MAX_CHAR + 12)
#define OP_WB (MAX_CHAR + 13)

#define TREX_SYMBOL_ANY_CHAR ('.')
#define TREX_SYMBOL_GREEDY_ONE_OR_MORE ('+')
#define TREX_SYMBOL_GREEDY_ZERO_OR_MORE ('*')
#define TREX_SYMBOL_GREEDY_ZERO_OR_ONE ('?')
#define TREX_SYMBOL_BRANCH ('|')
#define TREX_SYMBOL_END_OF_STRING ('$')
#define TREX_SYMBOL_BEGINNING_OF_STRING ('^')
#define TREX_SYMBOL_ESCAPE_CHAR ('\\')

typedef int TRexNodeType;

typedef struct tagTRexNode {
    TRexNodeType type;
    int left;
    int right;
    int next;
} TRexNode;

struct TRex {
    const TRexChar* _eol;
    const TRexChar* _bol;
    const TRexChar* _p;
    int _first;
    int _op;
    TRexNode* _nodes;
    int _nallocated;
    int _nsize;
    int _nsubexpr;
    TRexMatch* _matches;
    int _currsubexp;
    void* _jmpbuf;
    const TRexChar** _error;
    int _flags;
};

static int trex_list(TRex* exp);

static int trex_newnode(TRex* exp, TRexNodeType type) {
    TRexNode n;
    int newid;
    n.type = type;
    n.next = n.right = n.left = -1;
    if (type == OP_EXPR)
        n.right = exp->_nsubexpr++;
    if (exp->_nallocated < (exp->_nsize + 1)) {
        exp->_nallocated *= 2;
        exp->_nodes = (TRexNode*)xrealloc(exp->_nodes, exp->_nallocated * sizeof(TRexNode));
    }
    exp->_nodes[exp->_nsize++] = n;
    newid = exp->_nsize - 1;
    return (int)newid;
}

static void trex_error(TRex* exp, const TRexChar* error) {
    if (exp->_error)
        *exp->_error = error;
    longjmp(*((jmp_buf*)exp->_jmpbuf), -1);
}

static void trex_expect(TRex* exp, int n) {
    if ((*exp->_p) != n)
        trex_error(exp, _SC("expected paren"));
    exp->_p++;
}

static TRexChar trex_escapechar(TRex* exp) {
    if (*exp->_p == TREX_SYMBOL_ESCAPE_CHAR) {
        exp->_p++;
        switch (*exp->_p) {
            case 'v':
                exp->_p++;
                return '\v';
            case 'n':
                exp->_p++;
                return '\n';
            case 't':
                exp->_p++;
                return '\t';
            case 'r':
                exp->_p++;
                return '\r';
            case 'f':
                exp->_p++;
                return '\f';
            default:
                return (*exp->_p++);
        }
    } else if (!scisprint(*exp->_p))
        trex_error(exp, _SC("letter expected"));
    return (*exp->_p++);
}

static int trex_charclass(TRex* exp, int classid) {
    int n = trex_newnode(exp, OP_CCLASS);
    exp->_nodes[n].left = classid;
    return n;
}

static int trex_charnode(TRex* exp, TRexBool isclass) {
    TRexChar t;
    if (*exp->_p == TREX_SYMBOL_ESCAPE_CHAR) {
        exp->_p++;
        switch (*exp->_p) {
            case 'n':
                exp->_p++;
                return trex_newnode(exp, '\n');
            case 't':
                exp->_p++;
                return trex_newnode(exp, '\t');
            case 'r':
                exp->_p++;
                return trex_newnode(exp, '\r');
            case 'f':
                exp->_p++;
                return trex_newnode(exp, '\f');
            case 'v':
                exp->_p++;
                return trex_newnode(exp, '\v');
            case 'a':
            case 'A':
            case 'w':
            case 'W':
            case 's':
            case 'S':
            case 'd':
            case 'D':
            case 'x':
            case 'X':
            case 'c':
            case 'C':
            case 'p':
            case 'P':
            case 'l':
            case 'u': {
                t = *exp->_p;
                exp->_p++;
                return trex_charclass(exp, t);
            }
            case 'b':
            case 'B':
                if (!isclass) {
                    int node = trex_newnode(exp, OP_WB);
                    exp->_nodes[node].left = *exp->_p;
                    exp->_p++;
                    return node;
                }
                /* fall through */
            default:
                t = *exp->_p;
                exp->_p++;
                return trex_newnode(exp, t);
        }
    } else if (!scisprint(*exp->_p)) {
        trex_error(exp, _SC("letter expected"));
    }
    t = *exp->_p;
    exp->_p++;
    return trex_newnode(exp, t);
}
static int trex_class(TRex* exp) {
    int ret = -1;
    int first = -1, chain;
    if (*exp->_p == TREX_SYMBOL_BEGINNING_OF_STRING) {
        ret = trex_newnode(exp, OP_NCLASS);
        exp->_p++;
    } else
        ret = trex_newnode(exp, OP_CLASS);

    if (*exp->_p == ']')
        trex_error(exp, _SC("empty class"));
    chain = ret;
    while (*exp->_p != ']' && exp->_p != exp->_eol) {
        if (*exp->_p == '-' && first != -1) {
            int r, t;
            if (*exp->_p++ == ']')
                trex_error(exp, _SC("unfinished range"));
            r = trex_newnode(exp, OP_RANGE);
            if (first > *exp->_p)
                trex_error(exp, _SC("invalid range"));
            if (exp->_nodes[first].type == OP_CCLASS)
                trex_error(exp, _SC("cannot use character classes in ranges"));
            exp->_nodes[r].left = exp->_nodes[first].type;
            t = trex_escapechar(exp);
            exp->_nodes[r].right = t;
            exp->_nodes[chain].next = r;
            chain = r;
            first = -1;
        } else {
            if (first != -1) {
                int c = first;
                exp->_nodes[chain].next = c;
                chain = c;
                first = trex_charnode(exp, TRex_True);
            } else {
                first = trex_charnode(exp, TRex_True);
            }
        }
    }
    if (first != -1) {
        int c = first;
        exp->_nodes[chain].next = c;
        chain = c;
        first = -1;
    }
    /* hack? */
    exp->_nodes[ret].left = exp->_nodes[ret].next;
    exp->_nodes[ret].next = -1;
    return ret;
}

static int trex_parsenumber(TRex* exp) {
    int ret = *exp->_p - '0';
    int positions = 10;
    exp->_p++;
    while (isdigit(*exp->_p)) {
        ret = ret * 10 + (*exp->_p++ - '0');
        if (positions == 1000000000)
            trex_error(exp, _SC("overflow in numeric constant"));
        positions *= 10;
    };
    return ret;
}

static int trex_element(TRex* exp) {
    int ret = -1;
    switch (*exp->_p) {
        case '(': {
            int expr, newn;
            exp->_p++;

            if (*exp->_p == '?') {
                exp->_p++;
                trex_expect(exp, ':');
                expr = trex_newnode(exp, OP_NOCAPEXPR);
            } else
                expr = trex_newnode(exp, OP_EXPR);
            newn = trex_list(exp);
            exp->_nodes[expr].left = newn;
            ret = expr;
            trex_expect(exp, ')');
        } break;
        case '[':
            exp->_p++;
            ret = trex_class(exp);
            trex_expect(exp, ']');
            break;
        case TREX_SYMBOL_END_OF_STRING:
            exp->_p++;
            ret = trex_newnode(exp, OP_EOL);
            break;
        case TREX_SYMBOL_ANY_CHAR:
            exp->_p++;
            ret = trex_newnode(exp, OP_DOT);
            break;
        default:
            ret = trex_charnode(exp, TRex_False);
            break;
    }

    {
        TRexBool isgreedy = TRex_False;
        unsigned short p0 = 0, p1 = 0;
        switch (*exp->_p) {
            case TREX_SYMBOL_GREEDY_ZERO_OR_MORE:
                p0 = 0;
                p1 = 0xFFFF;
                exp->_p++;
                isgreedy = TRex_True;
                break;
            case TREX_SYMBOL_GREEDY_ONE_OR_MORE:
                p0 = 1;
                p1 = 0xFFFF;
                exp->_p++;
                isgreedy = TRex_True;
                break;
            case TREX_SYMBOL_GREEDY_ZERO_OR_ONE:
                p0 = 0;
                p1 = 1;
                exp->_p++;
                isgreedy = TRex_True;
                break;
            case '{':
                exp->_p++;
                if (!isdigit(*exp->_p))
                    trex_error(exp, _SC("number expected"));
                p0 = (unsigned short)trex_parsenumber(exp);
                /*******************************/
                switch (*exp->_p) {
                    case '}':
                        p1 = p0;
                        exp->_p++;
                        break;
                    case ',':
                        exp->_p++;
                        p1 = 0xFFFF;
                        if (isdigit(*exp->_p)) {
                            p1 = (unsigned short)trex_parsenumber(exp);
                        }
                        trex_expect(exp, '}');
                        break;
                    default:
                        trex_error(exp, _SC(", or } expected"));
                }
                /*******************************/
                isgreedy = TRex_True;
                break;
        }
        if (isgreedy) {
            int nnode = trex_newnode(exp, OP_GREEDY);
            exp->_nodes[nnode].left = ret;
            exp->_nodes[nnode].right = ((p0) << 16) | p1;
            ret = nnode;
        }
    }
    if ((*exp->_p != TREX_SYMBOL_BRANCH) && (*exp->_p != ')') && (*exp->_p != TREX_SYMBOL_GREEDY_ZERO_OR_MORE) &&
        (*exp->_p != TREX_SYMBOL_GREEDY_ONE_OR_MORE) && (*exp->_p != '\0')) {
        int nnode = trex_element(exp);
        exp->_nodes[ret].next = nnode;
    }

    return ret;
}

static int trex_list(TRex* exp) {
    int ret = -1, e;
    if (*exp->_p == TREX_SYMBOL_BEGINNING_OF_STRING) {
        exp->_p++;
        ret = trex_newnode(exp, OP_BOL);
    }
    e = trex_element(exp);
    if (ret != -1) {
        exp->_nodes[ret].next = e;
    } else
        ret = e;

    if (*exp->_p == TREX_SYMBOL_BRANCH) {
        int temp, tright;
        exp->_p++;
        temp = trex_newnode(exp, OP_OR);
        exp->_nodes[temp].left = ret;
        tright = trex_list(exp);
        exp->_nodes[temp].right = tright;
        ret = temp;
    }
    return ret;
}

static TRexBool trex_matchcclass(int cclass, TRexChar c) {
    switch (cclass) {
        case 'a':
            return isalpha(c) ? TRex_True : TRex_False;
        case 'A':
            return !isalpha(c) ? TRex_True : TRex_False;
        case 'w':
            return (isalnum(c) || c == '_') ? TRex_True : TRex_False;
        case 'W':
            return (!isalnum(c) && c != '_') ? TRex_True : TRex_False;
        case 's':
            return isspace(c) ? TRex_True : TRex_False;
        case 'S':
            return !isspace(c) ? TRex_True : TRex_False;
        case 'd':
            return isdigit(c) ? TRex_True : TRex_False;
        case 'D':
            return !isdigit(c) ? TRex_True : TRex_False;
        case 'x':
            return isxdigit(c) ? TRex_True : TRex_False;
        case 'X':
            return !isxdigit(c) ? TRex_True : TRex_False;
        case 'c':
            return iscntrl(c) ? TRex_True : TRex_False;
        case 'C':
            return !iscntrl(c) ? TRex_True : TRex_False;
        case 'p':
            return ispunct(c) ? TRex_True : TRex_False;
        case 'P':
            return !ispunct(c) ? TRex_True : TRex_False;
        case 'l':
            return islower(c) ? TRex_True : TRex_False;
        case 'u':
            return isupper(c) ? TRex_True : TRex_False;
    }
    return TRex_False; /*cannot happen*/
}

static TRexBool trex_matchclass(TRex* exp, TRexNode* node, TRexChar c) {
    do {
        switch (node->type) {
            case OP_RANGE:
                if (exp->_flags & TREX_ICASE) {
                    if (c >= toupper(node->left) && c <= toupper(node->right))
                        return TRex_True;
                    if (c >= tolower(node->left) && c <= tolower(node->right))
                        return TRex_True;
                } else {
                    if (c >= node->left && c <= node->right)
                        return TRex_True;
                }
                break;
            case OP_CCLASS:
                if (trex_matchcclass(node->left, c))
                    return TRex_True;
                break;
            default:
                if (exp->_flags & TREX_ICASE) {
                    if (c == tolower(node->type) || c == toupper(node->type))
                        return TRex_True;
                } else {
                    if (c == node->type)
                        return TRex_True;
                }
        }
    } while ((node->next != -1) && ((node = &exp->_nodes[node->next]) != NULL));
    return TRex_False;
}

static const TRexChar* trex_matchnode(TRex* exp, TRexNode* node, const TRexChar* str, TRexNode* next) {
    TRexNodeType type = node->type;
    switch (type) {
        case OP_GREEDY: {
            /* TRexNode *greedystop = (node->next != -1) ? &exp->_nodes[node->next] : NULL; */
            TRexNode* greedystop = NULL;
            int p0 = (node->right >> 16) & 0x0000FFFF, p1 = node->right & 0x0000FFFF, nmaches = 0;
            const TRexChar *s = str, *good = str;

            if (node->next != -1) {
                greedystop = &exp->_nodes[node->next];
            } else {
                greedystop = next;
            }

            while ((nmaches == 0xFFFF || nmaches < p1)) {
                const TRexChar* stop;
                if ((s = trex_matchnode(exp, &exp->_nodes[node->left], s, greedystop)) == NULL)
                    break;
                nmaches++;
                good = s;
                if (greedystop) {
                    /* checks that 0 matches satisfy the expression(if so skips) */
                    /* if not would always stop(for instance if is a '?') */
                    if (greedystop->type != OP_GREEDY || (greedystop->type == OP_GREEDY && ((greedystop->right >> 16) & 0x0000FFFF) != 0)) {
                        TRexNode* gnext = NULL;
                        if (greedystop->next != -1) {
                            gnext = &exp->_nodes[greedystop->next];
                        } else if (next && next->next != -1) {
                            gnext = &exp->_nodes[next->next];
                        }
                        stop = trex_matchnode(exp, greedystop, s, gnext);
                        if (stop) {
                            /* if satisfied stop it */
                            if (p0 == p1 && p0 == nmaches)
                                break;
                            else if (nmaches >= p0 && p1 == 0xFFFF)
                                break;
                            else if (nmaches >= p0 && nmaches <= p1)
                                break;
                        }
                    }
                }

                if (s >= exp->_eol)
                    break;
            }
            if (p0 == p1 && p0 == nmaches)
                return good;
            else if (nmaches >= p0 && p1 == 0xFFFF)
                return good;
            else if (nmaches >= p0 && nmaches <= p1)
                return good;
            return NULL;
        }
        case OP_OR: {
            const TRexChar* asd = str;
            TRexNode* temp = &exp->_nodes[node->left];
            while ((asd = trex_matchnode(exp, temp, asd, NULL)) != NULL) {
                if (temp->next != -1)
                    temp = &exp->_nodes[temp->next];
                else
                    return asd;
            }
            asd = str;
            temp = &exp->_nodes[node->right];
            while ((asd = trex_matchnode(exp, temp, asd, NULL)) != NULL) {
                if (temp->next != -1)
                    temp = &exp->_nodes[temp->next];
                else
                    return asd;
            }
            return NULL;
            break;
        }
        case OP_EXPR:
        case OP_NOCAPEXPR: {
            TRexNode* n = &exp->_nodes[node->left];
            const TRexChar* cur = str;
            int capture = -1;
            if (node->type != OP_NOCAPEXPR && node->right == exp->_currsubexp) {
                capture = exp->_currsubexp;
                exp->_matches[capture].begin = cur;
                exp->_currsubexp++;
            }

            do {
                TRexNode* subnext = NULL;
                if (n->next != -1) {
                    subnext = &exp->_nodes[n->next];
                } else {
                    subnext = next;
                }
                if ((cur = trex_matchnode(exp, n, cur, subnext)) == NULL) {
                    if (capture != -1) {
                        exp->_matches[capture].begin = 0;
                        exp->_matches[capture].len = 0;
                    }
                    return NULL;
                }
            } while ((n->next != -1) && ((n = &exp->_nodes[n->next]) != NULL));

            if (capture != -1)
                exp->_matches[capture].len = (int)(cur - exp->_matches[capture].begin);
            return cur;
        }
        case OP_WB:
            if ((str == exp->_bol && !isspace(*str)) || (str == exp->_eol && !isspace(*(str - 1))) || (!isspace(*str) && isspace(*(str + 1))) ||
                (isspace(*str) && !isspace(*(str + 1)))) {
                return (node->left == 'b') ? str : NULL;
            }
            return (node->left == 'b') ? NULL : str;
        case OP_BOL:
            if (str == exp->_bol)
                return str;
            return NULL;
        case OP_EOL:
            if (str == exp->_eol)
                return str;
            return NULL;
        case OP_DOT: {
            str++;
        }
            return str;
        case OP_NCLASS:
        case OP_CLASS:
            if (trex_matchclass(exp, &exp->_nodes[node->left], *str) ? (type == OP_CLASS ? TRex_True : TRex_False)
                                                                     : (type == OP_NCLASS ? TRex_True : TRex_False)) {
                str++;
                return str;
            }
            return NULL;
        case OP_CCLASS:
            if (trex_matchcclass(node->left, *str)) {
                str++;
                return str;
            }
            return NULL;
        default: /* char */
            if (exp->_flags & TREX_ICASE) {
                if (*str != tolower(node->type) && *str != toupper(node->type))
                    return NULL;
            } else {
                if (*str != node->type)
                    return NULL;
            }
            str++;
            return str;
    }
}

/* public api */
TRex* trex_compile(const TRexChar* pattern, const TRexChar** error, int flags) {
    TRex* exp = (TRex*)xmalloc(sizeof(TRex));
    exp->_eol = exp->_bol = NULL;
    exp->_p = pattern;
    exp->_nallocated = (int)scstrlen(pattern) * sizeof(TRexChar);
    exp->_nodes = (TRexNode*)xmalloc(exp->_nallocated * sizeof(TRexNode));
    exp->_nsize = 0;
    exp->_matches = 0;
    exp->_nsubexpr = 0;
    exp->_first = trex_newnode(exp, OP_EXPR);
    exp->_error = error;
    exp->_jmpbuf = xmalloc(sizeof(jmp_buf));
    exp->_flags = flags;
    if (setjmp(*((jmp_buf*)exp->_jmpbuf)) == 0) {
        int res = trex_list(exp);
        exp->_nodes[exp->_first].left = res;
        if (*exp->_p != '\0')
            trex_error(exp, _SC("unexpected character"));
#ifdef _DEBUG
        {
            int nsize, i;
            TRexNode* t;
            nsize = exp->_nsize;
            t = &exp->_nodes[0];
            scprintf(_SC("\n"));
            for (i = 0; i < nsize; i++) {
                if (exp->_nodes[i].type > MAX_CHAR)
                    scprintf(_SC("[%02d] %10s "), i, g_nnames[exp->_nodes[i].type - MAX_CHAR]);
                else
                    scprintf(_SC("[%02d] %10c "), i, exp->_nodes[i].type);
                scprintf(_SC("left %02d right %02d next %02d\n"), exp->_nodes[i].left, exp->_nodes[i].right, exp->_nodes[i].next);
            }
            scprintf(_SC("\n"));
        }
#endif
        exp->_matches = (TRexMatch*)xmalloc(exp->_nsubexpr * sizeof(TRexMatch));
        memset(exp->_matches, 0, exp->_nsubexpr * sizeof(TRexMatch));
    } else {
        trex_free(exp);
        return NULL;
    }
    return exp;
}

void trex_free(TRex* exp) {
    if (exp) {
        xfree(exp->_nodes);
        xfree(exp->_jmpbuf);
        xfree(exp->_matches);
        xfree(exp);
    }
}

TRexBool trex_match(TRex* exp, const TRexChar* text) {
    const TRexChar* res = NULL;
    exp->_bol = text;
    exp->_eol = text + scstrlen(text);
    exp->_currsubexp = 0;
    res = trex_matchnode(exp, exp->_nodes, text, NULL);
    if (res == NULL || res != exp->_eol)
        return TRex_False;
    return TRex_True;
}

TRexBool trex_searchrange(TRex* exp, const TRexChar* text_begin, const TRexChar* text_end, const TRexChar** out_begin, const TRexChar** out_end) {
    const TRexChar* cur = NULL;
    int node = exp->_first;
    if (text_begin >= text_end)
        return TRex_False;
    exp->_bol = text_begin;
    exp->_eol = text_end;
    do {
        cur = text_begin;
        while (node != -1) {
            exp->_currsubexp = 0;
            cur = trex_matchnode(exp, &exp->_nodes[node], cur, NULL);
            if (!cur)
                break;
            node = exp->_nodes[node].next;
        }
        text_begin++;
    } while (cur == NULL && text_begin != text_end);

    if (cur == NULL)
        return TRex_False;

    --text_begin;

    if (out_begin)
        *out_begin = text_begin;
    if (out_end)
        *out_end = cur;
    return TRex_True;
}

TRexBool trex_search(TRex* exp, const TRexChar* text, const TRexChar** out_begin, const TRexChar** out_end) {
    return trex_searchrange(exp, text, text + scstrlen(text), out_begin, out_end);
}

int trex_getsubexpcount(TRex* exp) {
    return exp->_nsubexpr;
}

TRexBool trex_getsubexp(TRex* exp, int n, TRexMatch* subexp) {
    if (n < 0 || n >= exp->_nsubexpr)
        return TRex_False;
    *subexp = exp->_matches[n];
    return TRex_True;
}
/*******************************************************************************
 * arg_str: Implements the str command-line option
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <stdlib.h>

static void arg_str_resetfn(struct arg_str* parent) {
    int i;
    
    ARG_TRACE(("%s:resetfn(%p)\n", __FILE__, parent));
    for (i = 0; i < parent->count; i++) {
        parent->sval[i] = "";
    }
    parent->count = 0;
}

static int arg_str_scanfn(struct arg_str* parent, const char* argval) {
    int errorcode = 0;

    if (parent->count == parent->hdr.maxcount) {
        /* maximum number of arguments exceeded */
        errorcode = ARG_ERR_MAXCOUNT;
    } else if (!argval) {
        /* a valid argument with no argument value was given. */
        /* This happens when an optional argument value was invoked. */
        /* leave parent argument value unaltered but still count the argument. */
        parent->count++;
    } else {
        parent->sval[parent->count++] = argval;
    }

    ARG_TRACE(("%s:scanfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static int arg_str_checkfn(struct arg_str* parent) {
    int errorcode = (parent->count < parent->hdr.mincount) ? ARG_ERR_MINCOUNT : 0;

    ARG_TRACE(("%s:checkfn(%p) returns %d\n", __FILE__, parent, errorcode));
    return errorcode;
}

static void arg_str_errorfn(struct arg_str* parent, arg_dstr_t ds, int errorcode, const char* argval, const char* progname) {
    const char* shortopts = parent->hdr.shortopts;
    const char* longopts = parent->hdr.longopts;
    const char* datatype = parent->hdr.datatype;

    /* make argval NULL safe */
    argval = argval ? argval : "";

    arg_dstr_catf(ds, "%s: ", progname);
    switch (errorcode) {
        case ARG_ERR_MINCOUNT:
            arg_dstr_cat(ds, "missing option ");
            arg_print_option_ds(ds, shortopts, longopts, datatype, "\n");
            break;

        case ARG_ERR_MAXCOUNT:
            arg_dstr_cat(ds, "excess option ");
            arg_print_option_ds(ds, shortopts, longopts, argval, "\n");
            break;
    }
}

struct arg_str* arg_str0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_strn(shortopts, longopts, datatype, 0, 1, glossary);
}

struct arg_str* arg_str1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary) {
    return arg_strn(shortopts, longopts, datatype, 1, 1, glossary);
}

struct arg_str* arg_strn(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary) {
    size_t nbytes;
    struct arg_str* result;
    int i;

    /* should not allow this stupid error */
    /* we should return an error code warning this logic error */
    /* foolproof things by ensuring maxcount is not less than mincount */
    maxcount = (maxcount < mincount) ? mincount : maxcount;

    nbytes = sizeof(struct arg_str)      /* storage for struct arg_str */
             + maxcount * sizeof(char*); /* storage for sval[maxcount] array */

    result = (struct arg_str*)xmalloc(nbytes);

    /* init the arg_hdr struct */
    result->hdr.flag = ARG_HASVALUE;
    result->hdr.shortopts = shortopts;
    result->hdr.longopts = longopts;
    result->hdr.datatype = datatype ? datatype : "<string>";
    result->hdr.glossary = glossary;
    result->hdr.mincount = mincount;
    result->hdr.maxcount = maxcount;
    result->hdr.parent = result;
    result->hdr.resetfn = (arg_resetfn*)arg_str_resetfn;
    result->hdr.scanfn = (arg_scanfn*)arg_str_scanfn;
    result->hdr.checkfn = (arg_checkfn*)arg_str_checkfn;
    result->hdr.errorfn = (arg_errorfn*)arg_str_errorfn;

    /* store the sval[maxcount] array immediately after the arg_str struct */
    result->sval = (const char**)(result + 1);
    result->count = 0;

    /* foolproof the string pointers by initializing them to reference empty strings */
    for (i = 0; i < maxcount; i++)
        result->sval[i] = "";

    ARG_TRACE(("arg_strn() returns %p\n", result));
    return result;
}
/*******************************************************************************
 * arg_cmd: Provides the sub-command mechanism
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 2013-2019 Tom G. Huang
 * <tomghuang@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MODULE_VERSION_SIZE 128

static arg_hashtable_t* s_hashtable = NULL;
static char* s_module_name = NULL;
static int s_mod_ver_major = 0;
static int s_mod_ver_minor = 0;
static int s_mod_ver_patch = 0;
static char* s_mod_ver_tag = NULL;
static char* s_mod_ver = NULL;

void arg_set_module_name(const char* name) {
    size_t slen;

    xfree(s_module_name);
    slen = strlen(name);
    s_module_name = (char*)xmalloc(slen + 1);
    memset(s_module_name, 0, slen + 1);

#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
    strncpy_s(s_module_name, slen + 1, name, slen);
#else
    memcpy(s_module_name, name, slen);
#endif
}

void arg_set_module_version(int major, int minor, int patch, const char* tag) {
    size_t slen_tag, slen_ds;
    arg_dstr_t ds;

    s_mod_ver_major = major;
    s_mod_ver_minor = minor;
    s_mod_ver_patch = patch;

    xfree(s_mod_ver_tag);
    slen_tag = strlen(tag);
    s_mod_ver_tag = (char*)xmalloc(slen_tag + 1);
    memset(s_mod_ver_tag, 0, slen_tag + 1);

#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
    strncpy_s(s_mod_ver_tag, slen_tag + 1, tag, slen_tag);
#else
    memcpy(s_mod_ver_tag, tag, slen_tag);
#endif

    ds = arg_dstr_create();
    arg_dstr_catf(ds, "%d.", s_mod_ver_major);
    arg_dstr_catf(ds, "%d.", s_mod_ver_minor);
    arg_dstr_catf(ds, "%d.", s_mod_ver_patch);
    arg_dstr_cat(ds, s_mod_ver_tag);

    xfree(s_mod_ver);
    slen_ds = strlen(arg_dstr_cstr(ds));
    s_mod_ver = (char*)xmalloc(slen_ds + 1);
    memset(s_mod_ver, 0, slen_ds + 1);

#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
    strncpy_s(s_mod_ver, slen_ds + 1, arg_dstr_cstr(ds), slen_ds);
#else
    memcpy(s_mod_ver, arg_dstr_cstr(ds), slen_ds);
#endif

    arg_dstr_destroy(ds);
}

static unsigned int hash_key(const void* key) {
    const char* str = (const char*)key;
    int c;
    unsigned int hash = 5381;

    while ((c = *str++) != 0)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static int equal_keys(const void* key1, const void* key2) {
    char* k1 = (char*)key1;
    char* k2 = (char*)key2;
    return (0 == strcmp(k1, k2));
}

void arg_cmd_init(void) {
    s_hashtable = arg_hashtable_create(32, hash_key, equal_keys);
}

void arg_cmd_uninit(void) {
    arg_hashtable_destroy(s_hashtable, 1);
}

void arg_cmd_register(const char* name, arg_cmdfn* proc, const char* description) {
    arg_cmd_info_t* cmd_info;
    size_t slen_name;
    void* k;

    assert(strlen(name) < ARG_CMD_NAME_LEN);
    assert(strlen(description) < ARG_CMD_DESCRIPTION_LEN);

    /* Check if the command already exists. */
    /* If the command exists, replace the existing command. */
    /* If the command doesn't exist, insert the command. */
    cmd_info = (arg_cmd_info_t*)arg_hashtable_search(s_hashtable, name);
    if (cmd_info) {
        arg_hashtable_remove(s_hashtable, name);
        cmd_info = NULL;
    }

    cmd_info = (arg_cmd_info_t*)xmalloc(sizeof(arg_cmd_info_t));
    memset(cmd_info, 0, sizeof(arg_cmd_info_t));

#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
    strncpy_s(cmd_info->name, ARG_CMD_NAME_LEN, name, strlen(name));
    strncpy_s(cmd_info->description, ARG_CMD_DESCRIPTION_LEN, description, strlen(description));
#else
    memcpy(cmd_info->name, name, strlen(name));
    memcpy(cmd_info->description, description, strlen(description));
#endif

    cmd_info->proc = proc;

    slen_name = strlen(name);
    k = xmalloc(slen_name + 1);
    memset(k, 0, slen_name + 1);

#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
    strncpy_s((char*)k, slen_name + 1, name, slen_name);
#else
    memcpy((char*)k, name, slen_name);
#endif

    arg_hashtable_insert(s_hashtable, k, cmd_info);
}

void arg_cmd_unregister(const char* name) {
    arg_hashtable_remove(s_hashtable, name);
}

int arg_cmd_dispatch(const char* name, int argc, char* argv[], arg_dstr_t res) {
    arg_cmd_info_t* cmd_info = arg_cmd_info(name);

    assert(cmd_info != NULL);
    assert(cmd_info->proc != NULL);

    return cmd_info->proc(argc, argv, res);
}

arg_cmd_info_t* arg_cmd_info(const char* name) {
    return (arg_cmd_info_t*)arg_hashtable_search(s_hashtable, name);
}

unsigned int arg_cmd_count(void) {
    return arg_hashtable_count(s_hashtable);
}

arg_cmd_itr_t arg_cmd_itr_create(void) {
    return (arg_cmd_itr_t)arg_hashtable_itr_create(s_hashtable);
}

int arg_cmd_itr_advance(arg_cmd_itr_t itr) {
    return arg_hashtable_itr_advance((arg_hashtable_itr_t*)itr);
}

char* arg_cmd_itr_key(arg_cmd_itr_t itr) {
    return (char*)arg_hashtable_itr_key((arg_hashtable_itr_t*)itr);
}

arg_cmd_info_t* arg_cmd_itr_value(arg_cmd_itr_t itr) {
    return (arg_cmd_info_t*)arg_hashtable_itr_value((arg_hashtable_itr_t*)itr);
}

void arg_cmd_itr_destroy(arg_cmd_itr_t itr) {
    arg_hashtable_itr_destroy((arg_hashtable_itr_t*)itr);
}

int arg_cmd_itr_search(arg_cmd_itr_t itr, void* k) {
    return arg_hashtable_itr_search((arg_hashtable_itr_t*)itr, s_hashtable, k);
}

static const char* module_name(void) {
    if (s_module_name == NULL || strlen(s_module_name) == 0)
        return "<name>";

    return s_module_name;
}

static const char* module_version(void) {
    if (s_mod_ver == NULL || strlen(s_mod_ver) == 0)
        return "0.0.0.0";

    return s_mod_ver;
}

void arg_make_get_help_msg(arg_dstr_t res) {
    arg_dstr_catf(res, "%s v%s\n", module_name(), module_version());
    arg_dstr_catf(res, "Please type '%s help' to get more information.\n", module_name());
}

void arg_make_help_msg(arg_dstr_t ds, char* cmd_name, void** argtable) {
    arg_cmd_info_t* cmd_info = (arg_cmd_info_t*)arg_hashtable_search(s_hashtable, cmd_name);
    if (cmd_info) {
        arg_dstr_catf(ds, "%s: %s\n", cmd_name, cmd_info->description);
    }

    arg_dstr_cat(ds, "Usage:\n");
    arg_dstr_catf(ds, "  %s", module_name());

    arg_print_syntaxv_ds(ds, argtable, "\n \nAvailable options:\n");
    arg_print_glossary_ds(ds, argtable, "  %-23s %s\n");

    arg_dstr_cat(ds, "\n");
}

void arg_make_syntax_err_msg(arg_dstr_t ds, void** argtable, struct arg_end* end) {
    arg_print_errors_ds(ds, end, module_name());
    arg_dstr_cat(ds, "Usage: \n");
    arg_dstr_catf(ds, "  %s", module_name());
    arg_print_syntaxv_ds(ds, argtable, "\n");
    arg_dstr_cat(ds, "\n");
}

int arg_make_syntax_err_help_msg(arg_dstr_t ds, char* name, int help, int nerrors, void** argtable, struct arg_end* end, int* exitcode) {
    /* help handling
     * note: '-h|--help' takes precedence over error reporting
     */
    if (help > 0) {
        arg_make_help_msg(ds, name, argtable);
        *exitcode = EXIT_SUCCESS;
        return 1;
    }

    /* syntax error handling */
    if (nerrors > 0) {
        arg_make_syntax_err_msg(ds, argtable, end);
        *exitcode = EXIT_FAILURE;
        return 1;
    }

    return 0;
}
/*******************************************************************************
 * argtable3: Implements the main interfaces of the library
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "argtable3.h"

#ifndef ARG_AMALGAMATION
#include "argtable3_private.h"
#include "getopt.h"
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void arg_register_error(struct arg_end* end, void* parent, int error, const char* argval) {
    /* printf("arg_register_error(%p,%p,%d,%s)\n",end,parent,error,argval); */
    if (end->count < end->hdr.maxcount) {
        end->error[end->count] = error;
        end->parent[end->count] = parent;
        end->argval[end->count] = argval;
        end->count++;
    } else {
        end->error[end->hdr.maxcount - 1] = ARG_ELIMIT;
        end->parent[end->hdr.maxcount - 1] = end;
        end->argval[end->hdr.maxcount - 1] = NULL;
    }
}

/*
 * Return index of first table entry with a matching short option
 * or -1 if no match was found.
 */
static int find_shortoption(struct arg_hdr** table, char shortopt) {
    int tabindex;
    for (tabindex = 0; !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        if (table[tabindex]->shortopts && strchr(table[tabindex]->shortopts, shortopt))
            return tabindex;
    }
    return -1;
}

struct longoptions {
    int getoptval;
    int noptions;
    struct option* options;
};

#if 0
static
void dump_longoptions(struct longoptions * longoptions)
{
    int i;
    printf("getoptval = %d\n", longoptions->getoptval);
    printf("noptions  = %d\n", longoptions->noptions);
    for (i = 0; i < longoptions->noptions; i++)
    {
        printf("options[%d].name    = \"%s\"\n",
               i,
               longoptions->options[i].name);
        printf("options[%d].has_arg = %d\n", i, longoptions->options[i].has_arg);
        printf("options[%d].flag    = %p\n", i, longoptions->options[i].flag);
        printf("options[%d].val     = %d\n", i, longoptions->options[i].val);
    }
}
#endif

static struct longoptions* alloc_longoptions(struct arg_hdr** table) {
    struct longoptions* result;
    size_t nbytes;
    int noptions = 1;
    size_t longoptlen = 0;
    int tabindex;
    int option_index = 0;
    char* store;

    /*
     * Determine the total number of option structs required
     * by counting the number of comma separated long options
     * in all table entries and return the count in noptions.
     * note: noptions starts at 1 not 0 because we getoptlong
     * requires a NULL option entry to terminate the option array.
     * While we are at it, count the number of chars required
     * to store private copies of all the longoption strings
     * and return that count in logoptlen.
     */
    tabindex = 0;
    do {
        const char* longopts = table[tabindex]->longopts;
        longoptlen += (longopts ? strlen(longopts) : 0) + 1;
        while (longopts) {
            noptions++;
            longopts = strchr(longopts + 1, ',');
        }
    } while (!(table[tabindex++]->flag & ARG_TERMINATOR));
    /*printf("%d long options consuming %d chars in total\n",noptions,longoptlen);*/

    /* allocate storage for return data structure as: */
    /* (struct longoptions) + (struct options)[noptions] + char[longoptlen] */
    nbytes = sizeof(struct longoptions) + sizeof(struct option) * noptions + longoptlen;
    result = (struct longoptions*)xmalloc(nbytes);

    result->getoptval = 0;
    result->noptions = noptions;
    result->options = (struct option*)(result + 1);
    store = (char*)(result->options + noptions);

    for (tabindex = 0; !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        const char* longopts = table[tabindex]->longopts;

        while (longopts && *longopts) {
            char* storestart = store;

            /* copy progressive longopt strings into the store */
            while (*longopts != 0 && *longopts != ',')
                *store++ = *longopts++;
            *store++ = 0;
            if (*longopts == ',')
                longopts++;
            /*fprintf(stderr,"storestart=\"%s\"\n",storestart);*/

            result->options[option_index].name = storestart;
            result->options[option_index].flag = &(result->getoptval);
            result->options[option_index].val = tabindex;
            if (table[tabindex]->flag & ARG_HASOPTVALUE)
                result->options[option_index].has_arg = 2;
            else if (table[tabindex]->flag & ARG_HASVALUE)
                result->options[option_index].has_arg = 1;
            else
                result->options[option_index].has_arg = 0;

            option_index++;
        }
    }
    /* terminate the options array with a zero-filled entry */
    result->options[option_index].name = 0;
    result->options[option_index].has_arg = 0;
    result->options[option_index].flag = 0;
    result->options[option_index].val = 0;

    /*dump_longoptions(result);*/
    return result;
}

static char* alloc_shortoptions(struct arg_hdr** table) {
    char* result;
    size_t len = 2;
    int tabindex;
    char* res;

    /* determine the total number of option chars required */
    for (tabindex = 0; !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        struct arg_hdr* hdr = table[tabindex];
        len += 3 * (hdr->shortopts ? strlen(hdr->shortopts) : 0);
    }

    result = xmalloc(len);

    res = result;

    /* add a leading ':' so getopt return codes distinguish    */
    /* unrecognised option and options missing argument values */
    *res++ = ':';

    for (tabindex = 0; !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        struct arg_hdr* hdr = table[tabindex];
        const char* shortopts = hdr->shortopts;
        while (shortopts && *shortopts) {
            *res++ = *shortopts++;
            if (hdr->flag & ARG_HASVALUE)
                *res++ = ':';
            if (hdr->flag & ARG_HASOPTVALUE)
                *res++ = ':';
        }
    }
    /* null terminate the string */
    *res = 0;

    /*printf("alloc_shortoptions() returns \"%s\"\n",(result?result:"NULL"));*/
    return result;
}

/* return index of the table terminator entry */
static int arg_endindex(struct arg_hdr** table) {
    int tabindex = 0;
    while (!(table[tabindex]->flag & ARG_TERMINATOR))
        tabindex++;
    return tabindex;
}

static void arg_parse_tagged(int argc, char** argv, struct arg_hdr** table, struct arg_end* endtable) {
    struct longoptions* longoptions;
    char* shortoptions;
    int copt;

    /*printf("arg_parse_tagged(%d,%p,%p,%p)\n",argc,argv,table,endtable);*/

    /* allocate short and long option arrays for the given opttable[].   */
    /* if the allocs fail then put an error msg in the last table entry. */
    longoptions = alloc_longoptions(table);
    shortoptions = alloc_shortoptions(table);

    /*dump_longoptions(longoptions);*/

    /* reset getopts internal option-index to zero, and disable error reporting */
    optind = 0;
    opterr = 0;

    /* fetch and process args using getopt_long */
    while ((copt = getopt_long(argc, argv, shortoptions, longoptions->options, NULL)) != -1) {
        /*
           printf("optarg='%s'\n",optarg);
           printf("optind=%d\n",optind);
           printf("copt=%c\n",(char)copt);
           printf("optopt=%c (%d)\n",optopt, (int)(optopt));
         */
        switch (copt) {
            case 0: {
                int tabindex = longoptions->getoptval;
                void* parent = table[tabindex]->parent;
                /*printf("long option detected from argtable[%d]\n", tabindex);*/
                if (optarg && optarg[0] == 0 && (table[tabindex]->flag & ARG_HASVALUE)) {
                    /* printf(": long option %s requires an argument\n",argv[optind-1]); */
                    arg_register_error(endtable, endtable, ARG_EMISSARG, argv[optind - 1]);
                    /* continue to scan the (empty) argument value to enforce argument count checking */
                }
                if (table[tabindex]->scanfn) {
                    int errorcode = table[tabindex]->scanfn(parent, optarg);
                    if (errorcode != 0)
                        arg_register_error(endtable, parent, errorcode, optarg);
                }
            } break;

            case '?':
                /*
                 * getopt_long() found an unrecognised short option.
                 * if it was a short option its value is in optopt
                 * if it was a long option then optopt=0
                 */
                switch (optopt) {
                    case 0:
                        /*printf("?0 unrecognised long option %s\n",argv[optind-1]);*/
                        arg_register_error(endtable, endtable, ARG_ELONGOPT, argv[optind - 1]);
                        break;
                    default:
                        /*printf("?* unrecognised short option '%c'\n",optopt);*/
                        arg_register_error(endtable, endtable, optopt, NULL);
                        break;
                }
                break;

            case ':':
                /*
                 * getopt_long() found an option with its argument missing.
                 */
                /*printf(": option %s requires an argument\n",argv[optind-1]); */
                arg_register_error(endtable, endtable, ARG_EMISSARG, argv[optind - 1]);
                break;

            default: {
                /* getopt_long() found a valid short option */
                int tabindex = find_shortoption(table, (char)copt);
                /*printf("short option detected from argtable[%d]\n", tabindex);*/
                if (tabindex == -1) {
                    /* should never get here - but handle it just in case */
                    /*printf("unrecognised short option %d\n",copt);*/
                    arg_register_error(endtable, endtable, copt, NULL);
                } else {
                    if (table[tabindex]->scanfn) {
                        void* parent = table[tabindex]->parent;
                        int errorcode = table[tabindex]->scanfn(parent, optarg);
                        if (errorcode != 0)
                            arg_register_error(endtable, parent, errorcode, optarg);
                    }
                }
                break;
            }
        }
    }

    xfree(shortoptions);
    xfree(longoptions);
}

static void arg_parse_untagged(int argc, char** argv, struct arg_hdr** table, struct arg_end* endtable) {
    int tabindex = 0;
    int errorlast = 0;
    const char* optarglast = NULL;
    void* parentlast = NULL;

    /*printf("arg_parse_untagged(%d,%p,%p,%p)\n",argc,argv,table,endtable);*/
    while (!(table[tabindex]->flag & ARG_TERMINATOR)) {
        void* parent;
        int errorcode;

        /* if we have exhausted our argv[optind] entries then we have finished */
        if (optind >= argc) {
            /*printf("arg_parse_untagged(): argv[] exhausted\n");*/
            return;
        }

        /* skip table entries with non-null long or short options (they are not untagged entries) */
        if (table[tabindex]->longopts || table[tabindex]->shortopts) {
            /*printf("arg_parse_untagged(): skipping argtable[%d] (tagged argument)\n",tabindex);*/
            tabindex++;
            continue;
        }

        /* skip table entries with NULL scanfn */
        if (!(table[tabindex]->scanfn)) {
            /*printf("arg_parse_untagged(): skipping argtable[%d] (NULL scanfn)\n",tabindex);*/
            tabindex++;
            continue;
        }

        /* attempt to scan the current argv[optind] with the current     */
        /* table[tabindex] entry. If it succeeds then keep it, otherwise */
        /* try again with the next table[] entry.                        */
        parent = table[tabindex]->parent;
        errorcode = table[tabindex]->scanfn(parent, argv[optind]);
        if (errorcode == 0) {
            /* success, move onto next argv[optind] but stay with same table[tabindex] */
            /*printf("arg_parse_untagged(): argtable[%d] successfully matched\n",tabindex);*/
            optind++;

            /* clear the last tentative error */
            errorlast = 0;
        } else {
            /* failure, try same argv[optind] with next table[tabindex] entry */
            /*printf("arg_parse_untagged(): argtable[%d] failed match\n",tabindex);*/
            tabindex++;

            /* remember this as a tentative error we may wish to reinstate later */
            errorlast = errorcode;
            optarglast = argv[optind];
            parentlast = parent;
        }
    }

    /* if a tenative error still remains at this point then register it as a proper error */
    if (errorlast) {
        arg_register_error(endtable, parentlast, errorlast, optarglast);
        optind++;
    }

    /* only get here when not all argv[] entries were consumed */
    /* register an error for each unused argv[] entry */
    while (optind < argc) {
        /*printf("arg_parse_untagged(): argv[%d]=\"%s\" not consumed\n",optind,argv[optind]);*/
        arg_register_error(endtable, endtable, ARG_ENOMATCH, argv[optind++]);
    }

    return;
}

static void arg_parse_check(struct arg_hdr** table, struct arg_end* endtable) {
    int tabindex = 0;
    /* printf("arg_parse_check()\n"); */
    do {
        if (table[tabindex]->checkfn) {
            void* parent = table[tabindex]->parent;
            int errorcode = table[tabindex]->checkfn(parent);
            if (errorcode != 0)
                arg_register_error(endtable, parent, errorcode, NULL);
        }
    } while (!(table[tabindex++]->flag & ARG_TERMINATOR));
}

static void arg_reset(void** argtable) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    int tabindex = 0;
    /*printf("arg_reset(%p)\n",argtable);*/
    do {
        if (table[tabindex]->resetfn)
            table[tabindex]->resetfn(table[tabindex]->parent);
    } while (!(table[tabindex++]->flag & ARG_TERMINATOR));
}

int arg_parse(int argc, char** argv, void** argtable) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    struct arg_end* endtable;
    int endindex;
    char** argvcopy = NULL;
    int i;

    /*printf("arg_parse(%d,%p,%p)\n",argc,argv,argtable);*/

    /* reset any argtable data from previous invocations */
    arg_reset(argtable);

    /* locate the first end-of-table marker within the array */
    endindex = arg_endindex(table);
    endtable = (struct arg_end*)table[endindex];

    /* Special case of argc==0.  This can occur on Texas Instruments DSP. */
    /* Failure to trap this case results in an unwanted NULL result from  */
    /* the malloc for argvcopy (next code block).                         */
    if (argc == 0) {
        /* We must still perform post-parse checks despite the absence of command line arguments */
        arg_parse_check(table, endtable);

        /* Now we are finished */
        return endtable->count;
    }

    argvcopy = (char**)xmalloc(sizeof(char*) * (argc + 1));

    /*
        Fill in the local copy of argv[]. We need a local copy
        because getopt rearranges argv[] which adversely affects
        susbsequent parsing attempts.
        */
    for (i = 0; i < argc; i++)
        argvcopy[i] = argv[i];

    argvcopy[argc] = NULL;

    /* parse the command line (local copy) for tagged options */
    arg_parse_tagged(argc, argvcopy, table, endtable);

    /* parse the command line (local copy) for untagged options */
    arg_parse_untagged(argc, argvcopy, table, endtable);

    /* if no errors so far then perform post-parse checks otherwise dont bother */
    if (endtable->count == 0)
        arg_parse_check(table, endtable);

    /* release the local copt of argv[] */
    xfree(argvcopy);

    return endtable->count;
}

/*
 * Concatenate contents of src[] string onto *pdest[] string.
 * The *pdest pointer is altered to point to the end of the
 * target string and *pndest is decremented by the same number
 * of chars.
 * Does not append more than *pndest chars into *pdest[]
 * so as to prevent buffer overruns.
 * Its something like strncat() but more efficient for repeated
 * calls on the same destination string.
 * Example of use:
 *   char dest[30] = "good"
 *   size_t ndest = sizeof(dest);
 *   char *pdest = dest;
 *   arg_char(&pdest,"bye ",&ndest);
 *   arg_char(&pdest,"cruel ",&ndest);
 *   arg_char(&pdest,"world!",&ndest);
 * Results in:
 *   dest[] == "goodbye cruel world!"
 *   ndest  == 10
 */
static void arg_cat(char** pdest, const char* src, size_t* pndest) {
    char* dest = *pdest;
    char* end = dest + *pndest;

    /*locate null terminator of dest string */
    while (dest < end && *dest != 0)
        dest++;

    /* concat src string to dest string */
    while (dest < end && *src != 0)
        *dest++ = *src++;

    /* null terminate dest string */
    *dest = 0;

    /* update *pdest and *pndest */
    *pndest = end - dest;
    *pdest = dest;
}

static void arg_cat_option(char* dest, size_t ndest, const char* shortopts, const char* longopts, const char* datatype, int optvalue) {
    if (shortopts) {
        char option[3];

        /* note: option array[] is initialiazed dynamically here to satisfy   */
        /* a deficiency in the watcom compiler wrt static array initializers. */
        option[0] = '-';
        option[1] = shortopts[0];
        option[2] = 0;

        arg_cat(&dest, option, &ndest);
        if (datatype) {
            arg_cat(&dest, " ", &ndest);
            if (optvalue) {
                arg_cat(&dest, "[", &ndest);
                arg_cat(&dest, datatype, &ndest);
                arg_cat(&dest, "]", &ndest);
            } else
                arg_cat(&dest, datatype, &ndest);
        }
    } else if (longopts) {
        size_t ncspn;

        /* add "--" tag prefix */
        arg_cat(&dest, "--", &ndest);

        /* add comma separated option tag */
        ncspn = strcspn(longopts, ",");
#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
        strncat_s(dest, ndest, longopts, (ncspn < ndest) ? ncspn : ndest);
#else
        strncat(dest, longopts, (ncspn < ndest) ? ncspn : ndest);
#endif

        if (datatype) {
            arg_cat(&dest, "=", &ndest);
            if (optvalue) {
                arg_cat(&dest, "[", &ndest);
                arg_cat(&dest, datatype, &ndest);
                arg_cat(&dest, "]", &ndest);
            } else
                arg_cat(&dest, datatype, &ndest);
        }
    } else if (datatype) {
        if (optvalue) {
            arg_cat(&dest, "[", &ndest);
            arg_cat(&dest, datatype, &ndest);
            arg_cat(&dest, "]", &ndest);
        } else
            arg_cat(&dest, datatype, &ndest);
    }
}

static void
arg_cat_optionv(char* dest, size_t ndest, const char* shortopts, const char* longopts, const char* datatype, int optvalue, const char* separator) {
    separator = separator ? separator : "";

    if (shortopts) {
        const char* c = shortopts;
        while (*c) {
            /* "-a|-b|-c" */
            char shortopt[3];

            /* note: shortopt array[] is initialiazed dynamically here to satisfy */
            /* a deficiency in the watcom compiler wrt static array initializers. */
            shortopt[0] = '-';
            shortopt[1] = *c;
            shortopt[2] = 0;

            arg_cat(&dest, shortopt, &ndest);
            if (*++c)
                arg_cat(&dest, separator, &ndest);
        }
    }

    /* put separator between long opts and short opts */
    if (shortopts && longopts)
        arg_cat(&dest, separator, &ndest);

    if (longopts) {
        const char* c = longopts;
        while (*c) {
            size_t ncspn;

            /* add "--" tag prefix */
            arg_cat(&dest, "--", &ndest);

            /* add comma separated option tag */
            ncspn = strcspn(c, ",");
#if (defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)) || (defined(__STDC_SECURE_LIB__) && defined(__STDC_WANT_SECURE_LIB__))
            strncat_s(dest, ndest, c, (ncspn < ndest) ? ncspn : ndest);
#else
            strncat(dest, c, (ncspn < ndest) ? ncspn : ndest);
#endif
            c += ncspn;

            /* add given separator in place of comma */
            if (*c == ',') {
                arg_cat(&dest, separator, &ndest);
                c++;
            }
        }
    }

    if (datatype) {
        if (longopts)
            arg_cat(&dest, "=", &ndest);
        else if (shortopts)
            arg_cat(&dest, " ", &ndest);

        if (optvalue) {
            arg_cat(&dest, "[", &ndest);
            arg_cat(&dest, datatype, &ndest);
            arg_cat(&dest, "]", &ndest);
        } else
            arg_cat(&dest, datatype, &ndest);
    }
}

void arg_print_option_ds(arg_dstr_t ds, const char* shortopts, const char* longopts, const char* datatype, const char* suffix) {
    char syntax[200] = "";
    suffix = suffix ? suffix : "";

    /* there is no way of passing the proper optvalue for optional argument values here, so we must ignore it */
    arg_cat_optionv(syntax, sizeof(syntax), shortopts, longopts, datatype, 0, "|");

    arg_dstr_cat(ds, syntax);
    arg_dstr_cat(ds, (char*)suffix);
}

/* this function should be deprecated because it doesn't consider optional argument values (ARG_HASOPTVALUE) */
void arg_print_option(FILE* fp, const char* shortopts, const char* longopts, const char* datatype, const char* suffix) {
    arg_dstr_t ds = arg_dstr_create();
    arg_print_option_ds(ds, shortopts, longopts, datatype, suffix);
    fputs(arg_dstr_cstr(ds), fp);
    arg_dstr_destroy(ds);
}

/*
 * Print a GNU style [OPTION] string in which all short options that
 * do not take argument values are presented in abbreviated form, as
 * in: -xvfsd, or -xvf[sd], or [-xvsfd]
 */
static void arg_print_gnuswitch_ds(arg_dstr_t ds, struct arg_hdr** table) {
    int tabindex;
    char* format1 = " -%c";
    char* format2 = " [-%c";
    char* suffix = "";

    /* print all mandatory switches that are without argument values */
    for (tabindex = 0; table[tabindex] && !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        /* skip optional options */
        if (table[tabindex]->mincount < 1)
            continue;

        /* skip non-short options */
        if (table[tabindex]->shortopts == NULL)
            continue;

        /* skip options that take argument values */
        if (table[tabindex]->flag & ARG_HASVALUE)
            continue;

        /* print the short option (only the first short option char, ignore multiple choices)*/
        arg_dstr_catf(ds, format1, table[tabindex]->shortopts[0]);
        format1 = "%c";
        format2 = "[%c";
    }

    /* print all optional switches that are without argument values */
    for (tabindex = 0; table[tabindex] && !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        /* skip mandatory args */
        if (table[tabindex]->mincount > 0)
            continue;

        /* skip args without short options */
        if (table[tabindex]->shortopts == NULL)
            continue;

        /* skip args with values */
        if (table[tabindex]->flag & ARG_HASVALUE)
            continue;

        /* print first short option */
        arg_dstr_catf(ds, format2, table[tabindex]->shortopts[0]);
        format2 = "%c";
        suffix = "]";
    }

    arg_dstr_catf(ds, "%s", suffix);
}

void arg_print_syntax_ds(arg_dstr_t ds, void** argtable, const char* suffix) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    int i, tabindex;

    /* print GNU style [OPTION] string */
    arg_print_gnuswitch_ds(ds, table);

    /* print remaining options in abbreviated style */
    for (tabindex = 0; table[tabindex] && !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        char syntax[200] = "";
        const char *shortopts, *longopts, *datatype;

        /* skip short options without arg values (they were printed by arg_print_gnu_switch) */
        if (table[tabindex]->shortopts && !(table[tabindex]->flag & ARG_HASVALUE))
            continue;

        shortopts = table[tabindex]->shortopts;
        longopts = table[tabindex]->longopts;
        datatype = table[tabindex]->datatype;
        arg_cat_option(syntax, sizeof(syntax), shortopts, longopts, datatype, table[tabindex]->flag & ARG_HASOPTVALUE);

        if (strlen(syntax) > 0) {
            /* print mandatory instances of this option */
            for (i = 0; i < table[tabindex]->mincount; i++) {
                arg_dstr_cat(ds, " ");
                arg_dstr_cat(ds, syntax);
            }

            /* print optional instances enclosed in "[..]" */
            switch (table[tabindex]->maxcount - table[tabindex]->mincount) {
                case 0:
                    break;
                case 1:
                    arg_dstr_cat(ds, " [");
                    arg_dstr_cat(ds, syntax);
                    arg_dstr_cat(ds, "]");
                    break;
                case 2:
                    arg_dstr_cat(ds, " [");
                    arg_dstr_cat(ds, syntax);
                    arg_dstr_cat(ds, "]");
                    arg_dstr_cat(ds, " [");
                    arg_dstr_cat(ds, syntax);
                    arg_dstr_cat(ds, "]");
                    break;
                default:
                    arg_dstr_cat(ds, " [");
                    arg_dstr_cat(ds, syntax);
                    arg_dstr_cat(ds, "]...");
                    break;
            }
        }
    }

    if (suffix) {
        arg_dstr_cat(ds, (char*)suffix);
    }
}

void arg_print_syntax(FILE* fp, void** argtable, const char* suffix) {
    arg_dstr_t ds = arg_dstr_create();
    arg_print_syntax_ds(ds, argtable, suffix);
    fputs(arg_dstr_cstr(ds), fp);
    arg_dstr_destroy(ds);
}

void arg_print_syntaxv_ds(arg_dstr_t ds, void** argtable, const char* suffix) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    int i, tabindex;

    /* print remaining options in abbreviated style */
    for (tabindex = 0; table[tabindex] && !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        char syntax[200] = "";
        const char *shortopts, *longopts, *datatype;

        shortopts = table[tabindex]->shortopts;
        longopts = table[tabindex]->longopts;
        datatype = table[tabindex]->datatype;
        arg_cat_optionv(syntax, sizeof(syntax), shortopts, longopts, datatype, table[tabindex]->flag & ARG_HASOPTVALUE, "|");

        /* print mandatory options */
        for (i = 0; i < table[tabindex]->mincount; i++) {
            arg_dstr_cat(ds, " ");
            arg_dstr_cat(ds, syntax);
        }

        /* print optional args enclosed in "[..]" */
        switch (table[tabindex]->maxcount - table[tabindex]->mincount) {
            case 0:
                break;
            case 1:
                arg_dstr_cat(ds, " [");
                arg_dstr_cat(ds, syntax);
                arg_dstr_cat(ds, "]");
                break;
            case 2:
                arg_dstr_cat(ds, " [");
                arg_dstr_cat(ds, syntax);
                arg_dstr_cat(ds, "]");
                arg_dstr_cat(ds, " [");
                arg_dstr_cat(ds, syntax);
                arg_dstr_cat(ds, "]");
                break;
            default:
                arg_dstr_cat(ds, " [");
                arg_dstr_cat(ds, syntax);
                arg_dstr_cat(ds, "]...");
                break;
        }
    }

    if (suffix) {
        arg_dstr_cat(ds, (char*)suffix);
    }
}

void arg_print_syntaxv(FILE* fp, void** argtable, const char* suffix) {
    arg_dstr_t ds = arg_dstr_create();
    arg_print_syntaxv_ds(ds, argtable, suffix);
    fputs(arg_dstr_cstr(ds), fp);
    arg_dstr_destroy(ds);
}

void arg_print_glossary_ds(arg_dstr_t ds, void** argtable, const char* format) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    int tabindex;

    format = format ? format : "  %-20s %s\n";
    for (tabindex = 0; !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        if (table[tabindex]->glossary) {
            char syntax[200] = "";
            const char* shortopts = table[tabindex]->shortopts;
            const char* longopts = table[tabindex]->longopts;
            const char* datatype = table[tabindex]->datatype;
            const char* glossary = table[tabindex]->glossary;
            arg_cat_optionv(syntax, sizeof(syntax), shortopts, longopts, datatype, table[tabindex]->flag & ARG_HASOPTVALUE, ", ");
            arg_dstr_catf(ds, format, syntax, glossary);
        }
    }
}

void arg_print_glossary(FILE* fp, void** argtable, const char* format) {
    arg_dstr_t ds = arg_dstr_create();
    arg_print_glossary_ds(ds, argtable, format);
    fputs(arg_dstr_cstr(ds), fp);
    arg_dstr_destroy(ds);
}

/**
 * Print a piece of text formatted, which means in a column with a
 * left and a right margin. The lines are wrapped at whitspaces next
 * to right margin. The function does not indent the first line, but
 * only the following ones.
 *
 * Example:
 * arg_print_formatted( fp, 0, 5, "Some text that doesn't fit." )
 * will result in the following output:
 *
 * Some
 * text
 * that
 * doesn'
 * t fit.
 *
 * Too long lines will be wrapped in the middle of a word.
 *
 * arg_print_formatted( fp, 2, 7, "Some text that doesn't fit." )
 * will result in the following output:
 *
 * Some
 *   text
 *   that
 *   doesn'
 *   t fit.
 *
 * As you see, the first line is not indented. This enables output of
 * lines, which start in a line where output already happened.
 *
 * Author: Uli Fouquet
 */
static void arg_print_formatted_ds(arg_dstr_t ds, const unsigned lmargin, const unsigned rmargin, const char* text) {
    const unsigned int textlen = (unsigned int)strlen(text);
    unsigned int line_start = 0;
    unsigned int line_end = textlen;
    const unsigned int colwidth = (rmargin - lmargin) + 1;

    assert(strlen(text) < UINT_MAX);

    /* Someone doesn't like us... */
    if (line_end < line_start) {
        arg_dstr_catf(ds, "%s\n", text);
    }

    while (line_end > line_start) {
        /* Eat leading white spaces. This is essential because while
           wrapping lines, there will often be a whitespace at beginning
           of line */
        while (isspace(*(text + line_start))) {
            line_start++;
        }

        /* Find last whitespace, that fits into line */
        if (line_end - line_start > colwidth) {
            line_end = line_start + colwidth;

            while ((line_end > line_start) && !isspace(*(text + line_end))) {
                line_end--;
            }

            /* Consume trailing spaces */
            while ((line_end > line_start) && isspace(*(text + line_end))) {
                line_end--;
            }

            /* Restore the last non-space character */
            line_end++;
        }

        /* Output line of text */
        while (line_start < line_end) {
            char c = *(text + line_start);
            arg_dstr_catc(ds, c);
            line_start++;
        }
        arg_dstr_cat(ds, "\n");

        /* Initialize another line */
        if (line_end < textlen) {
            unsigned i;

            for (i = 0; i < lmargin; i++) {
                arg_dstr_cat(ds, " ");
            }

            line_end = textlen;
        }
    } /* lines of text */
}

/**
 * Prints the glossary in strict GNU format.
 * Differences to arg_print_glossary() are:
 *   - wraps lines after 80 chars
 *   - indents lines without shortops
 *   - does not accept formatstrings
 *
 * Contributed by Uli Fouquet
 */
void arg_print_glossary_gnu_ds(arg_dstr_t ds, void** argtable) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    int tabindex;

    for (tabindex = 0; !(table[tabindex]->flag & ARG_TERMINATOR); tabindex++) {
        if (table[tabindex]->glossary) {
            char syntax[200] = "";
            const char* shortopts = table[tabindex]->shortopts;
            const char* longopts = table[tabindex]->longopts;
            const char* datatype = table[tabindex]->datatype;
            const char* glossary = table[tabindex]->glossary;

            if (!shortopts && longopts) {
                /* Indent trailing line by 4 spaces... */
                memset(syntax, ' ', 4);
                *(syntax + 4) = '\0';
            }

            arg_cat_optionv(syntax, sizeof(syntax), shortopts, longopts, datatype, table[tabindex]->flag & ARG_HASOPTVALUE, ", ");

            /* If syntax fits not into column, print glossary in new line... */
            if (strlen(syntax) > 25) {
                arg_dstr_catf(ds, "  %-25s %s\n", syntax, "");
                *syntax = '\0';
            }

            arg_dstr_catf(ds, "  %-25s ", syntax);
            arg_print_formatted_ds(ds, 28, 79, glossary);
        }
    } /* for each table entry */

    arg_dstr_cat(ds, "\n");
}

void arg_print_glossary_gnu(FILE* fp, void** argtable) {
    arg_dstr_t ds = arg_dstr_create();
    arg_print_glossary_gnu_ds(ds, argtable);
    fputs(arg_dstr_cstr(ds), fp);
    arg_dstr_destroy(ds);
}

/**
 * Checks the argtable[] array for NULL entries and returns 1
 * if any are found, zero otherwise.
 */
int arg_nullcheck(void** argtable) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    int tabindex;
    /*printf("arg_nullcheck(%p)\n",argtable);*/

    if (!table)
        return 1;

    tabindex = 0;
    do {
        /*printf("argtable[%d]=%p\n",tabindex,argtable[tabindex]);*/
        if (!table[tabindex])
            return 1;
    } while (!(table[tabindex++]->flag & ARG_TERMINATOR));

    return 0;
}

/*
 * arg_free() is deprecated in favour of arg_freetable() due to a flaw in its design.
 * The flaw results in memory leak in the (very rare) case that an intermediate
 * entry in the argtable array failed its memory allocation while others following
 * that entry were still allocated ok. Those subsequent allocations will not be
 * deallocated by arg_free().
 * Despite the unlikeliness of the problem occurring, and the even unlikelier event
 * that it has any deliterious effect, it is fixed regardless by replacing arg_free()
 * with the newer arg_freetable() function.
 * We still keep arg_free() for backwards compatibility.
 */
void arg_free(void** argtable) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    int tabindex = 0;
    int flag;
    /*printf("arg_free(%p)\n",argtable);*/
    do {
        /*
           if we encounter a NULL entry then somewhat incorrectly we presume
           we have come to the end of the array. It isnt strictly true because
           an intermediate entry could be NULL with other non-NULL entries to follow.
           The subsequent argtable entries would then not be freed as they should.
         */
        if (table[tabindex] == NULL)
            break;

        flag = table[tabindex]->flag;
        xfree(table[tabindex]);
        table[tabindex++] = NULL;

    } while (!(flag & ARG_TERMINATOR));
}

/* frees each non-NULL element of argtable[], where n is the size of the number of entries in the array */
void arg_freetable(void** argtable, size_t n) {
    struct arg_hdr** table = (struct arg_hdr**)argtable;
    size_t tabindex = 0;
    /*printf("arg_freetable(%p)\n",argtable);*/
    for (tabindex = 0; tabindex < n; tabindex++) {
        if (table[tabindex] == NULL)
            continue;

        xfree(table[tabindex]);
        table[tabindex] = NULL;
    };
}

#ifdef _WIN32
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(fdwReason);
    UNREFERENCED_PARAMETER(lpvReserved);
}
#endif
