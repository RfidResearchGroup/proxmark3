/* ----------------------------------------------------------------------------
 * umm_malloc.h - a memory allocator for embedded systems (microcontrollers)
 *
 * From https://github.com/rhempel/umm_malloc
 * See copyright notice in LICENSE.TXT
 * ----------------------------------------------------------------------------
 */

#ifndef UMM_MALLOC_H
#define UMM_MALLOC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */

extern void  umm_init( void );
extern void *umm_malloc( size_t size );
extern void *umm_calloc( size_t num, size_t size );
extern void *umm_realloc( void *ptr, size_t size );
extern void  umm_free( void *ptr );

/* ------------------------------------------------------------------------ */

#ifdef __cplusplus
}
#endif

#endif /* UMM_MALLOC_H */
