
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

//#include <math.h>
#ifdef UMM_INFO

/* ----------------------------------------------------------------------------
 * From https://github.com/rhempel/umm_malloc
 * One of the coolest things about this little library is that it's VERY
 * easy to get debug information about the memory heap by simply iterating
 * through all of the memory blocks.
 *
 * As you go through all the blocks, you can check to see if it's a free
 * block by looking at the high order bit of the next block index. You can
 * also see how big the block is by subtracting the next block index from
 * the current block number.
 *
 * The umm_info function does all of that and makes the results available
 * in the ummHeapInfo structure.
 * ----------------------------------------------------------------------------
 */

UMM_HEAP_INFO ummHeapInfo;

void *umm_info( void *ptr, bool force ) {
  if(umm_heap == NULL) {
    umm_init();
  }

  uint16_t blockNo = 0;

  /* Protect the critical section... */
  UMM_CRITICAL_ENTRY();

  /*
   * Clear out all of the entries in the ummHeapInfo structure before doing
   * any calculations..
   */
  memset( &ummHeapInfo, 0, sizeof( ummHeapInfo ) );

  DBGLOGS_FORCE( force, "\n" );
  DBGLOGS_FORCE( force, "+----------+-------+--------+--------+-------+--------+--------+\n" );
  DBGLOG_FORCE( force, "|0x%08x|B %5i|NB %5i|PB %5i|Z %5i|NF %5i|PF %5i|\n",
      DBGLOG_32_BIT_PTR(&UMM_BLOCK(blockNo)),
      blockNo,
      UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK,
      UMM_PBLOCK(blockNo),
      (UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK )-blockNo,
      UMM_NFREE(blockNo),
      UMM_PFREE(blockNo) );

  /*
   * Now loop through the block lists, and keep track of the number and size
   * of used and free blocks. The terminating condition is an nb pointer with
   * a value of zero...
   */

  blockNo = UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK;

  while( UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK ) {
    size_t curBlocks = (UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK )-blockNo;

    ++ummHeapInfo.totalEntries;
    ummHeapInfo.totalBlocks += curBlocks;

    /* Is this a free block? */

    if( UMM_NBLOCK(blockNo) & UMM_FREELIST_MASK ) {
      ++ummHeapInfo.freeEntries;
      ummHeapInfo.freeBlocks += curBlocks;
      ummHeapInfo.freeBlocksSquared += (curBlocks * curBlocks);

      if (ummHeapInfo.maxFreeContiguousBlocks < curBlocks) {
        ummHeapInfo.maxFreeContiguousBlocks = curBlocks;
      }

      DBGLOG_FORCE( force, "|0x%08x|B %5i|NB %5i|PB %5i|Z %5u|NF %5i|PF %5i|\n",
          DBGLOG_32_BIT_PTR(&UMM_BLOCK(blockNo)),
          blockNo,
          UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK,
          UMM_PBLOCK(blockNo),
          (uint16_t)curBlocks,
          UMM_NFREE(blockNo),
          UMM_PFREE(blockNo) );

      /* Does this block address match the ptr we may be trying to free? */

      if( ptr == &UMM_BLOCK(blockNo) ) {

        /* Release the critical section... */
        UMM_CRITICAL_EXIT();

        return( ptr );
      }
    } else {
      ++ummHeapInfo.usedEntries;
      ummHeapInfo.usedBlocks += curBlocks;

      DBGLOG_FORCE( force, "|0x%08x|B %5i|NB %5i|PB %5i|Z %5u|                 |\n",
          DBGLOG_32_BIT_PTR(&UMM_BLOCK(blockNo)),
          blockNo,
          UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK,
          UMM_PBLOCK(blockNo),
          (uint16_t)curBlocks );
    }

    blockNo = UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK;
  }

  /*
   * The very last block is used as a placeholder to indicate that
   * there are no more blocks in the heap, so it cannot be used
   * for anything - at the same time, the size of this block must
   * ALWAYS be exactly 1 !
   */

  DBGLOG_FORCE( force, "|0x%08x|B %5i|NB %5i|PB %5i|Z %5i|NF %5i|PF %5i|\n",
      DBGLOG_32_BIT_PTR(&UMM_BLOCK(blockNo)),
      blockNo,
      UMM_NBLOCK(blockNo) & UMM_BLOCKNO_MASK,
      UMM_PBLOCK(blockNo),
      UMM_NUMBLOCKS-blockNo,
      UMM_NFREE(blockNo),
      UMM_PFREE(blockNo) );

  DBGLOGS_FORCE( force, "+----------+-------+--------+--------+-------+--------+--------+\n" );

  DBGLOG_FORCE( force, "Total Entries %5i    Used Entries %5i    Free Entries %5i\n",
      ummHeapInfo.totalEntries,
      ummHeapInfo.usedEntries,
      ummHeapInfo.freeEntries );

  DBGLOG_FORCE( force, "Total Blocks  %5i    Used Blocks  %5i    Free Blocks  %5i\n",
      ummHeapInfo.totalBlocks,
      ummHeapInfo.usedBlocks,
      ummHeapInfo.freeBlocks  );

  DBGLOGS_FORCE( force, "+--------------------------------------------------------------+\n" );

  DBGLOG_FORCE( force, "Usage Metric:               %5i\n", umm_usage_metric());
  DBGLOG_FORCE( force, "Fragmentation Metric:       %5i\n", umm_fragmentation_metric());

  DBGLOGS_FORCE( force, "+--------------------------------------------------------------+\n" );

  /* Release the critical section... */
  UMM_CRITICAL_EXIT();

  return( NULL );
}

/* ------------------------------------------------------------------------ */

size_t umm_free_heap_size( void ) {
  umm_info(NULL, 0);
  return (size_t)ummHeapInfo.freeBlocks * sizeof(umm_block);
}

size_t umm_max_free_block_size( void ) {
  umm_info(NULL, 0);
  return ummHeapInfo.maxFreeContiguousBlocks * sizeof(umm_block);
}

int umm_usage_metric( void ) {
  DBGLOG_DEBUG( "usedBlocks %i totalBlocks %i\n", ummHeapInfo.usedBlocks, ummHeapInfo.totalBlocks);

  return (int)((ummHeapInfo.usedBlocks * 100)/(ummHeapInfo.freeBlocks));
}

static uint32_t sqrt(uint32_t x) {
    double n=x;
    while((n*n-x>0.0001)||(n*n-x<-0.0001)){
        n=(n+x/n)/2;
    }
    return (uint32_t)n;
}

int umm_fragmentation_metric( void ) {
  DBGLOG_DEBUG( "freeBlocks %i freeBlocksSquared %i\n", ummHeapInfo.freeBlocks, ummHeapInfo.freeBlocksSquared);
  if (0 == ummHeapInfo.freeBlocks) {
      return 0;
  } else {
      return (100 - ((sqrt(ummHeapInfo.freeBlocksSquared) * 100)/(ummHeapInfo.freeBlocks)));
  }
}

#ifdef UMM_INLINE_METRICS
static void umm_fragmentation_metric_init( void ) {
    ummHeapInfo.freeBlocks = UMM_NUMBLOCKS - 2;
    ummHeapInfo.freeBlocksSquared = ummHeapInfo.freeBlocks * ummHeapInfo.freeBlocks;
}

static void umm_fragmentation_metric_add( uint16_t c ) {
    uint16_t blocks = (UMM_NBLOCK(c) & UMM_BLOCKNO_MASK) - c;
    DBGLOG_DEBUG( "Add block %i size %i to free metric\n", c, blocks);
    ummHeapInfo.freeBlocks += blocks;
    ummHeapInfo.freeBlocksSquared += (blocks * blocks);
}

static void umm_fragmentation_metric_remove( uint16_t c ) {
    uint16_t blocks = (UMM_NBLOCK(c) & UMM_BLOCKNO_MASK) - c;
    DBGLOG_DEBUG( "Remove block %i size %i from free metric\n", c, blocks);
    ummHeapInfo.freeBlocks -= blocks;
    ummHeapInfo.freeBlocksSquared -= (blocks * blocks);
}
#endif // UMM_INLINE_METRICS

/* ------------------------------------------------------------------------ */
#endif
