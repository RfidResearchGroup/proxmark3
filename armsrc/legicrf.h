/*
 * LEGIC RF emulation public interface
 *
 * (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
 */

#ifndef __LEGICRF_H
#define __LEGICRF_H

extern void LegicRfSimulate(void);
extern void LegicRfReader(int bytes, int offset);

#endif /* __LEGICRF_H */
