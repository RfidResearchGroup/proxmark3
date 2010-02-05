/*
 * LEGIC RF emulation public interface
 * 
 * (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
 */

#ifndef LEGICRF_H_
#define LEGICRF_H_

extern void LegicRfSimulate(void);
extern void LegicRfReader(int bytes, int offset);
#endif /* LEGICRF_H_ */
