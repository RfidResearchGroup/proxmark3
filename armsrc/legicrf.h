//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF emulation public interface
//-----------------------------------------------------------------------------

#ifndef __LEGICRF_H
#define __LEGICRF_H

extern void LegicRfSimulate(int phase, int frame, int reqresp);
extern int  LegicRfReader(int bytes, int offset);
extern void LegicRfWriter(int bytes, int offset);

#endif /* __LEGICRF_H */
