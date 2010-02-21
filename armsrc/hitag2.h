//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hitag2 emulation public interface
//-----------------------------------------------------------------------------

#ifndef __HITAG2_H
#define __HITAG2_H

typedef int (*hitag2_response_callback_t)(const char* response_data, const int response_length, const int fdt, void *cb_cookie);

extern int hitag2_init(void);
extern int hitag2_handle_command(const char* data, const int length, hitag2_response_callback_t cb, void *cb_cookie);

#endif
