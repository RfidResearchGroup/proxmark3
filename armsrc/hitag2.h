/*
 * Hitag2 emulation public interface
 * 
 * (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
 */

typedef int (*hitag2_response_callback_t)(const char* response_data, const int response_length, const int fdt, void *cb_cookie);

extern int hitag2_init(void);
extern int hitag2_handle_command(const char* data, const int length, hitag2_response_callback_t cb, void *cb_cookie);
