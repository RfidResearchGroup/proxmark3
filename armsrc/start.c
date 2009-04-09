//-----------------------------------------------------------------------------
// Just vector to AppMain(). This is in its own file so that I can place it
// with the linker script.
// Jonathan Westhues, Mar 2006
//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"

void Vector(void)
{
	AppMain();
}
