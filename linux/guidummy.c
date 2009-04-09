#include <stdio.h>

void ShowGraphWindow(void)
{
	static int warned = 0;

	if (!warned) {
		printf("No GUI in this build!\n");
		warned = 1;
	}
}

void HideGraphWindow(void) {}
void RepaintGraphWindow(void) {}
void MainGraphics() {}
void InitGraphics(int argc, char **argv) {}
void ExitGraphics(void) {}
