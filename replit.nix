{ pkgs }: {
	deps = [
   pkgs.proxmark3
		pkgs.clang_12
		pkgs.ccls
		pkgs.gdb
		pkgs.gnumake
	];
}