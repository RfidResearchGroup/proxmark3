{ pkgs }: {
	deps = [
   pkgs.run
   pkgs.pwdsafety
   pkgs.rcs
   pkgs.proxmark3
		pkgs.clang_12
		pkgs.ccls
		pkgs.gdb
		pkgs.gnumake
	];
}