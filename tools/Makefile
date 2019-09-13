MKDIR = mkdir -p
WGET = wget -N
TAR = tar Jxvf
GIT = git clone

get_craptev1:
	$(WGET) http://crapto1.netgarage.org/craptev1-v1.1.tar.xz
	$(TAR) craptev1-v1.1.tar.xz -C craptev1-v1.1

get_crapto1:
	$(WGET) http://crapto1.netgarage.org/crapto1-v3.3.tar.xz
	$(TAR) Jxvf crapto1-v3.3.tar.xz -C crapto1-v3.3

get_nonce_bf:
#	$(GIT) https://github.com/J-Run/mf_key_brute.git mf_key_brute
	$(GIT) https://github.com/iceman1001/mf_nonce_brute mf_nonce_brute

get_xorsearch:
	$(MKDIR) xorsearch
	$(WGET) https://didierstevens.com/files/software/XORSearch_V1_11_2.zip
#  Mingw
#	unzzip-big XORSearch_V1_11_2.zip
#  linux
#	gunzip  XORSearch_V1_11_2.zip
