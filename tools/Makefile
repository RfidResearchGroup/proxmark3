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

get_xorsearch:
	$(MKDIR) xorsearch
	$(WGET) https://didierstevens.com/files/software/XORSearch_V1_11_2.zip
#  Mingw
#	unzzip-big XORSearch_V1_11_2.zip
#  linux
#	gunzip  XORSearch_V1_11_2.zip

# Python impl of NDEF FORUM 1-5 protocol
get_nfcpy:
	$(MKDIR) nfcpy
	$(GIT) https://github.com/nfcpy/nfcpy.git

# Python tool to create, modify and print NDEF records
get_ndeftool:
	$(MKDIR) ndeftool
	$(GIT) https://github.com/nfcpy/ndeftool.git
