CFLAGS?=-Wall
#INCLUDE=-I/usr/local/cuda-7.5/include
INCLUDE=-I/opt/nvidia/cuda/include
#Linux
#LIBS=-L/usr/local/cuda-7.5/lib64 -lOpenCL
LIBS=-L/opt/nvidia/cuda/lib64 -lOpenCL
#Mac
#LIBS=-framework OpenCL
VPATH=../common
INC=-I ../common

all: ht2crack5.c ht2crackutils.o hitagcrypto.o
	$(CC) $(CFLAGS) $(INC) -o ht2crack5gpu $< ht2crackutils.o hitagcrypto.o $(LIBS) -lpthread

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

ht2crackutils.o: ht2crackutils.c ht2crackutils.h
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

clean:
	rm -f *.o ht2crack5gpu
fresh: clean all
