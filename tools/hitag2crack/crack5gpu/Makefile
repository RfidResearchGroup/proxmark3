CFLAGS?=-Wall
#INCLUDE=-I/usr/local/cuda-7.5/include
INCLUDE=-I/opt/nvidia/cuda/include
#Linux
#LIBS=-L/usr/local/cuda-7.5/lib64 -lOpenCL
LIBS=-L/opt/nvidia/cuda/lib64 -lOpenCL
#Mac
#LIBS=-framework OpenCL

all: ht2crack5.c utilpart.o ht2crack2utils.o hitagcrypto.o
	$(CC) $(CFLAGS) ht2crack5.c -o ht2crack5gpu utilpart.o ht2crack2utils.o hitagcrypto.o $(LIBS) -lpthread

utilpart.o: util.h utilpart.c
	$(CC) $(CFLAGS) $(INCLUDE) -c utilpart.c

hitagcrypto.o: hitagcrypto.h hitagcrypto.c
	$(CC) $(CFLAGS) $(INCLUDE) -c hitagcrypto.c

ht2crack2utils.o: ht2crack2utils.h ht2crack2utils.c
	$(CC) $(CFLAGS) $(INCLUDE) -c ht2crack2utils.c

clean:
	rm -f *.o ht2crack5gpu
fresh: clean all
