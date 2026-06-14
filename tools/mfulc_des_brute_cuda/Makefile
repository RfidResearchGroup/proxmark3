NVCC ?= nvcc
TARGET ?= mfulc_des_brute_cuda
SOURCES := main.cu desbrute.cu

NVCCFLAGS ?= -O3 -std=c++14

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) desbrute.h des_host.h
	$(NVCC) $(NVCCFLAGS) -o $@ $(SOURCES)

clean:
	rm -f $(TARGET)
