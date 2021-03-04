ht2crack5opencl



Build
-----

It requires an OpenCL framework.

If required, edit Makefile and adjust INCLUDE and LIBS directives to your setup.

```
make clean
make
```

Run
---

You'll need just two nR aR pairs.  These are the
encrypted nonces and challenge response values.  They should be in hex.

```
./ht2crack5opencl <UID> <nR1> <aR1> <nR2> <aR2>
```

UID is the UID of the tag that you used to gather the nR aR values.

Usage:

```
$ ./ht2crack5opencl
./ht2crack5opencl [options] {UID} {nR1} {aR1} {nR2} {aR2}

Options:
-p     : select OpenCL Platform(s). Multiple allowed (1,2,3,etc.). [Default: all]
-d     : select OpenCL Device(s). Multiple allowed (1,2,3,etc.). [Default: all]
-D     : select OpenCL Device Type. 0: GPU, 1: CPU, 2: all. [Default: GPU]
-S     : select the thread scheduler type. 0: sequential, 1: asynchronous. [Default 1]
-P     : select the Profile, from 0 to 10. [Default: auto-tuning]
-F     : force verify key with OpenCL instead of CPU. [Default: disabled]
-Q     : select queue engine. 0: forward, 1: reverse, 2: random. [Default: 0]
-s     : show the list of OpenCL platforms/devices, then exit
-V     : enable debug messages
-v     : show the version
-h     : show this help

Example, select devices 1, 2 and 3 using platform 1 and 2, with random queue engine:

./ht2crack5opencl -D 2 -Q 2 -p 1,2 -d 1,2,3 2ab12bf2 4B71E49D 6A606453 D79BD94B 16A2255B
```

You can find the correct OpenCL Platform ID (-p) and Device ID (-d) with:

```
./ht2crack5opencl -s
```
