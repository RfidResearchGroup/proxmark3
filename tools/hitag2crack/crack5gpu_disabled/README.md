ht2crack5gpu



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
./ht2crack5gpu <UID> <nR1> <aR1> <nR2> <aR2>
```

UID is the UID of the tag that you used to gather the nR aR values.
