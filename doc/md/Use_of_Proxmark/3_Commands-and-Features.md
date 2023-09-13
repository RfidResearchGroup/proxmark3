<a id="Top"></a>

# 3. Commands and Features

# Table of Contents
- [3. Commands and Features](#3-commands-and-features)
- [Table of Contents](#table-of-contents)
  - [To get interactive help](#to-get-interactive-help)
  - [New Features in RDV4](#new-features-in-rdv4)
  - [Useful commands](#useful-commands)
- [Hardnested tables](#hardnested-tables)



Please make sure you've gone through the following pages firstly:

* [Compilation Instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)
* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)

## To get interactive help
^[Top](#top)

As seen before, for basic help type `help`. Or for help on a set of sub commands type the command followed by `help`. For example `hf mf help`.  Many commands uses the `-h` / `--help` parameter to show a help text.

The Proxmark3 client now also supports tab-autocomplete in both commands and filenames. Like for instance `hf mf a<tab>`  will give you a list of three availble commands.  
This feature is quite powerful and similar to your normal shell experiences.


## New Features in RDV4
^[Top](#top)

Further details coming soon

## Useful commands
^[Top](#top)

Here are some commands to start off with.

To get an overview of the available commands for LF RFID and HF RFID:
```
[usb] pm3 --> lf
[usb] pm3 --> hf
```

To search quickly for known LF or HF tags:
```
[usb] pm3 --> lf search
[usb] pm3 --> hf search
```

To get info on a ISO14443-A tag:
```
[usb] pm3 --> hf 14a info
```

A good starting point is the following [Cheat sheet](/doc/cheatsheet.md)

Or 

this compilation of links to [Proxmark3 walk throughs](https://github.com/RfidResearchGroup/proxmark3/wiki/More-cheat-sheets)

# Hardnested tables
^[Top](#top)

Hardnested tables are compressed with LZ4 for a good compromise between space and decompression speed.

If you are under very space constrained environment, you can recompress the tables with BZip2 and delete the LZ4. It will break the git workdir but if space is a concern, you're not deploying the source and `.git` of > 80Mb anyway, do you?

```sh
cd client/resources/hardnested_tables
lz4 -dm --rm *lz4
bzip2 *.bin
```

If you want top speed, you can decompress the tables in advance. Keep the `.lz4` files, so you can always just `rm *.bin` to save space again.

```sh
cd client/resources/hardnested_tables
lz4 -dkm *lz4
```

| Compression | Size in Mb |   Speed(*)  |
|-------------|:----------:|:-----------:|
| LZ4         | 9          | 1           |
| BZip2       | 2          | 6.5x slower |
| None        | 704        | 2.5x faster |

(*) rough idea of relative speeds, real numbers depend on your actual system
