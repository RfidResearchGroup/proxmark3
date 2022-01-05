
# Contributing to Proxmark3

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

This guide covers mostly coding style for submitting pull requests, but you can also contribute by [Reporting Bugs](https://github.com/RfidResearchGroup/proxmark3/issues) and [Suggesting Enhancements](https://github.com/RfidResearchGroup/proxmark3/issues) after having carefully checked that a corresponding issue doesn't exist yet.

Beware we're all very busy so the best way is by providing yourself some fixes and enhancements via [Pull Requests](https://github.com/RfidResearchGroup/proxmark3/pulls) respecting the following coding style.

[Styleguides](#styleguides)
  * [Overview](#overview)
  * [Indentation](#indentation)
  * [Width](#width)
  * [Macros](#macros)
  * [Identifiers](#identifiers)
  * [Data types](#data-types)
  * [Expressions](#expressions)
  * [If / for / while etc](#if-for-while-etc)
  * [Functions](#fonctions)
  * [Structs / unions / enums](#structs-unions-enums)
  * [Switch](#switch)
  * [Comments](#comments)
  * [File](#file)
  * [File headers](#file-headers)
  * [Header files](#header-files)
  * [Whitespace](#whitespace)

# Styleguides

_"Coding styles are like assholes, everyone has one and no one likes anyone elses."_
--Eric Warmenhoven

## Overview

We have established a set of coding style guidelines in order to
clean up the code consistently and keep it consistent in the future.
Look around and respect the same style.

Helper script to get some uniformity in the style:

```bash
$ make style
```

It makes use of `astyle` so be sure to install it first.


## Indentation

Don't use tabs, editors are messing them up too easily.
Increment unit is four spaces.

If you use `make style`, this will be done for you.

## Width

Try to keep lines to a reasonable length. 80 characters is a good mark; using an
editor that shows a vertical line is a great idea. However, don't break a line
just because you're slightly over, it's not worth it. No 200-character lines,
though.

## Macros

`#define`, function-like or not, are all UPPERCASE unless you're emulating a
well-known function name.

## Identifiers

Functions, local variables, and arguments are all named using
`underscores_as_spaces`. Global variables are Evil and are prepended with `g_` to
distinguish them. Avoid them.

Single-character variables are a bad idea. Exceptions: loop iterators and maybe
simple byte pointers (`*p`) in very obvious places. If you have more than one
such pointer, use a real name. If you have more than a couple nested loops,
complex logic, or indices that differ in interpretation or purpose, use real
names instead of i,j,k.

## Data types

Use `stdint.h` types (`uint32_t` and friends) unless you have a reason not to. Don't
use microsoft-style `DWORD` and the like, we're getting rid of those. Avoid char
for buffers, `uint8_t` is more obvious when you're not working with strings. Use
`const` where things are const. Try to use `size_t` for sizes.

Pointers and reference operators are attached to the variable name:
```c
    void *ptr;
```
not:
```c
    void* ptr;
```
otherwise you're tempted to write:
```c
    void* in, out;
```
and you'll fail.

`make style` will take care of pointers & reference operators.

## Expressions

In general, use whitespace around binary operators - no unspaced blobs of an
expression. `make style` will take care of whitespaces around operators.

For example,
```c
    if (5 * a < b && some_bool_var)
```
but not
```c
    if (5*a<b&&some_bool_var)
```
For equality with constants, use `i == 0xF00`, not `0xF00 == i`. The compiler warns
you about `=` vs `==` anyway, and you shouldn't be screwing that one up by now
anyway.

## If / for / while etc

Put the opening brace on the same line, with a space before it.
There should be a space between the construct name (if/for/whatever) and the
opening parenthesis, and there should be a space between the closing parenthesis
and the opening brace, and no space between parenthesis and expression.
`make style` will take care of all that.

If you do split the condition, put the binary operators that join the lines at
the beginning of the following lines, not at the end of the prior lines.

For generic `for()` iterator variables, declare them in-line:
```c
    for (int i = 0; i < 10; i++) {
        ...
    }
```
Note the spaces after the semicolons.

if/else should be laid out as follows:
```c
    if (foo) {
        ...
    } else if (bar) {
        ...
    } else {
        ...
    }
```
You can skip braces around 1-line statements but don't mix braces vs. no braces.

## Functions

Put the return type on the same line.
Put a space after a comma in argument lists.
Open the brace after the declaration (after a space).
`make style` will take care of all that.
```c
void foo(int a_thing, int something_else) {
    ...
}
```
Functions with no arguments are declared as `f(void)`, not `f()`.
Use static for functions that aren't exported, and put exported functions
in a header file (one header file per source file with exported functions
usually, no huge headers with all functions). 
```c
void baz(void) {
    foo(bluh, blah);
}
```
Function names should be `separated_with_underscores()`, except for standard
functions (`memcpy`, etc.). It may make sense to break this rule for very common,
generic functions that look like library functions (e.g. `dprintf()`).

Don't use single-character arguments.
Exception: very short functions with one argument that's really obvious:
```c
static int ascii(char c) {
    if (c < 0x20 || c >= 0x7f)
        return '.';
    else
        return c;
}
```
vs.
```c
static void hexdump(void *buf, size_t len) {
    ...
}
```
As a general guideline, functions shouldn't usually be much more than 30-50
lines. Above, the general algorithm won't be easily apparent, and you're
probably missing some factoring/restructuring opportunity.

## Structs / unions / enums

Use typedefs when defining structs. The type should be named something_t.
```c
typedef struct {
    blah blah;
} prox_cmd_t;
```
You can use anonymous enums to replace lots of sequential or mostly-sequential
#defines.

## Switch

Indent once for the `case:` labels, then again for the body. Like this:
```c
switch(bar) {
    case OPTION_A:
        do_stuff();
        break;
    case OPTION_B:
        do_other_stuff();
        break;
}
```
`make style` will take care of the indentation.

If you fall through into another case, add an explicit comment;
otherwise, it can look confusing.

If your `switch()` is too long or has too many cases, it should be cleaned up.
Split off the cases into functions, break the switch() into parent and children
switches (e.g. command and subcommand), or use an array of function pointers or
the like. In other words, use common sense and your brain.

If you need local scope variables for a case, you can add braces:
```c
switch(bar) {
    case OPTION_A: {
        int baz = 5 * bar;
        do_stuff(baz);
        break;
    }
    ...
```
But at that point you should probably consider using a separate function.

## Comments

Use //, it's shorter:
```c
// this does foo
...

// baz:
// This does blah blah blah .....
// blah blah...
```
`/* */` can be used to comment blocks of code, but you should probably remove
them anyway - we have version control, it's easy to fetch old code if needed,
so avoid committing commented out chunks of code. The same goes for `#if 0`.

## File

Please use common sense and restrain yourself from having a thousands line
file. Functions in a file should have something *specific* in common. Over time
sub-categories can arise and should therefore yield to file splitting.

For these reasons, vague and general filenames (e.g. `util.*`, `global.*`, `misc.*`,
`main.*`, and the like) should be very limited, if not prohibited.

## File headers

License/description header first:
```c
//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// FILE DESCRIPTION GOES HERE
//-----------------------------------------------------------------------------
```

To avoid a huge mess of copyright notices in the source files, it has been chosen to keep this generic notice. Don't worry, you still hold the copyright on your respective contributions and date and authorship are tracked by the Git history, as explained in [AUTHORS](AUTHORS.md).
In January 2022, the Git history has recorded 293 different authors.

## Header files

Use the following include guard format:
```c
#ifndef FOOBAR_H__
#define FOOBAR_H__

...

#endif // FOOBAR_H__
```
Keep in mind that `__FOOBAR_H` would be reserved by the implementation and thus
you shouldn't use it (same for `_FOOBAR_H`).

## Whitespace

Avoid trailing whitespace (no line should end in tab or space).
Keep a newline (blank line) at the end of each file.

`make style` will take care of both.
