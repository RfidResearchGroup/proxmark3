# Notes on Color usage
<a id="Top"></a>


# Table of Contents
- [Notes on Color usage](#notes-on-color-usage)
- [Table of Contents](#table-of-contents)
  - [style/color](#stylecolor)
    - [Definition](#definition)
    - [Styled header](#styled-header)
    - [non styled header](#non-styled-header)
  - [Proxspace](#proxspace)
  - [Help texts](#help-texts)

The client should autodetect color support when starting.

You can also use the command  `pref show` to see and set your personal setting.  

Why use colors in the Proxmark client? When everything is white it is hard to extract the important information fast. You also need new-lines for extra space to be easier to read.
We have gradually been introducing this color scheme into the client since we got decent color support on all systems: OSX, Linux, WSL, Proxspace.


## style/color
^[Top](#top)

The following definition has be crystallized out from these experiments.  Its not set in stone yet so take this document as a guideline for how to create unified system scheme.

### Definition
^[Top](#top)

- blue - system related headers
- white  - normal
- cyan - headers, banner
- red - warning, error,  catastrophic failures
- yellow - informative  (to make things stick out from white blob)
- green - successful,  (to make things stick out from white blob)
- magenta - device side messages


### Styled header
^[Top](#top)

```
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
```
For more examples, see also all **-h**  helptext now in the LUA scripts.
For the command help texts using _YELLOW_ for the example makes it very easy to see what is the command vs the description.

### non styled header
^[Top](#top)

Most commands doesn't use a header yet. We added it to make it standout (ie: yellow,  green) of the informative tidbits in the output of a command. 


## Proxspace
^[Top](#top)

Proxspace has support for colors.


## Help texts
^[Top](#top)

The help text uses a hard coded template deep inside the cliparser.c file.