# Fixing git blame

If this isn't working for you, ensure you've configured git to use the generated file:
```
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

To update the checked-in data:
```
./filter_git_blame.sh
```




## Genesis of the shell script

It all started out seeming so easy.

This is the messy story, without pulling punches, showing how I
got from a simple one-liner, to the final script now setup
for filtering git blame results.

It all started with a dream of simply doing:

```
git log --grep="^make style$" --grep="^style$" --grep="^cppcheck" --format="%H"  | sort -u > .git-blame-ignore-revs
```

But this wasn't matching the first two patterns against the entire commit message,
it was matching against ANY of the (potentially many) lines in the commit message.

## Fixup how to get the commits of interest....

My goal was to match only when the **entire** commit message begins with the pattern.
For some patterns, I wanted to match against the entire multi-line message.

This seemed like something designed for `awk`, and `git log --format=...` allows
inserting null characters, so I started throwing things together.
I started with the format message `'%H%x00%B'` ... the multi-line commit message, null byte, the commit hash.

For `awk`, `RS='\0'` make the null character the record separator.  Thus began
my journey into madness.

### Attempt #1 ...

#### Verify the output format

```
clear; git log --format='%H%x00%B' -n 3
```

Looks good.

#### Verify AWK is parsing one commit + hash

```
clear; git log --format='%H%x00%B' -n 3 | awk -v RS='\0' '{ print "\nvvvvvvvvvvvvvvvv\n" $0 "\n^^^^^^^^^^^^^^^^\n" }'
```

This is NO GOOD.  The first hash is considered a record by itself.
Then the first message + second hash are taken together.

### Attempt #2 ...

Let's try to have each record be of the form:

`([0-9a-fA-F]{40})\n([^\x00]*)\x00`, which means that
`$1` == commit hash, and
`$2` == message body.

#### Verify the output format

```
clear; git log --format='%H%n%B%x00' -n 3
```

Looking good.

#### Verify AWK is parsing one commit + hash

```
clear; git log --format='%H%n%B%x00' -n 3 | awk -v RS='\0' '{ print "\nvvvvvvvvvvvvvvvv\n" $0 "\n^^^^^^^^^^^^^^^^\n" }'
```

This is OK, although the hashes in second and later records have a prepended newline.
That's easy enough to workaround.


#### Verify AWK is splitting $1 as commit hash and $2 as message

```
clear; git log --format='%H%n%B%x00' -n 3 | awk -v RS='\0' '{ print "\nvvvvvvvvvvvvvvvv\n" $0 "\n--------\n" $1 "\n--------\n" $2 "\n^^^^^^^^^^^^^^^^\n" }'
```

And... failure.   Apparently, AWK split the records on the null
character, but continues to split the fields with `[ \t\n]+` (default field separator).

### Attempt #3 ...

Maybe change each record to be of the form:

`([0-9a-fA-F]{40})\x00([^\x00]*)\x00`, which means that
`$1` == commit hash, and
`$2` == message body.

Then, maybe we can make the field separator be the null character.

#### Verify the output format

```
clear; git log --format='%H%x00%B%x00' -n 3
```

Looks good.


#### Verify AWK is parsing one commit + hash

```
clear; git log --format='%H%x00%B%x00' -n 3 | awk -v RS='\0' '{ print "\nvvvvvvvvvvvvvvvv\n" $0 "\n^^^^^^^^^^^^^^^^\n" }'
```

This is problematic ... it's only getting EITHER the commit hash OR the commit message.
Of course, this makes sense after I thought about it.  The records separator was the
null byte, and I'd effectively split one record into two.

This is likely workable, by parsing all the lines, then matching them up.
Defer that ... it seems too much work.   There might be an easier way.

#### Verify AWK is splitting $1 as commit hash and $2 as message

... moot ...

### Attempt #4 ...

Let's return to having each record be of the form:

`([0-9a-fA-F]{39})\n([^\x00]*)\x00`, which means that
`$1` == commit hash, and
`$2` == message body.

We can probably rely on the commit hash being a hex string,
and then parse the rest.


#### Verify the output format

```
clear; git log --format='%H%n%B%x00' -n 3
```

Looks good....

#### Verify AWK is parsing one commit + hash

```
clear; git log --format='%H%n%B%x00' -n 3 | awk -v RS='\0' '{ print "\nvvvvvvvvvvvvvvvv\n" $0 "\n^^^^^^^^^^^^^^^^\n" }'
```

Note that records after the first have an additional newline, prior to the hash,
and `$0` is the entire record, in the form:

`^\n?([0-9A-Fa-f]{40})\n([^\x00]*)$`

This will put the entire message (including multi-line) into match group 2,
while the hash is in match group 1.

#### Verify AWK is splitting $1 as commit hash and $2 as message

We cannot just change FS to `\n`, because `awk` doesn't have a simple way
to say, "all the fields after $1", and we want all lines of the multiline
commit messages.

So, first split matches[1] = commit hash, matches[2] = full message
(including multiline) using match.  Verify this.

NOTE: This is effectively multiline matching because `RS` is no longer `\n`.

```
clear; git log --format='%H%n%B%x00' -n 3 | awk -v RS='\0' '{
    if (match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) {
        print "\nvvvvvvvvvvvvvvvv\n" matches[0] "\n--------\n" matches[1] "\n--------\n" matches[2] "\n^^^^^^^^^^^^^^^^\n"
    }
}'
```

Looks promising....

#### Limit output count at matching stage.

Thus far, I was limiting the output by limiting the count at `git log`.
Instead, limit the output within the `awk` script itself.

NOTE: This is effectively multiline matching because `RS` is no longer `\n`.

```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '{
    if (match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) {
        print "\nvvvvvvvvvvvvvvvv\n" matches[0] "\n--------\n" matches[1] "\n--------\n" matches[2] "\n^^^^^^^^^^^^^^^^\n"
        if (++count == 3) exit
    }
}'
```

So far, so good....


#### Filter to only the interesting messages

Can try this directly in first match, but it's messy and hard to maintain,
and also hard to validate that each match type works.

```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '{
    if (match($0, /^\n?([0-9A-Fa-f]{40})\n((make style(\r?\n)?$)|(style(\r?\n)?$)|(cppcheck[.\r\n]*$))/, matches)) {
        print "\nvvvvvvvvvvvvvvvv\n" matches[0] "\n--------\n" matches[1] "\n--------\n" matches[2] "\n^^^^^^^^^^^^^^^^\n"
        if (++count == 10) exit
    }
}'
```

While there was output, it did not provide any confidence.
Need to try something different...

#### Easier to maintain filtering

After first use of `match()` to split the commit from the message,
remove any trailing `\n` and `\r\n` from the end of the message.

Compare the matches individually, and have `0` lines just
to make it easy to track additions/removals/changes in source
control (which is typically line-based).

```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '{
    if (match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) {
        msg = matches[2]
        sub(/( *(\r?\n))+$/, "", msg)
        if (0                          ||
            msg ~ /^make style$/       ||
            msg ~ /^make miscchecks$/  ||
            msg ~ /^cppcheck/          ||
            0) {
            print "\nvvvvvvvvvvvvvvvv\n" matches[0] "\n--------\n" matches[1] "\n--------\n`" msg "`\n^^^^^^^^^^^^^^^^\n"
            if (++count == 3) exit
        }
    }
}'
```

Meh. Able to comment out lines to test, but still
feels blargh.

#### Easier to validate filtering

Let's match individually, and limit each match type to
only print four times.   This should allow easily reviewing
the output.


```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '{
    if (match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) {
        do_print = 0
        msg = matches[2]
        sub(/( *(\r?\n))+$/, "", msg)
        if (msg ~ /^make style$/) {
            if (++cnt_make_style < 4) {
                do_print = 1
            }
        } else if (msg ~ /^make miscchecks$/) {
            if (++cnt_make_miscchecks < 4) {
                do_print = 1
            }
        } else if (msg ~ /^cppcheck/){
            if (++cnt_cppcheck < 4) {
                do_print = 1
            }
        }
        if (do_print) {
            print "\nvvvvvvvvvvvvvvvv\n" matches[0] "\n--------\n" matches[1] "\n--------\n`" msg "`\n^^^^^^^^^^^^^^^^\n"
        }
    }
}'
```

OK, that worked.  Still want something better....


#### Make it table-based?

`awk` has both `BEGIN` and `END` blocks.  Use the `BEGIN`
block to setup a table of patterns to be matched, along
with a limit for how many of those matches to dump to screen.
Use the `END` block to provide a summary of how many lines matched

```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '
    BEGIN {
        # Table for easier testing
        # Set limits[i]   to 0 to suppress printing altogether, else count of matches that print
        # Set found[i]    to 0
        # Set patterns[i] to the regex-like match pattern
        i = 0
        limits[i] = 0; found[i] = 0; patterns[i++] = "^make style$"
        limits[i] = 0; found[i] = 0; patterns[i++] = "^make miscchecks$"
        limits[i] = 0; found[i] = 0; patterns[i++] = "^cppcheck"
        total_pattern_count = i
        total_records = 0
        total_records_compared_against_patterns = 0
        total_records_matched_patterns = 0
    }
    {
        ++total_records
        if (!match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) {
            # Turns out only whitespace ... so false positive?
            # print "FAIL: \n------\n" $0 "\n-------\n
            next
        }
        ++total_records_compared_against_patterns

        # Only print once, even if matches multiple table entries
        do_print = 0
        any_match = 0

        # message ... remove trailing whitespace and blank lines
        msg = matches[2]
        sub(/( *(\r?\n))+$/, "", msg)

        # try each pattern in the table
        for (i in patterns) {
            if (msg ~ patterns[i]) {
                any_match = 1
                if (found[i]++ < limits[i]) {
                    do_print = 1
                }
            }
        }
        if (any_match) {
            ++total_records_matched_patterns
        }
        if (do_print) {
            print "\nvvvvvvvvvvvvvvvv\n" matches[0] "\n--------\n" matches[1] "\n--------\n`" msg "`\n^^^^^^^^^^^^^^^^\n"
        }
    }
    END {
        # Print table header and separator line
        printf "Searched %d (%d) records, %d records matched a pattern\n\n", total_records_compared_against_patterns, total_records, total_records_matched_patterns
        printf " Count  | Pattern\n"
        printf "--------|---------------------\n", found[i], patterns[i]
        for (i in patterns) {
            # Print found count, right-aligned 7 characters, followed by pattern
            printf "%7d | %s\n", found[i], patterns[i]
        }
    }    
    '
```

### Print ONLY the commit message

#### Starting from the table-based solution....

```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '
    BEGIN {
        # Table for easier testing
        # Set limits[i]   to 0 to suppress printing altogether, else count of matches that print
        # Set found[i]    to 0
        # Set patterns[i] to the regex-like match pattern
        i = 0
        limits[i] = 0; found[i] = 0; patterns[i++] = "^make style$"
        limits[i] = 0; found[i] = 0; patterns[i++] = "^make miscchecks$"
        limits[i] = 0; found[i] = 0; patterns[i++] = "^cppcheck"
        total_pattern_count = i
        total_records = 0
        total_records_compared_against_patterns = 0
        total_records_matched_patterns = 0
    }
    {
        ++total_records
        if (!match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) {
            # Turns out only whitespace ... so false positive?
            # print "FAIL: \n------\n" $0 "\n-------\n
            next
        }
        ++total_records_compared_against_patterns

        # Only print once, even if matches multiple table entries
        do_print = 0
        any_match = 0

        # message ... remove trailing whitepace and blank lines
        msg = matches[2]
        sub(/( *(\r?\n))+$/, "", msg)

        # try each pattern in the table
        for (i in patterns) {
            if (msg ~ patterns[i]) {
                any_match = 1
                if (found[i]++ < limits[i]) {
                    do_print = 1
                }
            }
        }
        if (any_match) {
            ++total_records_matched_patterns
        }
        if (do_print) {
            print "\nvvvvvvvvvvvvvvvv\n" matches[0] "\n--------\n" matches[1] "\n--------\n`" msg "`\n^^^^^^^^^^^^^^^^\n"
        }
    }
    END {
        # Print table header and separator line
        printf "Searched %d (%d) records, %d records matched a pattern\n\n", total_records_compared_against_patterns, total_records, total_records_matched_patterns
        printf " Count  | Pattern\n"
        printf "--------|---------------------\n", found[i], patterns[i]
        for (i in patterns) {
            # Print found count, right-aligned 7 characters, followed by pattern
            printf "%7d | %s\n", found[i], patterns[i]
        }
    }    
    '
```

#### Reduce it

```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '
    BEGIN {
        i = 0
        patterns[i++] = "^make style$"
        patterns[i++] = "^make miscchecks$"
        patterns[i++] = "^cppcheck"
    }
    {
        if (!match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) next

        # Only print once, even if matches multiple table entries
        do_print = 0

        # message ... remove trailing whitepace and blank lines
        msg = matches[2]
        sub(/( *(\r?\n))+$/, "", msg)

        # try each pattern in the table
        for (i in patterns) {
            if (msg ~ patterns[i]) {
                do_print = 1
            }
        }
        if (do_print) {
            print matches[1]
        }
    }
'
```

## Final Solution

```
clear; git log --format='%H%n%B%x00' | awk -v RS='\0' '
    BEGIN {
        i = 0
        patterns[i++] = "^make style$"
        patterns[i++] = "^make miscchecks$"
        patterns[i++] = "^cppcheck"
    }
    {
        if (!match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) next

        # Only print once, even if matches multiple table entries
        do_print = 0

        # message ... remove trailing whitepace and blank lines
        msg = matches[2]
        sub(/( *(\r?\n))+$/, "", msg)

        # try each pattern in the table
        for (i in patterns) {
            if (msg ~ patterns[i]) {
                do_print = 1
            }
        }
        if (do_print) {
            print matches[1]
        }
    }
' | sort --unique --ignore-case > .git-blame-ignore-revs
```
