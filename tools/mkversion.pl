#!/usr/bin/perl -w

# Output a version.c file that includes information about the current build
# Normally a couple of lines of bash would be enough (see openpcd project, original firmware by Harald Welte and Milosch Meriac)
# but this will, at least in theory, also work on Windows with our current compile environment.
# -- Henryk Plötz <henryk@ploetzli.ch> 2009-09-28
# Modified april 2014 because of the move to github.
# --- Martin Holst Swende <martin@swende.se>
# Modified january 2016 to work with Travis-CI
# --- iceman <iceman@iuse.se>

# Clear environment locale so that git will not use localized strings
$ENV{'LC_ALL'} = "C";
$ENV{'LANG'} = "C";

# if you are making your own fork,  change this line to reflect your fork-name
my $fullgitinfo = 'RRG/Iceman';
my $ctime;
# GIT status  0 = dirty,  1 = clean ,  2 = undecided
my $clean = 2;

# Do we have acces to git command?
#######
# solves some bug on macos i.e:
##
# perl ../tools/mkversion.pl .. > version.c || cp ../common/default_version.c version.c
# /usr/bin/which: /usr/bin/which: cannot execute binary file
# fatal: No names found, cannot describe anything.
##
# anyway forcing any kind of shell is at least useless, at worst fatal.
my $commandGIT = "env which git";

if ( defined($commandGIT) )  {

    # this goes on Internet and cause major slowdowns on poor connections or intranets, let's comment it
    #my $githistory = `git fetch --all`;
    # now avoiding the "fatal: No names found, cannot describe anything." error by fallbacking to abbrev hash in such case
    my $gitversion = `git describe --dirty --always`;
    my $gitbranch = `git rev-parse --abbrev-ref HEAD`;
    $clean = $gitversion =~ '-dirty' ? 0 : 1;

    if ( defined($gitbranch) and defined($gitversion) ) {
        $fullgitinfo =  $fullgitinfo.'/'. $gitbranch . '/' . $gitversion;

        my @compiletime = localtime();
        $compiletime[4] += 1;
        $compiletime[5] += 1900;
        $ctime = sprintf("%6\$04i-%5\$02i-%4\$02i %3\$02i:%2\$02i:%1\$02i", @compiletime);
    } else {
        $fullgitinfo =  $fullgitinfo.'/master/release (git)';
    }
} else {
    $fullgitinfo =  $fullgitinfo.'/master/release (no_git)';
    my @dl_time = localtime( (stat('../README.md'))[10] );
    $dl_time[4] += 1;
    $dl_time[5] += 1900;
    $ctime = sprintf("%6\$04i-%5\$02i-%4\$02i %3\$02i:%2\$02i:%1\$02i", @dl_time);
}

$fullgitinfo =~ s/(\s)//g;

# Crop so it fits within 50 characters
#$fullgitinfo =~ s/.{50}\K.*//s;
$fullgitinfo = substr $fullgitinfo, 0, 49;

print <<EOF
#include "proxmark3.h"
/* Generated file, do not edit */
const struct version_information __attribute__((section(".version_information"))) version_information = {
    VERSION_INFORMATION_MAGIC,
    1,
    1,
    $clean,
    "$fullgitinfo",
    "$ctime",
};
EOF
