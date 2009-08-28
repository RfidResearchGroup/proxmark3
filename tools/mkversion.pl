#!/usr/bin/perl
# Output a version.c file that includes information about the current build
# Normally a couple of lines of bash would be enough (see openpcd project, original firmware by Harald Welte and Milosch Meriac)
# but this will, at least in theory, also work on Windows with our current compile environment.
# -- Henryk Plötz <henryk@ploetzli.ch> 2009-09-28

my $main_dir = shift;

# Clear environment locale so that svn will not use localized strings
$ENV{'LC_ALL'} = "C";
$ENV{'LANG'} = "C";

my $svnversion = 0;
my $present = 0;
my $clean = 2;
my @compiletime = gmtime();

# Strategy one: call svn info and extract last changed revision, call svn status and look for ^M
if(open(SVNINFO, "svn info $main_dir|")) {
	while(<SVNINFO>) {
		if (/^Last Changed Rev: (.*)/) {
			$present = 1;
			$svnversion = $1;
			## last; # Do not abort here, since SVN tends to complain about a Broken pipe
		}
	}
	close(SVNINFO);
	
	if(open(SVNSTATUS, "svn status $main_dir|")) {
		$clean = 1;
		while(<SVNSTATUS>) {
			if(/^M/) {
				$clean = 0;
				## last;
			}
		}
		close(SVNINFO);
	}
	
} else {
	# Strategy two: look for .svn/entries. The third line should be "dir", the fourth line should contain the current
	#  revision.
	if(open(ENTRIES, "$main_dir/.svn/entries")) {
		my $i = 1;
		while(<ENTRIES>) {
			last if($i == 3 and !/^dir/);
			if($i == 4 and /^([0-9]*)/) {
				$present = 1;
				$svnversion = $1;
			}
			$i++;
		}
	}
}

$compiletime[4] += 1;
$compiletime[5] += 1900;
my $ctime = sprintf("%6\$04i-%5\$02i-%4\$02i %3\$02i:%2\$02i:%1\$02i", @compiletime);

print <<EOF
#include <proxmark3.h>
/* Generated file, do not edit */
struct version_information __attribute__((section(".version_information"))) version_information = {
	VERSION_INFORMATION_MAGIC,
	1,
	$present,
	$clean,
	"svn $svnversion",
	"$ctime",
};
EOF
