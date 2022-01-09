Initial author of the Proxmark3 code is Jonathan Westhues, starting in August 2005.  
His latest release was done in May 2007 and is available [here](https://cq.cx/dl/proxmark3-may23-2007.zip) (copy available [here](http://proxmark.org/files/J.Westhues/)).

Initial copyright notice is therefore:  
Copyright (C) 2005-2007 Jonathan Westhues

Since then, each contribution is under the copyright of its respective author.

A few releases were done by the Proxmark community between 2007 and March 2009 before using version control.  
The last release which served as basis for version control, under SVN then migrated to Git, was the `20090306_ela` release by Edouard Lafargue. See the first commit of this repository.

Therefore, only the following copyright notices are left untouched in the corresponding files:
- copyright notices present in the `20090306_ela` release
- copyright notices of code borrowed from other projects
- copyright notices of standalone modes initial authors
- copyright notices of dependencies (client/deps, common)

Since then, copyright of each contribution is tracked by the Git history. See the output of `git shortlog -nse` for a full list or `git log --pretty=short --follow <path/to/sourcefile> |git shortlog -ne` to track a specific file. See also [the Contributors page on Github](https://github.com/RfidResearchGroup/proxmark3/graphs/contributors) and [this Gource animation](https://www.youtube.com/watch?v=N7vpk0iIq9s) retracing the commits history from March 2009 until January 2022.

A [mailmap](.mailmap) is maintained to map author and committer names and email addresses to canonical names and email addresses.

If by accident a copyright was removed from a file and is *not* directly deducible from the Git history, please submit a PR.
