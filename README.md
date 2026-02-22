![rling logo](/img/rling_256.png)

# rling - a better rli
> rling is similar to the rli utility found in [hashcat-utils](https://github.com/hashcat/hashcat-utils), but much, much faster

## Table of contents
* [General info](#general-info)
* [Technologies](#technologies)
* [Setup](#setup)
* [Usage](#usage)
* [Options](#options)
* [Examples](#examples)
* [Features](#features)
* [Status](#status)
* [Inspiration](#inspiration)
* [Contact](#contact)

## General info
In July, 2020, @tychotithonus asked a simple question - theoretically, could rli be faster?  Answering that question took the CynoSurePrime team down several roads, looking for "the better ways" to handle the problem. It ended up in a "how many nanoseconds" race in the end!

The essential task of removing lines from a file (or a database) has been fundamental to computing since the very earliest days, and rli seems "good enough" for most purposes.  But when the files get large, the amount of RAM used by rli is high, and the performance was not sufficient to the task at hand.  @tychotithonus also wanted a few new features.

The performance of rling is impressive (this done on a Power8 system with 80 cores). 1billion.txt is a ~10gigabyte file containing 1,000,000,000 lines.  rem is a file containing 6 lines matching ones scattered throughout the 1billion.txt file.

| Program | Input    |  Remove | Memory | Time |
| ------- | -------- | ------- | ------ | ---- |
| rli | 1billion.txt | rem | 59.7g | 12m37s |
| rli | 1billion.txt | 1billion.txt | 59.7g | 22m14s |
| rling | 1billion.txt | rem | 38.0g | 22s |
| rling | 1billion.txt | 1billion.txt | 38.0g | 1m15s |
| rling -b | 1billion.txt | rem | 17.0g | 55s |
| rling -b | 1billion.txt | 1billion.txt | 17.0g | 1m36s |


## Technologies
* Dynamic sizing\
rling dynamically sizes the memory to be appropriate for the file.  By not having compiled-in limits for things like line lengths for the input lines, users are able to focus on novel use cases for the program.
* Hashing with xxHash\
xxHash is a great new hashing method - its very fast and portable.  By combining a dynamic (overridable) hash table with an excellent hash function, performance was accelerated greatly.  Also, because hash tables are sized dynamically, there is no need to guess "optimal" hash sizes.
* Multi threaded Binary searches and sorts\
Thanks to blazer's multi threaded qsort, sorts are very fast, and make use of all of your system thread and multicore resources.  In general, hashing is faster than binary search, but binary search uses half of the memory, and can be many times faster for certain kinds of input.
* Filesystem-based database for very large files\
If you need to process very large datasets, and don't have enough memory, the -f option allows you to use a Berkeley db-based database instead of in-memory.  This does allow unlimited file sizes, but you do need substantial free disk space.  Use the -M option to give it more cache for the database, and -T to tell it where to put the databases (defaults to current directory).
* Memory use estimates\
For large files, memory use can still be high.  rling displays the estimated amount of memory to be used as soon as practical after reading the input files.  This can still be "too late" for some use cases - in general, you need at least 2 times the input file size in memory.
* stdin/stdout/named pipes fully supported\
Thanks to the "read exactly once, write exactly once" method rling uses for file I/O, stdin/stdout and named pipes can be used in any position that requires a file name.  This is great for creating complex workloads.

## Setup
There are several precompiled binaries included with the distribution.  If your system is one of these, you are done.  If not, here are some things to watch out for\
* -DINTEL and -DPOWERPC\
The makefile has a few different options for compiling the code.  There is SSE Intel code used in a rling to improve finding the end of strings.  -DINTEL enables this code.
There was PowerPC specific altivec code, which has been removed (for now) as the code was changed to make the intristic memchr "fast enough" for rling.  On PowerPC platforms you should add -DPOWERPC and include -malitivec to allow for this.  -DAIX is a good idea if compiling on AIX, along with -maix64.
* Threads\
-pthread is used extensively in rling, so make sure you compile with it.
* 64-bit systems are pretty much essential\
While it may be possible to re-write portions of the code to run on 32-bit systems, it's probably going to hurt quite a bit.  Let me know if you do end up porting it to 32 bit, and why you think it was a good plan.

## Usage

```
rling [options] input output [remfile1 remfile2 ...]
```

| Argument | Description |
| -------- | ----------- |
| `input` | The input file to read. Use `stdin` to read from standard input. |
| `output` | The output file to write. Use `stdout` to write to standard output. |
| `remfile` | One or more files whose lines will be removed from the input. |

## Options

| Option | Description |
| ------ | ----------- |
| `-i` | Ignore missing or inaccessible files on the remove list instead of aborting. |
| `-d` | Remove duplicate lines from input (on by default). The first occurrence of each line is always kept. |
| `-D file` | Write duplicate lines to `file`. |
| `-n` | Do **not** remove duplicate lines from input. |
| `-c` | Output only lines **common** to both the input and the remove files. |
| `-s` | Sort output. Default is to preserve input order. Sorting makes `-b` and `-f` substantially faster. |
| `-t number` | Number of threads to use (default: all available cores). |
| `-p prime` | Force the hash table to a specific size. A power-of-two value uses shift-and-mask instead of modulo. |
| `-b` | Use binary search instead of hashing. Slower, but uses roughly half the memory. Produces the same output as the default hash mode. |
| `-2` | Use rli2 mode. All files must already be sorted. Very low memory usage. |
| `-f` | Use a file-backed Berkeley DB instead of memory. Slower, but supports very large files with limited RAM. |
| `-l len` | Limit all matching to a specific line length. Requires `-b`, `-2`, or `-f`. |
| `-M memsize` | Maximum memory for `-f` mode cache (e.g., `-M 4g`). |
| `-T path` | Directory to store temporary files in (default: current directory). |
| `-q [cahwsl]` | Frequency analysis on input. Flags: `a` all, `c` count, `h` histogram, `w` word, `l` length, `s` running statistics. Additional files on the command line will be matched against the input. |
| `-v` | Verbose mode. Displays timing for each section of the program. |
| `-h` | Display help. |

`stdin` and `stdout` can be used in place of any filename.

## Examples
There are many common, and not so common uses for rling.\
`rling big-file.txt new-file.txt /path/to/old-file.txt /path/to/others/*`\
This will read in big-file.txt, remove any duplicate lines, then check /path/to/old-file.txt and
all files matching /path/to/others/*.  Any line that is found in these files that also exists in big-file.txt will be removed.  Once all files are processed, new-file.txt is written with the lines that don't match.  This is a great way to remove lines from a new dictionary file, if already have them in your existing dictionary lists.

`rling -nb last-names.txt new-names.txt /path/to/names/[a-f]*`\
This will read last-names.txt, *not* remove duplicates (-n switch), and use binary search (-b) to remove any last names that match those lines in the files /path/to/names/[a-f]*.

`rling clean-list.txt clean-list.txt`\
This will read clean-list.txt, remove all duplicate lines, and re-write it (in original order) back to clean-list.txt.  This use is permitted (maybe not recommended, but permitted), because all of the input file is read into memory prior to opening the output file for writing.  Great if you are short on disk space, too.

`find /path/to/names -type f -print0 | xargs -0 gzcat | rling stdin stdout | gzip -9 > all-names.txt.gz`\
This will look in /path/to/names for all files, use gzcat to decompress or access them, pipe the result to rling which will then de-duplicate them all (keeping original order), and then pipe the resultant output to gzip -9 so as to create a new, de-duplicated name-list in compressed format.

`rling -c all-names.txt matching.txt /path/to/names/[a-f]\*`\
This will read in all-names.txt, then find only names in the input file, and present in one or more of the /path/to/names[a-f] files.  If there are no matching lines, no data is output to matching.txt.

`printf 'apple\nbanana\napple\ncherry\nbanana\ndate\n' | rling stdin stdout`\
Dedup always keeps the first occurrence of each line and preserves input order.  The output will be `apple`, `banana`, `cherry`, `date` — the second `apple` and `banana` are removed.  This is deterministic: every run produces the same result, and both the default hash mode and `-b` agree on the output.

## Features
I'm looking forward to feedback from the community for new features and options.  We're pretty happy with how it works right now.

To-do list:\
Better portability.

## Status
Project is in progress, and is in "beta" release.  We don't think there are any bugs left, but I'm sure there will be new features.

## Inspiration
Key inspiration for this project came from tychotithonus.  He suggested the project, and this quickly developed into a "who's smaller?" measuring contest of some kind between Waffle, blazer and hops. Breaking the 5 minute mark on 1,000,000,000 lines was easy, but breaking the 60 second mark was first done by blazer/hops.  blazer actually has a better algorithm (using Bloom filters and Judy) which is substantially better than this one.  I figure that this is "good enough" for now

Thank you to blazer for the qsort_mt code!\
Thank you to hops for the xxHash integration, and to Cyan4973 for xxHash.\
And a substantial thank you to Mark Adler, for his yarn code.  That's made my life better for more than 10 years now.

## Contact
Created by Waffle.
