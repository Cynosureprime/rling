# rling - a better rli
> rling is similar to the rli utility found in [hashcat-utils](https://github.com/hashcat/hashcat-utils), but much, much faster

## Table of contents
* [General info](#general-info)
* [Technologies](#technologies)
* [Setup](#setup)
* [Features](#features)
* [Examples](#examples)
* [Status](#status)
* [Inspiration](#inspiration)
* [Contact](#contact)

## General info
In July, 2020, @tychotithonus asked a simple question - theoretically, could rli be faster?  Answering that question took the CynoSurePrime team down several roads, looking for "the better ways" to handle the problem. It ended up in a "how many nanoseconds" race in the end!

The essential task of removing lines from a file (or a database) has been fundamental to computing since the very earliest days, and rli seems "good enough" for most purposes.  But when the files get large, the amount of RAM used by rli is high, and the performace was not sufficient to the task at hand.  @tychotithonus also wanted a few new features.

The performance of rling is impressive (this done on a Power8 system with 80 cores). 1billion.txt is a ~10gigabyte file containing 1,000,000,000 lines.  rem is a file containg 6 lines matching ones scattered throughout the 1billion.txt file.

| Program | Input    |  Remove | Memory | Time |
| ------- | -------- | ------- | ------ | ---- |
| rli | 1billion.txt | rem | 59.7g | 12:37 |
| rli | 1billion.txt | 1billion.txt | 59.7g | 22:14 |
| rling | 1billion.txt | rem | 38.0g | 0:22 |
| rling | 1billion.txt | 1billion.txt | 38.0g | 1:15 |
| rling -b | 1billion.txt | rem | 17.0g | 0:55 |
| rling -b | 1billion.txt | 1billion.txt | 17.0g | 1.36 |


## Technologies
* Dynamic sizing\
rling dynamically sizes the memory to be appropriate for the file.  By not having compiled-in limits for things like line lengths for the input lines, users are able to focus on novel use cases for the program.
* Hashing with xxHash\
xxHash is a great new hashing method - its very fast and portable.  By combining a dynamic (overridable) hash table with an excellent hash function, performance was accelerated greatly.  Also, because hash tables are sized dynamically, there is no need to guess "optimal" hash sizes.
* Multi threaded Binary searches and sorts\
Thanks to blazer's multi threaded qsort, sorts are very fast, and make use of all of your system thread and multicore resources.  In general, hashing is faster than binary search, but binary search uses half of the memory, and can be many times faster for certain kinds of input.
* Filesystem-based database for very large files\
If you need to process very large datasets, and don't have enough memory, the -f option allows you to use a Berkeley db-based database instead of in-memory.  This does allow unlimited file sizes, but you do need substantial free disk space.  Use the -M option to give it more cache for the database, and -T to tell it where to put the databases (defaults to current directory.
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

## Features
I'm looking forward to feedback from the community for new features and options.  We're pretty happy with how it works right now.

There are some "hidden features" in rling.
* -t [thread count]\
-t allows you to override the default "use all" threads for your hardware platform.  This can be useful if you need to conserve computing resources.  Additionally, sometimes limiting thread count can actually make a process faster - this is usually the case if you are running near the bandwidth of the memory with all threads active.
* -p [hash prime size]\
-p allows you to override the computed hash list size, and to implement the hash in two ways.  By default, rling selects a "good" hash table size based on a prime number, and uses a modulo operation to index into that table.  If you supply a different value, rling will use that, not caring if it is prime or not.  If you select a value which is an exact power-of-two, however, rling will use shift-and-mask instead of modulo.  This *may* be faster on certain processor types.
* -v\
-v is a secret "verbose" mode switch to rling.  It displays the run time of each section of the program, so you can understand where all the time is going to.
* -i\
-i "ignores" errors in the filenames.  By default, rling checks to make sure each filename specified on the command line is accessable.  It does not check to make sure it has read access to the file, nor does it care if it is a real file, or a named pipe, and certainly does not check to see if you have specified the correct input and output names!  -i suppresses these checks, which can be handy if you have files which might appear later, for some reason. 
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
