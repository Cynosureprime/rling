#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#ifndef _AIX
#include <getopt.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef __FreeBSD__
/* FreeBSD has the old-old DBM as default.  We want at least version 5 */
#include <db5/db.h>
#else
#include <db.h>
#endif

#include "yarn.h"

/*
 * rling is a tool that allows files to be processed in several ways.
 * The main purpose is to remove lines that exist in one or more "remove"
 * files from an input file, without altering line order.  By default,
 * it also removes duplicate lines from the input file (but that can be
 * suppressed with -n).  It's designed to be very (very) fast for very
 * large file sizes (10s to 100s of gigabytes, with hundreds of millions
 * or billions of lines).  Small files are processed effectively instantly
 * (sub second).  The most common use of rling is to remove already processed
 * data from large input sets, for example candidate passwords from a
 * dictionary.
 *
 * Lines are sequences of zero or more characters, terminated by a
 * \n (but \r\n line termination is accepted, and changed to \n).
 *
 * rling uses two (selectable) methods for this:  Hash, and binary search.
 *
 * Hash is the default mode, and ususally the fastest.  In this mode, each
 * line is read and the XXHASH64 value is computed, and stored in a hash
 * table.  Duplicates are removed as the input file is processed.  The
 * hash table is automatically sized to the input data, but this can be
 * overridden with the -p option.  If an exact power-of-2 hash size is
 * requested with -p, then rling uses a shift-and-mask instead of modulo
 * method, which can boost speed even more.
 *
 * Binary search is selected with the -b option.  Binary search is
 * usually a bit slower than hash, but uses about half of the memory
 * which may be important with large files and small memory systems.
 *
 * By default, rling uses the maximum number of threads permitted on your
 * system.  You can override this with the -t option, requesting more
 * or fewer threads to be used.  In general, the number of threads
 * used is not important until you get to hundreds of thousands of lines.
 * For example, processing a 1 gigabyte 100,000,000 line file takes 2
 * to 8 seconds on a Power8 system.
 *
 * rling can also output the lines "common" to a group of files (present in
 * both the input, and one or more of the "remove" files).  The -c switch
 * enables this feature.
 *
 * Here are some typical uses:
 *
 * rling infile outfile file1 file2
 * This reads infile, removes duplicates from it, and then removes any
 * lines matching the lines in file1 and file2, then writes the result to
 * outfile.
 *
 * rling infile infile
 * Reads infile, removes duplicate lines, and writes the output back to
 * infile when done.
 *
 * rling -b infile infile
 * Same as above, but uses binary search instead, to reduce memory usage.
 *
 * rling -bc infile outcommon file1 file2
 * Reads infile and outputs to outcommon any lines which exist in infile
 * and file1 or file2.
 *
 * There is no built-in limit on the number of "remove" files that can be
 * applied to a given "input" file.  In fact, you can also use stdin and
 * stdout if you like to augment this.
 *
 * find /dict -type f -print | xargs gzcat | rling infile outfile stdin
 *
 * This will find all files in /dict, then use gzcat to decompress them,
 * piping the output to rling, which then reads infile and then all of
 * stdin, then finally writing the result to outfile.
 *
 * rling was inspired by the "rli" utility from Hashcat, and
 * tychotithonus.  His suggestions, and extensive testing, were
 * foundational.  blazer and hops contributed extensively to the
 * code base - thank you blazer for the qsort_mt code, and hops for
 * multiple suggestions and the xxHash integration.  Thanks also to
 * Cyan4973 for the great work on xxHash
 *
 * Waffle - July, 2020
 */

extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;

 static char *Version = "$Header: /home/dlr/src/mdfind/RCS/rling.c,v 1.42 2020/07/23 13:28:24 dlr Exp dlr $";
/*
 * $Log: rling.c,v $
 * Revision 1.42  2020/07/23 13:28:24  dlr
 * Fixed typo on stdin for rli2.  Added additional error checks for the line
 * length.  Line lengths are not limited, but there must be room in the cache
 * for at least 2 lines.
 *
 * Revision 1.40  2020/07/23 05:45:27  dlr
 * add -2 to help
 *
 * Revision 1.39  2020/07/23 05:41:21  dlr
 * Ensure -n and -d dedupe code works for -2 as well.
 *
 * Revision 1.38  2020/07/23 05:11:29  dlr
 * Improve rli2 messages and add time info
 *
 * Revision 1.36  2020/07/22 13:49:16  dlr
 * Chavnge from leveldb to Berkeley db for a 3x improvement in performance.
 *
 * Revision 1.35  2020/07/21 06:48:58  dlr
 * Make -v mode the default.  Will re-use -v later for debug
 *
 * Revision 1.34  2020/07/21 06:22:10  dlr
 * Fix poor linecount performance, add -c mode support for -f
 *
 * Revision 1.33  2020/07/21 02:32:44  dlr
 * added -f option to use filesystem instead of memory to resolve duplicates.
 * Uses leveldb, and performance is... ok.
 *
 * Revision 1.32  2020/07/20 16:13:05  dlr
 * Minor wording change on error message
 *
 * Revision 1.31  2020/07/20 02:45:24  dlr
 * Minor typo, improve stat in early read abort.
 *
 * Revision 1.30  2020/07/19 20:07:24  dlr
 * Make error messages more verbox
 *
 * Revision 1.29  2020/07/19 16:22:50  dlr
 * Minor typo
 *
 * Revision 1.28  2020/07/19 15:39:44  dlr
 * Minor change to define findeol, if no alternative implementations available.
 *
 * Revision 1.27  2020/07/19 03:06:48  dlr
 * Improve portability for AIX and MacOSX
 *
 * Revision 1.26  2020/07/18 15:18:39  dlr
 * Add some comments, improve findeol for intel
 *
 * Revision 1.25  2020/07/17 20:36:28  dlr
 * Left in a debugging line
 *
 * Revision 1.24  2020/07/17 20:20:20  dlr
 * Fix error on line count - end-of-block pointing to a zero-length line would hang
 *
 * Revision 1.23  2020/07/16 06:27:07  dlr
 * Portability for Windows, better EOL handling for CR LF
 *
 * Revision 1.22  2020/07/16 04:31:17  dlr
 * Rounding error on small files with large number of threads
 *
 * Revision 1.21  2020/07/14 17:31:42  dlr
 * Better locking for hash table, append to end of list now.  No more goto :-)
 *
 * Revision 1.20  2020/07/14 04:55:00  dlr
 * Slightly better global locking performance, better handling of hashtable
 *
 * Revision 1.19  2020/07/13 20:21:42  dlr
 * Minor fix for race condition on removing duplicates
 *
 * Revision 1.18  2020/07/13 12:32:06  dlr
 * Better memory estimates, smaller code size
 *
 * Revision 1.17  2020/07/13 07:00:23  dlr
 * Better progress, added hashprime/hashmask autocode
 *
 * Revision 1.16  2020/07/13 06:08:27  dlr
 * Somewhat better progress on hash build, add -i option and input file checking.
 *
 * Revision 1.15  2020/07/13 05:42:37  dlr
 * Fix obscure error on binary-search file write
 *
 * Revision 1.14  2020/07/13 02:01:13  dlr
 * Add back in locking for now
 *
 * Revision 1.13  2020/07/13 01:14:03  dlr
 * Added dynamic memory allocation, effectively unlimited string length.
 *
 * Revision 1.12  2020/07/08 12:33:11  dlr
 * Added -v and debug code for time on each section
 *
 * Revision 1.11  2020/07/08 03:58:17  dlr
 * cleanup, fix uninitialized variables, delete TASK structures
 *
 * Revision 1.10  2020/07/08 00:51:46  dlr
 * Fix findeol bug
 *
 * Revision 1.9  2020/07/07 18:28:07  dlr
 * Minor help change
 *
 * Revision 1.8  2020/07/07 18:25:58  dlr
 * Allow stdin/stdout to be used for files.  Change all human output to stderr
 *
 * Revision 1.7  2020/07/07 17:31:20  dlr
 * made output faster
 *
 * Revision 1.6  2020/07/07 17:01:16  dlr
 * add -c for common line production
 *
 * Revision 1.5  2020/07/07 15:11:03  dlr
 * New qsort_mt code
 *
 * Revision 1.4  2020/07/07 06:04:48  dlr
 * Fix memory init problems
 *
 * Revision 1.3  2020/07/07 03:19:50  dlr
 * Add binary and multithreaded code
 *
 * Revision 1.1  2020/07/03 23:01:50  dlr
 * Initial revision
 *
 *
 */

#include "xxh3.h"


#ifdef POWERPC
/*
#define XXH_VECTOR XXH_VSX
*/
#include <altivec.h>
#endif
#ifdef INTEL
#include <emmintrin.h>
#include <xmmintrin.h>
#endif

extern void qsort_mt();


/* After LINELIMIT lines, threads kick in */
/* Maximume line length now 4gigabytes */
#define LINELIMIT 100000
#define MEMCHUNK (1024*1000+16)

/* Bloom filter size in bits */
#define BLOOMSIZE (1LL << 30)
#define BLOOMMASK ((BLOOMSIZE/8)-1)

#define MAXCHUNK (50*1024*1024)
#define MAXLINE (((MAXCHUNK/2)-16)/2)
#define MAXLINEPERCHUNK (MAXCHUNK/2/8)
#define RINDEXSIZE (MAXLINEPERCHUNK)
struct LineInfo {
    unsigned int offset;
    unsigned int len;
} *Readindex;
static int Cacheindex;
char *Readbuf;


struct WorkUnit {
    struct WorkUnit *next;
    lock *wulock;
    char **Sortlist;
    uint64_t ssize,count,start,end;
} *WUList;

struct DBSort {
    uint64_t line,len;
    char *key;
};

struct Infiles {
    FILE *fi;
    char *fn;
    uint64_t line;
    char *Buffer;
    size_t size, curpos, end, eof, unique, dup;
    char *curline;
    uint64_t curlen;
} *Infile;

struct InHeap {
    struct Infiles *In;
};

struct JOB {
    struct JOB *next;
    uint64_t start,end;
    int startline, numline;
    char *readbuf, *fn;
    DB *db;
    struct WorkUnit *wu;
    struct LineInfo *readindex;
    FILE *fo;
    int func;
} *Jobs;


#define JOB_COUNT 1
#define JOB_DEDUPE 2
#define JOB_SEARCH 3
#define JOB_FINDHASH 4
#define JOB_GENHASH 5
#define JOB_WRITE 6
#define JOB_BUILDDB 7
#define JOB_FINDDB 8
#define JOB_DONE 99

struct JOB *FreeHead, **FreeTail;
struct JOB *WorkHead, **WorkTail;
struct WorkUnit *WUHead, **WUTail;

lock *FreeWaiting,*WorkWaiting, *WUWaiting;
lock *Currem_lock, *ReadBuf0, *ReadBuf1;
lock *Common_lock;

uint64_t Currem_global,Unique_global,Write_global, Occ_global;
uint64_t Maxdepth_global;
uint64_t Line_global, HashPrime, HashMask, HashSize;
int Maxt, Workthread;
int _dowildcard = -1; /* enable wildcard expansion for Windows */

#ifdef MAXPATHLEN
#define MDXMAXPATHLEN (MAXPATHLEN)
#else
#define MDXMAXPATHLEN 5000
#endif

char TempPath[MDXMAXPATHLEN+16];


char *Fileinmem, *Fileend;
uint64_t Filesize;
uint64_t WorkUnitLine, WorkUnitSize, MaxMem;
char **Sortlist;

struct Memscale {
    double size, scale;
    char *name;
} Memscale[] = {
{1024,1, "bytes"},
{1024*1024,1024, "kbytes"},
{1024LL*1024L*1024L,1024L*1024L, "Mbytes"},
{1024LL*1024L*1024L*1024L,1024L*1024L*1024L, "Gbytes"},
{1024LL*1024L*1024L*1024L*1024L,1024LL*1024L*1024L*1024L,"Tbytes"}
};

struct Hashsizes {
    uint64_t size,prime;
} Hashsizes[] = {
{2048,1543},
{4096,3079},
{8192,6151},
{16384,12289},
{32768,24593},
{65536,49157},
{131072,98317},
{262144,196613},
{524288,393241},
{1048576,786433},
{2097152,1572869},
{4194304,3145739},
{8388608,6291469},
{16777216,12582917},
{33554432,25165843},
{67108864,50331653},
{134217728,100663319},
{268435456,201326611},
{536870912,402653189},
{1073741824,805306457},
{2147483648L,1610612741L},
{0,0}
};


struct Linelist {
    struct Linelist *next;
} *Linel;

struct Linelist **HashLine;


int Dedupe = 1;
int DoCommon = 0, SortOut = 0;
uint64_t *Common, *Bloom;
#define Commonset(offset) {__sync_or_and_fetch(&Common[(uint64_t)(offset)/64],(uint64_t)1L << ((uint64_t)(offset) & 0x3f)); }
#define Bloomset(offset) (__sync_fetch_and_or(&Bloom[(uint64_t)(offset)/64],(uint64_t)1L << ((uint64_t)(offset) & 0x3f)) & ((uint64_t)1L <<((uint64_t)(offset) & 0x3f)))
#define Commontest(offset) (Common[(uint64_t)(offset)/64] & (uint64_t)1L << ((uint64_t)(offset) & 0x3f))

/*
 * MarkD(pointer to char*, 64 bit value)
 * MarkD marks a particular entry in the Sortlist array as being a "deleted"
 * line, by setting the most significant bit of the address.  This is not
 * portable, but saves memory.  The valididity of the use of this bit is
 * tested for in main, by checking the range of memory used to store the
 * file read in.
 */
uint64_t inline _MarkD(uint64_t *ptr, uint64_t val) {
    uint64_t p = *ptr;
    *ptr |= val;
    return(p);
}
#define MarkDeleted(line) _MarkD((uint64_t *)&Sortlist[line],0x8000000000000000L)





/*
 * prstr prints a \n terminated string, or up to n characters
 */

void prstr(char *s, int n) {
     uint64_t RC = (uint64_t)(s) & 0x7fffffffffffffffL;
     if (s != (char *)RC) fprintf(stderr,"(deleted) ");
     s = (char *)RC;
     while (n-- && *s != '\n') {if (*s >= ' ' && *s < 0x7f) fputc(*s++,stderr); else fprintf(stderr,"0x%02x",*s);}
     fputc(*s,stderr);
}

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif
void current_utc_time(struct timespec *ts) {
#ifdef __MACH__ // OS X does not have clock_gettime, use clock_get_time
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

/*
 * findeol(pointer, length)
 *
 * findeol searches for the next eol character (\n, 0x0a) in a string
 *
 * The Intel version uses SSE to process 64 bits at a time.  This only
 * is able to work because I ensure that the Fileinmem buffer has adequate
 * space (16 bytes) following it to ensure that reading past the end won't
 * read memory not available and cause a fault.
 *
 * This is important to the operation of this program, and care should be
 * taken to ensure that the performance of this function is kept fast
 */

#if !defined(POWERPC) && !defined(INTEL)
#define findeol(a,b) memchr(a,10,b)
#endif

#ifdef POWERPC
#define findeol(a,b) memchr(a,10,b)
#endif

#ifdef INTEL
inline char *findeol(char *s, int64_t l) {
  unsigned int align, res, f;
  __m128i cur, seek;

  if (l <=0) return (NULL);

  seek = _mm_set1_epi8('\n');
  align = ((uint64_t) s) & 0xf;
  s = (char *) (((uint64_t) s) & 0xfffffffffffffff0L);
  cur = _mm_load_si128((__m128i const *) s);
  res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur)) >> align;

  f = ffs(res);
  res <<= align;
  if (f && (f <= l))
    return (s + ffs(res) - 1);
  s += 16;
  l -= (16 - align);

  while (l >= 16) {
    cur = _mm_load_si128((__m128i const *) s);
    res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur));
    f = ffs(res);
    if (f)
      return (s + f - 1);
    s += 16;
    l -= 16;
  }
  if (l > 0) {
    cur = _mm_load_si128((__m128i const *) s);
    res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur));
    f = ffs(res);
    if (f && (f <= l)) {
      return (s + f - 1);
    }
  }
  return (NULL);
}
#endif

/* get_nprocs
 *
 * Returns the available number of threads that this program has access to
 * and this value is used to set the number of simultaneous work threads
 * for large files.
 */
#ifdef _SC_NPROCESSORS_ONLN
#ifdef MACOSX
#include <sys/sysctl.h>
int get_nprocs() {
    int numCPUs;
    size_t len = sizeof(numCPUs);
    int mib[2] = { CTL_HW, HW_NCPU };
    if (sysctl(mib, 2, &numCPUs, &len, NULL, 0))
      return 1;
    return numCPUs;
}
#else
int get_nprocs() {
    int numCPUs;
    numCPUs = sysconf(_SC_NPROCESSORS_ONLN);
    if (numCPUs <=0)
      numCPUs = 1;
    return(numCPUs);
}
#endif
#endif
#ifdef SPARC
#ifndef AIX
int get_nprocs() { return(1); }
#endif
#endif
#ifdef _WIN32
#include <windows.h>

int get_nprocs() {
    SYSTEM_INFO SysInfo;
    ZeroMemory(&SysInfo,sizeof(SYSTEM_INFO));
    GetSystemInfo(&SysInfo);
    return SysInfo.dwNumberOfProcessors;
}
#endif



/*
 * commify takes a large integer (long long), and returns a char *
 * to a static space with commas inserted to make large numbers more
 * readable.
 */
static char Commify[128];
char *commify(uint64_t source) {
  char temp[128];
  char *s, *d;
  int len, targlen, x;

  sprintf(temp, "%"PRIu64, source);
  len = strlen(temp);
  targlen = len + ((len - 1) / 3);
  d = &Commify[targlen];
  s = &temp[len];
  *d-- = *s--;
  for (x = 1; x <= len && d >= Commify; x++) {
    *d-- = *s--;
    if ((x % 3) == 0 && x && d >= Commify)
      *d-- = ',';
  }
  return (Commify);
}

/*
 * mystrcmp compares two \n-terminated strings
 * Just like strcmp, but instead of nul termination...
 */
int mystrcmp(const char *a, const char *b) {
  const unsigned char *s1 = (const unsigned char *) a;
  const unsigned char *s2 = (const unsigned char *) b;
  unsigned char c1, c2;
  do
    {
      c1 = (unsigned char) *s1++;
      c2 = (unsigned char) *s2++;
      if (c1 == '\n')
        return c1 - c2;
    }
  while (c1 == c2);
  return c1 - c2;
}


/*
 * comp1 compares two Sortline[] strings, and removes the "deleted"
 * bit in case one ore more of the strings are in the deleted state.
 */
int comp1(const void *a, const void *b) {
    char *a1 = *((char **)a);
    char *b1 = *((char **)b);
    a1 = (char *)((uint64_t)a1 & 0x7fffffffffffffffL);
    b1 = (char *)((uint64_t)b1 & 0x7fffffffffffffffL);
    return(mystrcmp(a1,b1));
}
/*
 * comp2 compares a key against the (potentially deleted) Sortline[] entry
 * it removes the deleted bit before comparison
 */
int comp2(const void *a, const void *b) {
    char *a1 = (char *)a;
    char *b1 = (char *)(((uint64_t)*((char **)b)) & 0x7fffffffffffffffL);
    return(mystrcmp(a1,b1));
}
/* comp3 compares the addresses pointed to by the Sortline[] array.
 * This is used to sort the array back into input-file line order, but also
 * moves all of the deleted lines to the end.
 */
int comp3(const void *a, const void *b) {
    uint64_t a1 = (uint64_t)(*((char **)a));
    uint64_t b1 = (uint64_t)(*((char **)b));
    if (a1 > b1) return(1);
    if (a1 < b1) return(-1);
    return(0);
}

int comp4(DB *v, const DBT *a, const DBT *b) {
    uint64_t a1,b1;
    if (a->size != 8 || b->size != 8) return 0;
    a1 = *(uint64_t *)a->data;
    b1 = *(uint64_t *)b->data;
    if (a1 < b1) return(-1);
    if (a1 > b1) return(1);
    return (0);
}


/*
 * MDXALIGN forces the process to start on an appropriate boundary.  Windows
 * gets picky about the offset of a particular thread function
 */
#ifdef MDX_BIT32
#ifndef NOTINTEL
#define MDXALIGN __attribute__((force_align_arg_pointer))
#else
#define MDXALIGN
#endif
#else
#define MDXALIGN
#endif

/*
 * procjob is the main processing thread function.  It runs as a separate
 * thread, and up to Maxt threads can be running simultaneously.
 * In most cases, jobs are pulled from the head of the WorkWaiting
 * list, processed, and then the job is returned to the FreeWaiting list.
 * The exception is JOB_DONE, which stays on the head of the list, to
 * allow a single job to terminate all of the active procjob threads.
 *
 * JOB_COUNT is the first operation called. It finds each line in the file
 * and returns Sortlist[]-style entries into a buffer (which is temporarily
 * allocated from the remove-file-read-buffers).  This is done so that
 * Sortlist can be allocated from contiguous space, makeing realloc much
 * cheaper (both on time and memory). Large numbers of lines can then
 * exands the Sortlist until the whole file is processed.  The test
 * cases for rling have hundreds of millions of lines, or billions.  This
 * is also the process that removes Windows-style (\r\n) line termination
 * from the input file.
 *
 * JOB_DEDUPE is used only when Sortlist has been sorted into lexical order
 * (which usually means -b).  It takes the lines from job->start to job->end
 * and looks for duplicates.  The caller must ensure than duplicate lines
 * don't cross the job->end boundaries.
 *
 * JOB_SEARCH does a binary search on a block of input lines read from the
 * remove files.  If matches are found, the matching line(s) are marked
 * as deleted.  This is only used in -b mode.
 *
 * JOB_FINDHASH does a hash lookup search on a block of input lines read
 * from the remove files.  If matches are found, the matching lines
 * are marked as deleted.  This is only used in -h mode
 *
 * JOB_GENHASH generates the hash table for groups of lines.  This
 * use a compare-and-swap method of locking the linked list built from the
 * hash table, rather than a global lock on the hash table, improving
 * performance somewhat.  It is a linked list, however, and is searched
 * sequentially.
 *
 * JOB_WRITE finds all non-deleted lines in a given range, and assembles
 * them as a contiguous memory block, so that a single fwrite() call can
 * write a large block of memory.  The output file is kept in order by
 * having each thread wait-its-turn after the memory block is created,
 * before writing.
 *
 * JOB_DONE leaves the job on the work list, and terminates the thread.
 */

MDXALIGN void procjob(void *dummy) {
    struct JOB *job;
    struct WorkUnit *wu, *wulast, *wunext;
    struct Linelist *cur, *next, *last;
    char **sorted, *key, *newline, *eol;
    uint64_t x, unique, occ, rem,thisnum, crc, index, j, RC, COM, thisend;
    int64_t llen, maxdepth;
    int res, curline, numline, ch, delflag;
    DBT dbkey, dbdata;
    size_t DBlen;

    while (1) {
        possess(WorkWaiting);
	wait_for(WorkWaiting, NOT_TO_BE, 0);
	job = WorkHead;
	if (!job || job->func == 0) {
	    fprintf(stderr,"Job null - exiting\n");
	    exit(1);
	}
	if (job->func == JOB_DONE) {
	    release(WorkWaiting);
	    return;
	}
	WorkHead = job->next;
	if (WorkHead == NULL)
	    WorkTail = &WorkHead;
	twist(WorkWaiting, BY, -1);
	job->next = NULL;

	switch(job->func) {
	    case JOB_COUNT:
	        wu = job->wu;
		j = wu->count = 0;
		index = job->start;
		wu->start = index;
		do {
		    newline = &Fileinmem[index];
		    wu->Sortlist[j++] = newline;
		    eol = findeol(newline,job->end-index);
		    if (!eol)
		       eol = &Fileinmem[job->end];
		    if (eol > newline && eol[-1] == '\r')
		        eol[-1] = '\n';
		    index += (eol-newline) + 1;
		    if (index >= job->end || j >= wu->ssize) {
		        wu->count = j;
		        wu->end = index;
			possess(WUWaiting);
			possess(wu->wulock);
			wu->next = NULL;
			for (wulast = NULL, wunext = WUHead; wunext; wulast=wunext,wunext = wunext->next)
			    if (wu->start < wunext->start)
			        break;
			if (wunext == NULL) {
			    *WUTail = wu;
			    WUTail = &(wu->next);
			} else {
			   if (wulast == NULL) {
			       WUHead = wu;
			       wu->next = wunext;
			    } else {
			        if (WUTail == &(wunext->next)) {
				    *WUTail = wu;
				    WUTail = &(wu->next);
				} else {
				    wu->next = wunext;
				    wulast->next = wu;
				}
			    }
			}
			twist(wu->wulock, BY, +1);
			twist(WUWaiting,BY,+1);
			possess(wu->wulock);
			wait_for(wu->wulock,TO_BE,0);
			release(wu->wulock);
			wu->start = index;
			j = wu->count = 0;
		    }
		} while (index < job->end);
		break;

	    case JOB_DEDUPE:
		key = Sortlist[job->start];
		unique = 1; rem =0;
		for (index=job->start+1; index < job->end; index++) {
		    if (mystrcmp(key,Sortlist[index]) == 0) {
			rem++;
			MarkDeleted(index);
		    } else {
			unique++;
			key = Sortlist[index];
		    }
		}
		__sync_add_and_fetch(&Currem_global,rem);
		__sync_add_and_fetch(&Unique_global,unique);
		break;


	    case JOB_SEARCH:
		rem = 0;
		numline = 0;
	        for (curline = job->startline; numline < job->numline; curline++,numline++) {
  		    key = &job->readbuf[job->readindex[curline].offset];
		    key[job->readindex[curline].len] = '\n';

		    sorted = bsearch(
			    key,
			    &Sortlist[job->start],
			    job->end,
			    sizeof (char **),
			    comp2);
		    if (sorted) {
			uint64_t work;

			for (work = sorted - Sortlist;work < job->end  && comp2(key,&Sortlist[work]) == 0; work--) {
			    RC = MarkDeleted(work);
			    if ((RC & 0x8000000000000000L) == 0) {
				if (DoCommon)
				    Commonset(RC-(uint64_t)(Fileinmem));
				rem++;
			    }
			}
			for (work = (sorted - Sortlist) + 1;work < job->end && comp2(key,&Sortlist[work]) == 0; work++) {
			    RC = MarkDeleted(work);
			    if ((RC & 0x8000000000000000L) == 0) {
				if (DoCommon)
				    Commonset(RC-(uint64_t)(Fileinmem));
				rem++;
			    }
			}
		    }
		}
		if (rem) {
		    __sync_add_and_fetch(&Currem_global,rem);
		}
		if (job->readbuf == Readbuf) {
		    possess(ReadBuf0);
		    twist(ReadBuf0,BY, -1);
		} else {
		    possess(ReadBuf1);
		    twist(ReadBuf1,BY, -1);
		}
		break;

	    case JOB_FINDHASH:
		rem = 0;
		numline = 0;
		if (HashMask) {
		    for (curline=job->startline; numline<job->numline; curline++,numline++) {

			key = &job->readbuf[job->readindex[curline].offset];
			ch = job->readindex[curline].len;
			key[ch] = '\n';
			crc = XXH3_64bits(key,ch);
			for (cur = HashLine[crc&HashMask];cur;cur = cur->next) {
			    thisnum = cur - Linel;
			    if (((((uint64_t)Sortlist[thisnum])&0x8000000000000000L) == 0) && comp2(key, &Sortlist[thisnum]) == 0) {
				RC = (uint64_t)Sortlist[thisnum];
				if (DoCommon)
				    Commonset((RC&0x7fffffffffffffffL) - (uint64_t)Fileinmem);
				MarkDeleted(thisnum);
				rem++;
			    }
			}
		    }
		} else {
		    for (curline=job->startline; numline<job->numline; curline++,numline++) {

			key = &job->readbuf[job->readindex[curline].offset];
			ch = job->readindex[curline].len;
			key[ch] = '\n';
			crc = XXH3_64bits(key,ch);
			for (cur = HashLine[crc%HashPrime];cur;cur = cur->next) {
			    thisnum = cur - Linel;
			    if (((((uint64_t)Sortlist[thisnum])&0x8000000000000000L) == 0) && comp2(key, &Sortlist[thisnum]) == 0) {
				RC = (uint64_t)Sortlist[thisnum];
				if (DoCommon)
				    Commonset((RC&0x7fffffffffffffffL) - (uint64_t)Fileinmem);
				MarkDeleted(thisnum);
				rem++;
			    }
			}
		    }
		}
		if (rem) {
		    __sync_add_and_fetch(&Currem_global,rem);
		}
		if (job->readbuf == Readbuf) {
		    possess(ReadBuf0);
		    twist(ReadBuf0,BY, -1);
		} else {
		    possess(ReadBuf1);
		    twist(ReadBuf1,BY, -1);
		}
		break;

	    case JOB_GENHASH:
		occ = unique = rem = 0;
		maxdepth = 0;
	        ch = Dedupe;
		if (HashMask) {
		    int lastp = 99, progress;
		    for (index = job->start; index < job->end; index++) {
			if (job->start == 0){
			    progress = (index*100)/job->end;
			    if (progress != lastp) {
				lastp = progress;
				fprintf(stderr,"%c%c%c%c%3d%%",8,8,8,8,progress);fflush(stderr);
			    }
			}
			key = Sortlist[index];
			eol = findeol(key,Fileend-key);
			if (!eol) eol = key;
			llen = eol - key;
			crc =  XXH3_64bits(key,llen);
			j = crc & HashMask;
		        next = &Linel[index];
		        next->next = HashLine[j];
			if (!next->next && __sync_bool_compare_and_swap(&HashLine[j],next->next,next)) {
			    unique++;occ++;
			    continue;
			}
			delflag =  (((uint64_t)Sortlist[index]) & 0x8000000000000000L) ? 1 : 0;
			for (x=0,last = cur = HashLine[j]; !delflag && cur; x++) {
			    if (ch) {
				res = comp2(key,&Sortlist[cur - Linel]);
				if (res == 0) {
				    delflag = 1;
				    MarkDeleted(index);
				    rem++;
				    break;
				}
			    }
			    last = cur;
			    cur = cur->next;
			}
			if (x > maxdepth) maxdepth = x;
			if (!delflag) {
			    next->next = NULL;
			    while (last) {
			        if (__sync_bool_compare_and_swap(&last->next,next->next,next))
				break;
				last = last->next;
			    }
			    unique++;
			}
		    }
		} else {
		    int lastp = 99, progress;
		    for (index = job->start; index < job->end; index++) {
			if (job->start == 0){
			    progress = (index*100)/job->end;
			    if (progress != lastp) {
				lastp = progress;
				fprintf(stderr,"%c%c%c%c%3d%%",8,8,8,8,progress);fflush(stderr);
			    }
			}
			key = (char *)((uint64_t)Sortlist[index] & 0x7fffffffffffffffL);
			eol = findeol(key,Fileend-key);
			if (!eol) eol = key;
			llen = eol - key;
			crc =  XXH3_64bits(key,llen);
			j = crc % HashPrime;
		        next = &Linel[index];
		        next->next = HashLine[j];
			if (!next->next && __sync_bool_compare_and_swap(&HashLine[j],next->next,next)) {
			    unique++;occ++;
			    continue;
			}
			delflag =  (((uint64_t)Sortlist[index]) & 0x8000000000000000L) ? 1 : 0;
			for (x=0,last = cur = HashLine[j]; !delflag && cur; x++) {
			    if (ch) {
				res = comp2(key,&Sortlist[cur - Linel]);
				if (res == 0) {
				    delflag = 1;
				    MarkDeleted(index);
				    rem++;
				    break;
				}
			    }
			    last = cur;
			    cur = cur->next;
			}
			if (x > maxdepth) maxdepth = x;
			if (!delflag) {
			    next->next = NULL;
			    while (last) {
			        if (__sync_bool_compare_and_swap(&last->next,next->next,next))
				break;
				last = last->next;
			    }
			    unique++;
			}
		    }

		}
		if (maxdepth > Maxdepth_global) {
		    while (!__sync_bool_compare_and_swap(&Maxdepth_global,Maxdepth_global,maxdepth));
		}
		__sync_add_and_fetch(&Currem_global, rem);
		__sync_add_and_fetch(&Unique_global, unique);
		__sync_add_and_fetch(&Occ_global, occ);
		break;

	    case JOB_WRITE:
		unique = 0;
		thisend = (uint64_t)Fileend;
		if (DoCommon || SortOut) {
		    possess(Common_lock);
		    wait_for(Common_lock, TO_BE, job->startline);
		    for (index = job->start; index < job->end; index++) {
			RC = (uint64_t)Sortlist[index];
		        if (DoCommon) {
			    RC &= 0x7fffffffffffffffL;
			    if(Commontest(RC-(uint64_t)Fileinmem) == 0)
				continue;
			} else {
			    if (RC & 0x8000000000000000L) continue;
			}
			unique++;
			key= (char*)RC;
			eol = findeol(key,thisend-RC);
			if (!eol) eol = (char *)thisend;
			llen = eol-key;
			if (fwrite(key,llen+1,1,job->fo) != 1) {
			    fprintf(stderr,"Write error. Disk full?");
			    perror(job->fn);
			    exit(1);
			}
		    }
		} else {
		    for (index=job->start;index < job->end; index++) {
			RC = (uint64_t)Sortlist[index];
			if (!(RC & 0x8000000000000000L)) break;
		    }
		    thisnum = (((uint64_t)Sortlist[index]) & 0x7fffffffffffffffL);
		    newline = (char *)thisnum;
		    for (; index < job->end; index++) {
			RC = (uint64_t)Sortlist[index];
			if (!(RC & 0x8000000000000000L)) {
			    unique++;
			    key= (char*)RC;
			    eol = findeol(key,thisend-RC);
			    if (!eol) eol = (char *)thisend;
			    llen = eol-key;
			    if (llen && key != newline) memcpy(newline,key,llen);
			    newline[llen] = '\n'; newline += llen + 1;
			}
		    }
		    possess(Common_lock);
		    key = (char *)thisnum;
		    wait_for(Common_lock, TO_BE, job->startline);
		    if ((newline-key) && fwrite(key,newline-key,1,job->fo) != 1) {
			fprintf(stderr,"Write error. Disk full?\n");
			perror(job->fn);
			exit(1);
		    }
		}
		fflush(job->fo);
		Write_global += unique;
		twist(Common_lock,BY, +1);
		break;

	    case JOB_BUILDDB:
		unique = rem = 0;
		numline = 0;
		memset(&dbkey,0,sizeof(dbkey));
		memset(&dbdata,0,sizeof(dbdata));
		dbkey.flags = DB_DBT_USERMEM;
		dbdata.flags = DB_DBT_USERMEM;
		index = job->end + job->startline;
		for (curline=job->startline; numline<job->numline; curline++,numline++, index++) {
		    key = &job->readbuf[job->readindex[curline].offset];
		    ch = job->readindex[curline].len;
		    crc = XXH3_64bits(key,ch);
		    Bloomset((crc & BLOOMMASK));
		    dbkey.data = key;
		    dbkey.size = ch;
		    dbdata.data = &index;
		    dbdata.size = sizeof(index);
		    if ((res = job->db->put(job->db,NULL,&dbkey,&dbdata,DB_NOOVERWRITE))) {
			if (res == DB_KEYEXIST)
			    rem++;
			else {
			    fprintf(stderr,"Can't write to database. Disk full?\n");
			    fprintf(stderr,"%s\n",db_strerror(res));
			    exit(1);
			}
		    } else {
			unique++;
		    }
		}
		if (job->readbuf == Readbuf) {
		    possess(ReadBuf0);
		    twist(ReadBuf0,BY, -1);
		} else {
		    possess(ReadBuf1);
		    twist(ReadBuf1,BY, -1);
		}
		__sync_add_and_fetch(&Currem_global, rem);
		__sync_add_and_fetch(&Unique_global, unique);
		break;

	    case JOB_FINDDB:
		rem = 0;
		numline = 0;
		memset(&dbkey,0,sizeof(dbkey));
		memset(&dbdata,0,sizeof(dbdata));
		dbkey.flags = DB_DBT_USERMEM;

	        for (curline = job->startline; numline < job->numline; curline++,numline++) {
  		    key = &job->readbuf[job->readindex[curline].offset];
		    ch = job->readindex[curline].len;
		    crc = XXH3_64bits(key,ch);
		    if (Bloom[(crc & BLOOMMASK)/64] & ((uint64_t)1L<<(crc & 0x3f))) {
			dbkey.data = key;
			dbkey.ulen = dbkey.size = ch;
			dbdata.data = &index;
			dbdata.ulen = sizeof(index);
			dbdata.flags = DB_DBT_USERMEM;
			res = job->db->get(job->db,NULL,&dbkey,&dbdata,0);
			if (res == 0 &&  dbdata.size == sizeof(index)) {
			    rem++;
			    if (DoCommon) {
				Commonset(*(uint64_t *)dbdata.data);
			    } else {
				res = job->db->del(job->db,NULL,&dbkey,0);
				if (res != 0) {
				    fprintf(stderr,"DB Delete error\n%s\n",db_strerror(res));
				    exit(1);
				}
			    }
			}
		    }
		}
		if (rem) {
		    __sync_add_and_fetch(&Currem_global,rem);
		}
		if (job->readbuf == Readbuf) {
		    possess(ReadBuf0);
		    twist(ReadBuf0,BY, -1);
		} else {
		    possess(ReadBuf1);
		    twist(ReadBuf1,BY, -1);
		}
		break;

	    default:
	        fprintf(stderr,"Unknown job function: %d\n",job->func);
		exit(1);
	}
	job->func = 0;
	possess(FreeWaiting);
	*FreeTail = job;
	FreeTail = &(job->next);
	twist(FreeWaiting, BY, +1);
    }
}

/*
 * filljob is used to supply data to the JOB_COUNT operation of the procjob.
 *
 * It is run as a separate thread in order to make the mainline code as
 * simple as possible - this just fills the WorkWaiting list with
 * data blocks for the JOB_COUNT fuction, and when it is out of data,
 * waits for the queue to drain and exits.
 */
MDXALIGN void filljob(void *dummy) {
    struct JOB *job;
    uint64_t work,filesize;
    char *eol;


    filesize = Filesize;
    work = 0;
    while (work < filesize) {
	possess(FreeWaiting);
	wait_for(FreeWaiting, NOT_TO_BE,0);
	job = FreeHead;
	FreeHead = job->next;
	if (FreeHead == NULL) FreeTail = &FreeHead;
	twist(FreeWaiting, BY, -1);
	job->next = NULL;
	job->func = JOB_COUNT;
	job->start = work;
	job->end = work + WorkUnitLine;
	if (job->end > filesize) {
	    job->end = filesize;
	} else {
	    eol = findeol(&Fileinmem[job->end],filesize-job->end);
	    if (!eol || eol > &Fileinmem[filesize]) {
		job->end = filesize;
	    } else {
		job->end = (eol-Fileinmem) + 1;
	    }
	}
	work = job->end;
	if (Workthread < Maxt) {
	    launch(procjob,NULL);
	    Workthread++;
	}
	possess(WorkWaiting);
	*WorkTail = job;
	WorkTail = &(job->next);
	twist(WorkWaiting,BY,+1);
    }
    possess(FreeWaiting);
    wait_for(FreeWaiting, TO_BE, Maxt);
    release(FreeWaiting);
    possess(Common_lock);
    twist(Common_lock,TO,+1);
    return;
}


/*
 * cacheline is called from main, and reads the input file into buffers
 * By double-buffering, and using locks to keep track of the buffer
 * usage, it is able to keep the input data busy.  It breaks each
 * buffer into "lines", by looking for the eol (\n).  If there is a
 * Windows-style eol (\r\n), this is changed to \n\n, and the length
 * reduced by one.
 *
 * While the input file lines are truely "any length", the remove file
 * lines are limited to a bit less than half the buffer size in length.
 * So, if the buffers are 50 megabytes, then the maximum line length permitted
 * is around 25 megabytes.
 *
 * In practice, I doubt this will affect anyone, but it is something to
 * be aware of
 */
unsigned int cacheline(FILE *fi,char **mybuf,struct LineInfo **myindex) {
    char *curpos,*readbuf, *f;
    static unsigned int nextline;
    unsigned int dest, curline,len, Linecount, rlen;
    struct LineInfo *readindex;
    int cacheindex;
    static char *Lastleft;
    static int Lastcnt;
    int curcnt, curindex, doneline, x;

    cacheindex = Cacheindex;
    curpos = Readbuf;
    readindex = Readindex;
    if (cacheindex) {
        possess(ReadBuf1);
	wait_for(ReadBuf1, TO_BE,0);
	release(ReadBuf1);
	curpos += MAXCHUNK/2;
	readindex += RINDEXSIZE;
    } else {
        possess(ReadBuf0);
	wait_for(ReadBuf0, TO_BE,0);
	release(ReadBuf0);
    }
    readbuf = curpos;
    curcnt = 0;
    Linecount = 0;
    *mybuf = readbuf;
    *myindex = readindex;
    if (Lastcnt) {
        memmove(curpos,Lastleft,Lastcnt);
	curcnt = Lastcnt;
	curpos += Lastcnt;
	Lastcnt = 0;
	Lastleft = NULL;
    }
    curcnt += fread(curpos,1,(MAXCHUNK/2)-curcnt-1,fi);
    curpos = readbuf;
    curindex = 0;

    while (curindex < curcnt) {
	readindex[Linecount].offset = curindex;
	len = 0;
	doneline = 0;
	f = findeol(&curpos[curindex],curcnt-curindex-1);
	if (f) {
	    doneline = 1;
	    rlen = len = f - &curpos[curindex];
	    if (len > 0 && f[-1] == '\r') {
	        f[-1] = '\n';
		rlen--;
	    }
	    if (rlen < 0) rlen = 0;
	    readindex[Linecount].len = rlen;
	    curpos[curindex+rlen] = '\n';
	    curindex += len + 1;
	} else {
	    if (feof(fi)) {
	        curpos[curcnt] = '\n';
		rlen = len = (curcnt - curindex);
		if (len > 1) rlen--;
		if (rlen < 0) rlen = 0;
		if (rlen > 0 && curpos[curindex+rlen-1] == '\n') rlen--;
		if (rlen > 0 && curpos[curindex+rlen-1] == '\r') rlen--;
		if (rlen < 0) rlen = 0;
		readindex[Linecount].len = rlen;
		if (rlen < MAXLINE) {Linecount++; doneline = 1;}
		break;
	    }
	    Lastleft = &curpos[curindex];
	    Lastcnt = curcnt - curindex;
	    if (Lastcnt >= MAXLINE) {
		Lastcnt = 0;
	    }
	    break;
	}
	if (len >= MAXLINE) continue;
	if (doneline) {
	    if (++Linecount >= RINDEXSIZE) {
	        if (curindex < curcnt) {
		    Lastleft = &curpos[curindex];
		    Lastcnt = curcnt - curindex;
		}
		break;
	    }
	}
    }
    Cacheindex ^= 1;
    return(Linecount);
}



/*
 * heapcmp is used to compare two values on the "remove list" heap
 * It puts the lowest value on the top, and sorts files which are
 * at eof to the bottom of the heap
 */
int heapcmp(const void *a, const void *b) {
    struct InHeap *a1 = (struct InHeap *)a;
    struct InHeap *b1 = (struct InHeap *)b;
    if (a1->In->eof || b1->In->eof) {
	if (a1->In->eof && b1->In->eof)
	    return (0);
        if (a1->In->eof) return(1);
	return(-1);
    }
    if (a1->In->curlen == 0 || b1->In->curlen == 0) {
	if (a1->In->curlen < b1->In->curlen) return(1);
	if (a1->In->curlen > b1->In->curlen) return(-1);
	return(0);
    }
    return(mystrcmp(a1->In->curline,b1->In->curline));
}

/*
 * A classic, but still effective.
 * reheap takes an array arranged as a heap, and ensures that the lowest
 * value is always at position 0 in the array.  This permits high
 * performance for the rli2 function, regardless of how many files contain the
 * sorted remove data.  As items are removed from the top of the heap (using
 * getnextline, a single call to reheap will ensure that the "next" higher
 * value is present on the top of the heap.
 */
void reheap(struct InHeap *InH, int cnt)
{
    struct InHeap tmp;
    int child, parent;

    parent = 0;
    while ((child = (parent*2)+1) < cnt) {
        if ((child+1) < cnt && heapcmp(&InH[child],&InH[child+1]) >0)
            child++;
        if (heapcmp(&InH[child],&InH[parent]) < 0) {
            tmp = InH[child];InH[child]=InH[parent];InH[parent]=tmp;
            parent = child;
        } else break;
    }
}

/*
 * getnextline processes an Infiles structure pointer, by
 * 1. getting the next '\n' terminated line from the buffer
 * 2. if there is not enough data in the buffer, moving the
 *    last line, and what is available of the current line, to
 *    the top of the buffer, adjusting counts, and reading the
 *    opened file to fill the buffer.
 * 3. Removing any '\r' immediately proceeding the '\n', and adjusting
 *    the line length.  Note that the length it returns includes the
 *    '\n', so the minimum line length is 1, not 0.  A 0 line
 *    length means that there is no more data, and should also have
 *    the eof flag set.  This is redundant (setting the flag and returning
 *    0 length line), and you should probably just drop the eof flag.
 * 4. If Dedupe is set, this also skips (and counts) duplicate lines.
 * 5. This also checks file order.  If lines are not in lexically sorted
 *    order, then the program will abend, and display the out-of-order
 *    lines and line numbers.
 * 6. If a line appears which is > half the buffer size (more or less),
 *    then the program abends, and the user is encouraged to use a larger
 *    buffer.
 */
void getnextline(struct Infiles *infile) {
    char *lastline,*eol;
    int lastlen, offset, len, res;
    do {
	if (infile->curpos >= infile->end && infile->eof) {
	    infile->curlen = 0;
	    return;
	}
	lastline = infile->curline;
	lastlen = infile->curlen;
	infile->curline = &infile->Buffer[infile->curpos];
	eol = findeol(infile->curline,infile->end - infile->curpos);
	if (!eol) { /* Can't find eol? */
	    offset = lastline - infile->Buffer;
	    len = &infile->Buffer[infile->end]-lastline;
	    memmove(infile->Buffer,lastline,len);
	    lastline -= offset;
	    infile->curline -= offset;
	    infile->curpos -= offset;
	    infile->end -= offset;
	    len = fread(&infile->Buffer[infile->end],1,infile->size-infile->end,infile->fi);
	    infile->end += len;
	    infile->Buffer[infile->end] = '\n';
	    if (len == 0)
		infile->eof = feof(infile->fi);
	    eol = findeol(infile->curline,infile->end - infile->curpos);
	    if (!eol) {
		if (infile->end >= infile->curpos)
		    eol = &infile->Buffer[infile->end];
		else
		    eol = infile->curline;
	    }
	}
	infile->curlen = eol - infile->curline +1;
	if (infile->curpos >= infile->end) {
	    infile->curlen = 0;
	    infile->eof = feof(infile->fi);
	    return;
	}
	infile->line++;
	infile->curpos +=  infile->curlen;
	if (eol > infile->curline && eol[-1] == '\r') {
	    eol[-1] = '\n'; infile->curlen--;
	}
	if (infile->curlen == 0)
	    infile->eof = feof(infile->fi);
	else {
	    if (infile->curlen > ((infile->size/2)-5)) {
		fprintf(stderr,"Line %"PRIu64" in \"%s\" is too long at %"PRIu64"\n",infile->line,infile->fn,infile->curlen);
		fprintf(stderr,"Increase the memory available using -M\n");
		fprintf(stderr,"Memory is set to %"PRIu64", so try -M %"PRIu64"\n",MaxMem, 2*MaxMem);
		exit(1);
	    }
	    res = mystrcmp(lastline,infile->curline);
	    if (res > 0) {
		fprintf(stderr,"File \"%s\" is not in sorted order at line %"PRIu64"\n",infile->fn,infile->line);
		fprintf(stderr,"Line %"PRIu64": ",infile->line-1);prstr(lastline,lastlen);
		fprintf(stderr,"Line %"PRIu64": ",infile->line);prstr(infile->curline,infile->curlen);
		exit(1);
	    }
	    if (res ==0)
		infile->dup++;
	    else
		infile->unique++;
	    if (Dedupe == 0 || res != 0) return;
	}
    } while (1);
}

/*
 * rliwrite will write a buffer to the cache in the supplie Infiles.
 * If the cache is full, the data is flushed to the already-open file
 * attached. You can flush the last cache by using a NULL buffer
 * pointer.
 */
void rliwrite(struct Infiles *outfile,char *buf, size_t len) {
    if (len > outfile->size) {
        fprintf(stderr,"You tried to write %"PRIu64" bytes, but the buffer size is %"PRIu64"\n",len,outfile->size);
	fprintf(stderr,"Use -M option to make the buffers bigger\n");
	exit(1);
    }
    if (outfile->curpos+len > outfile->size || buf == NULL) {
	if (outfile->curpos && fwrite(outfile->Buffer,outfile->curpos,1,outfile->fi) != 1) {
	    fprintf(stderr,"Write error. Disk full?\n");
	    perror(outfile->fn);
	    exit(1);
	}
	outfile->curpos = 0;
    }
    if (buf == NULL) return;
    memcpy(&outfile->Buffer[outfile->curpos],buf,len);
    outfile->curpos += len;
}





/*
 * rli2 takes a list of filenames, in the order
 * inputfile outputfile remove [remove...]
 * It allocates space for the list of files, and divides up the total
 * -M memory available (defauts to about 50 megabytes, via MAXCHUNK)
 *  between all of the files to be used for local caches.
 *  As each file is opened, the first block of the file is read, and
 *  the first line located.  If the first line is too long (bigger than
 *  half the buffer size, more or less) and error message is displayed,
 *  and the program abends.
 *
 *  Once all of the files are opened, the "remove" files are arranged
 *  as a heap, with the smallest lexical line being on top (just qsort,
 *  as there is likely to be just a few.
 *
 *  Next, rli2 process each line from the input file, comparing it
 *  against the top of the heap.  If a match is found then the matching
 *  line is ether added to the output (if -c is in force), or discarded.
 *  The next line is then read from input.
 *
 *  If the top of the heap is smaller than the current input line,
 *  then the next line is read from that remove file, and the heap
 *  adjusted.  This automatically merge-sorts the list of remove files.
 *
 *  If the top of the heap is bigger than the current input line, then the
 *  current line is either written to the output, or discarded, depending
 *  on the -c flag.  This quickly spins through the input until we get
 *  to the next matching "remove" line.
 *
 *  getnextline checks the input order of all of the files, and if any
 *  are out of sort, so this mainline code can happily assume that
 *  all files are perfectly sorted and ready to use.
 *
 *  Once all of the files are read, any last data is flushed, and
 *  all the files are closed.
 *  Allocated memory is not freed, since the next step is to exit
 */
void rli2(int argc, char **argv) {
    struct timespec starttime,curtime;
    double wtime;
    int x, res;
    int64_t lsize, llen, Write, rem;
    char *eol,*linein;
    uint64_t memsize;
    struct InHeap *heap;
    int heapcnt = argc-2;


    current_utc_time(&starttime);

    lsize = MaxMem / argc;
    Infile = calloc(sizeof(struct Infiles),argc);
    heap = calloc(sizeof(struct InHeap),heapcnt);
    if (!Infile || !heap) {
	fprintf(stderr,"Out of memory initializing structures\n");
	exit(1);
    }
    memsize = argc*sizeof(struct Infiles) + heapcnt*sizeof(struct InHeap);
    for (x=0; x < argc; x++) {
	Infile[x].size = lsize;
	Infile[x].Buffer = calloc(lsize+16,1);
	memsize += lsize+16;
	if (!Infile[x].Buffer) {
	    fprintf(stderr,"Could not allocate %"PRIu64" bytes for I/O buffer\n",(uint64_t)lsize);
	    exit(1);
	}
	Infile[x].fn = argv[x];
	if (x == 1) {
	    if (strcmp(argv[x],"stdout") == 0)
		Infile[x].fi = stdout;
	    else
		Infile[x].fi = fopen(argv[x],"wb");
	} else {
	    if (strcmp(argv[x],"stdin") == 0)
		Infile[x].fi = stdin;
	    else
		Infile[x].fi = fopen(argv[x],"rb");
	}
	if (Infile[x].fi == NULL) {
	    fprintf(stderr,"Can't open \"%s\"\n",argv[x]);
	    perror(argv[x]);
	    exit(1);
	}
	if (x != 1) {
	    Infile[x].end = fread(Infile[x].Buffer,1,lsize,Infile[x].fi);
	    Infile[x].Buffer[Infile[x].end] = '\n';
	    if (Infile[x].end == 0) Infile[x].eof = feof(Infile[x].fi);
	    Infile[x].curline = Infile[x].Buffer;
	    eol = findeol(Infile[x].Buffer,Infile[x].end);
	    if (!eol) eol = &Infile[x].Buffer[Infile[x].end];
	    Infile[x].curlen = eol - Infile[x].curline + 1;
	    Infile[x].curpos = Infile[x].curlen;
	    if (eol > Infile[x].curline && eol[-1] == '\r') {
		eol[-1] = '\n'; Infile[x].curlen--;
	    }
	    if (Infile[x].curlen == 0)
		Infile[x].eof = 1;
	    Infile[x].unique = Infile[x].line = 1;
	    if (Infile[x].curlen > ((Infile[x].size/2)-5)) {
		fprintf(stderr,"Line %"PRIu64" in \"%s\" is too long at %"PRIu64"\n",Infile[x].line,Infile[x].fn,Infile[x].curlen);
		fprintf(stderr,"Increase the memory available using -M\n");
		fprintf(stderr,"Memory is set to %"PRIu64", so try -M %"PRIu64"\n",MaxMem, 2*MaxMem);
		exit(1);
	    }
	}
	if (x>1) {
	    heap[x-2].In = &Infile[x];
	}
    }


    qsort(heap,heapcnt,sizeof(struct InHeap),heapcmp);

    for (x=0 ; x < 4; x++) {
       if (memsize < Memscale[x].size) break;
    }

    current_utc_time(&curtime);
    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
    fprintf(stderr,"Estimated memory required: %s (%.02f%s)\nAllocated in %.4f seconds\n",
	 commify(memsize),(double)memsize/Memscale[x].scale,
	 Memscale[x].name,wtime);
    fprintf(stderr,"Start processing input \"%s\"\n",Infile[0].fn);
    current_utc_time(&starttime);

    Write = rem = 0;
    while (Infile[0].curlen && Infile[0].eof == 0) {
	if (heap[0].In->curlen && heap[0].In->eof == 0) {
	    res = mystrcmp(Infile[0].curline,heap[0].In->curline);
	    if (res == 0) {
		if (DoCommon) {
		    rliwrite(&Infile[1],Infile[0].curline,Infile[0].curlen);
		    rem++;Write++;
		} else {
		    rem++;
		}
		getnextline(&Infile[0]);
		continue;
	    }
	    if (res < 0) {
		if (DoCommon == 0) {
		    rliwrite(&Infile[1],Infile[0].curline,Infile[0].curlen);
		    Write++;
		}
		getnextline(&Infile[0]);
		continue;
	    }
	    if (res > 0) {
		getnextline(heap[0].In);
		if (heap[0].In->eof) {
		    current_utc_time(&curtime);
		    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
		    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
		    fprintf(stderr,
			    "%s file \"%s\" complete. %"PRIu64" unique (%"PRIu64" dup lines, %.4f seconds elapsed\n",(DoCommon)?"Common":"Remove",heap[0].In->fn,heap[0].In->unique,heap[0].In->dup,wtime);
		}
		reheap(heap,heapcnt);
	    }
	} else {
	    if (DoCommon == 0) {
		rliwrite(&Infile[1],Infile[0].curline,Infile[0].curlen);
		Write++;
	    }
	    getnextline(&Infile[0]);
	    continue;
	}
    }
    rliwrite(&Infile[1],NULL,0);
    current_utc_time(&curtime);
    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
    fprintf(stderr,"Input file \"%s\" complete. %"PRIu64" unique (%"PRIu64" dup lines) read. %.4f seconds elapsed\n",Infile[0].fn,Infile[0].unique,Infile[0].dup,wtime);
    fprintf(stderr,"%s total lines written, %"PRIu64" lines %s\n",commify(Write),rem,(DoCommon)?"in common":"removed");
    for (x=0; x < argc; x++) {
	fclose(Infile[x].fi);
    }

}








/* The mainline code.  Yeah, it's ugly, dresses poorly, and smells funny.
 *
 * But it's pretty fast.
 */

int main(int argc, char **argv) {
    struct timespec starttime,curtime;
    double wtime;
    int64_t llen;
    uint64_t Line, Estline,  RC, Totrem;
    uint64_t work,curpos, thisnum, Currem, mask;
    struct Linelist *cur, *next;
    int ch,  x, y, progress, Hidebit, last, DoDebug, forkelem, ProcMode;
    int ErrCheck;
    int curline, numline, Linecount;
    char *readbuf;
    struct LineInfo *readindex;
    int Workthread, locoff;
    FILE *fi, *fo;
    uint64_t crc, memsize, memscale;
    off_t filesize, readsize;
    int HashOpt=0;
    struct JOB *job;
    struct WorkUnit *wu, *wulast;
    struct stat sb1;
    char *linein, *newline, **sorted, *thisline, *eol;
    DB *db, *dbo;
    DBT dbkey, dbdata;
    DBC *dbcur;
    char DBNAME[MDXMAXPATHLEN*2],DBOUT[MDXMAXPATHLEN*2];
#ifndef _AIX
    struct option longopt[] = {
	{NULL,0,NULL,0}
    };
#endif

    MaxMem = MAXCHUNK;
    strcpy(TempPath,".");
    ErrCheck = 1;
    DoDebug = 0;
    SortOut = 0;
    Maxdepth_global = 0;
    Workthread = 0;
    last = 99;
    mask = 0xffff;

    ProcMode = Hidebit =  DoCommon = 0;
    Maxt = get_nprocs();
    current_utc_time(&starttime);
#ifdef _AIX
    while ((ch = getopt(argc, argv, "?2hbsficdnvt:p:T:M:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "?2hbsficdnvt:p:T:M:",longopt,NULL)) != -1) {
#endif
	switch(ch) {
	    case '?':
	    case 'h':
errexit:
		linein = Version;
		while (*linein++ != ' ');
		while (*linein++ != ' ');
		fprintf(stderr,"rling version: %s\n\n",linein);
		fprintf(stderr,"rling - remove matching lines from a file\n");
		fprintf(stderr,"rling input output [remfil1 remfile2 ...]\n\n");
		fprintf(stderr,"\t-i\t\tIgnore any error/missing files on remove list\n");
		fprintf(stderr,"\t-d\t\tRemoves duplicate lines from input (on by default)\n");
		fprintf(stderr,"\t-n\t\tDo not remove duplicate lines from input\n");
		fprintf(stderr,"\t-c\t\tOutput lines common to input and remove files\n");
		fprintf(stderr,"\t-s\t\tSort output. Default is input order.\n\t\t\tThis will make the -b and -f options substantially faster\n");
		fprintf(stderr,"\t-t number\tNumber of threads to use\n");
		fprintf(stderr,"\t-p prime\tForce size of hash table\n");
		fprintf(stderr,"\t-b\t\tUse binary search vs hash (slower, but less memory)\n");
		fprintf(stderr,"\t-f\t\tUse files instead of memory (slower, but small memory)\n");
		fprintf(stderr,"\t-2\t\tUse rli2 mode - all files must be sorted. Low mem usage.\n");
		fprintf(stderr,"\t-M memsize\tMaximum memory to use for -f mode\n");
		fprintf(stderr,"\t-T path\t\tDirectory to store temp files in\n");
		fprintf(stderr,"\t-h\t\tThis help\n");
		fprintf(stderr,"\n\tstdin and stdout can be used in the place of any filename\n");
		exit(1);
		break;

	    case 'b':
	        ProcMode = 1;
		break;

	    case 's':
		SortOut = 1;
		break;

	    case 'f':
		ProcMode = 2;
		break;

	    case '2':
		ProcMode = 3;
		break;

	    case 'c':
		DoCommon = 1;
		fprintf(stderr,"Will output lines common to input and remove files\n");
		break;

	    case 'd':
	        Dedupe = 1;
		break;

	    case 'i':
		ErrCheck =0;
		break;

	    case 'n':
	        Dedupe = 0;
		break;

	    case 'p':
		HashOpt = atoi(optarg);
		if (HashOpt <= 0) {
		    fprintf(stderr,"Hash prime must be positive value\n");
		    exit(1);
		}
	        break;

	    case 'M':
	    	RC = atol(optarg);
		if (strlen(optarg)) {
		    ch = optarg[strlen(optarg)-1];
		    switch (ch) {
		        case 'k':
			case 'K':
			    RC *= 1024L;
			    break;
			case 'm':
			case 'M':
			    RC *= 1024L*1024L;
			    break;
			case 'G':
			case 'g':
			    RC *= 1024L*1024L*1024L;
			    break;
			default:
			    break;
		    }
		}
		if (RC <64*1024) {
		    fprintf(stderr,"%"PRIu64" bytes isn't going to be very effective\nTry using more than 64k\n",RC);
		}
		fprintf(stderr,"Memory for cache set to %"PRIu64" bytes (was %"PRIu64")\n",RC,MaxMem);
		MaxMem = RC;
		linein = malloc(MaxMem);
		if (!linein) {
		    fprintf(stderr,"but allocation for that much failed.  Try using a smaller amount\n");
		    exit(1);
		}
		free(linein);
		break;


	    case 'T':
	        if (strlen(optarg) > MDXMAXPATHLEN) {
		    fprintf(stderr,"The path is too long - make it shorter.\n");
		    exit(1);
		}
		strcpy(TempPath,optarg);
		fprintf(stderr,"Temporary file path: %s\n",TempPath);
		break;
	    case 't':
	        x = atoi(optarg);
		if (x < 1 || x > 32768) {
		    fprintf(stderr,"Maximum threads invalid: %d\n",x);
		    exit(1);
		}
		fprintf(stderr,"Maximum number of threads was %d, now %d\n",Maxt,x);
		Maxt = x;
		break;
	    case 'v':
		DoDebug = 1;
		break;
	}
    }
    argc -= optind;
    argv += optind;

    sprintf(DBNAME,"%s/%s%d.db",TempPath,"rling",getpid());
    sprintf(DBOUT,"%s/%s%d.db",TempPath,"rlingo",getpid());

    if (ProcMode == 2 && (Dedupe == 0 )) {
	if (Dedupe == 0) fprintf(stderr,"The -n switch cannot be used with -f\n");
	fprintf(stderr,"Unfortunately, when using file mode, deduplication is required\n");
	exit(1);
    }
    if (ErrCheck) {
        for (x=2; x<argc; x++) {
	    if (strcmp(argv[x],"stdin") == 0 || strcmp(argv[x],"stdout") == 0)
		continue;
	    if (stat(argv[x],&sb1)) {
		fprintf(stderr,"File \"%s\" not found.  Aborting (see -i option)\n",argv[x]);
		exit(1);
	    }
	}
    }
    if (ProcMode == 3) {
	if (argc < 3) {
	    fprintf(stderr,"Need at least an input, output and remove file for sorted remove mode\n");
	    exit(1);
	}
	rli2(argc,argv);
	exit(0);
    }

    Readbuf = malloc(MAXCHUNK+16);
    Readindex = malloc(MAXLINEPERCHUNK*2*sizeof(struct LineInfo)+16);
    Jobs = calloc(Maxt,sizeof(struct JOB));
    WUList = calloc(Maxt,sizeof(struct WorkUnit));
    FreeWaiting = new_lock(Maxt);
    WorkWaiting = new_lock(0);
    WUWaiting = new_lock(0);
    Currem_lock = new_lock(0);
    Common_lock = new_lock(0);
    ReadBuf0 = new_lock(0);
    ReadBuf1 = new_lock(0);
    if (!Readbuf || !Readindex || !WUList || !Jobs || !FreeWaiting || !WorkWaiting || !WUWaiting || !Currem_lock || !ReadBuf0 || !ReadBuf1 || !Common_lock) {
	fprintf(stderr,"Can't allocate space for jobs\n");
	fprintf(stderr,"This means that you don't have enough memory available to even\nstart processing.  Please make more memory available.\n");
	exit(1);
    }
    WorkTail = &WorkHead;
    FreeTail = &FreeHead;
    WUTail = &WUHead;
    last = ((MAXCHUNK)/Maxt)/sizeof(char *);
    if (last < 16) {
	fprintf(stderr,"MAXCHUNK is set too low - please fix\n");
	exit(1);
    }
    WorkUnitSize = last;
    for (work=0,x=0; x<Maxt; x++) {
	*FreeTail = &Jobs[x];
	FreeTail = &(Jobs[x].next);
	WUList[x].Sortlist = (char **)&Readbuf[(x*sizeof(char*))*last];
	WUList[x].ssize = last;
 	WUList[x].wulock = new_lock(0);
	if (!WUList[x].wulock || WUList[x].Sortlist > (char **)(&Readbuf[MAXCHUNK])) {
	    fprintf(stderr,"Can't allocate lock for work unit\n");
	    exit(1);
	}
	Jobs[x].wu = &WUList[x];
    }

    if (argc < 2) {
        fprintf(stderr,"Need at least an input and an output file to process.\n");
	goto errexit;
    }

    if (strcmp(argv[0],"stdin") == 0) {
	fi = stdin;
#ifdef _WIN32
  setmode(0,O_BINARY);
#endif
    } else
	fi = fopen(argv[0],"rb");
    if (!fi) {
	fprintf(stderr,"Can't open:");
	perror(argv[0]);
	exit(1);
    }
    fprintf(stderr,"Reading \"%s\"...",argv[0]);fflush(stderr);
    Line = 0;
    WorkUnitLine =  WorkUnitSize *8;
    if (WorkUnitLine > filesize)
	WorkUnitLine = filesize;

    if (ProcMode < 2) {
	Fileinmem = malloc(MAXCHUNK + 16);
	for (filesize = 0; !feof(fi); ) {
	    readsize = fread(&Fileinmem[filesize],1,MAXCHUNK,fi);
	    if (readsize <= 0) {
		if (feof(fi) || readsize <0) break;
	    }
	    filesize += readsize;
	    Fileinmem = realloc(Fileinmem,filesize + MAXCHUNK + 16);
	    if (!Fileinmem) {
		fprintf(stderr,"Can't get %"PRIu64" more bytes for read buffer\n",(uint64_t)MAXCHUNK);
		fprintf(stderr,"This means that part (%"PRIu64" bytes) of the input file\nread ok, but that's not the end of the file.\nMake more memory available, or decrease the size of the input file\n",filesize);
		exit(1);
	    }
	}
	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"%"PRIu64" bytes total in %.4f seconds\n",filesize,wtime);
	current_utc_time(&starttime);

	Fileinmem = realloc(Fileinmem,filesize + 16);
	if (!Fileinmem) {
	    fprintf(stderr,"Could not shrink memory buffer\n");
	    fprintf(stderr,"Probably a bug in the program\n");
	    exit(1);
	}
	fclose(fi);

	Fileinmem[filesize] = '\n';
	Fileend = &Fileinmem[filesize];
	Filesize = filesize;
	fprintf(stderr,"Counting lines...    ");fflush(stderr);

	WorkUnitLine = filesize / (Maxt * 256);
	if (WorkUnitLine < Maxt)
	    WorkUnitLine = filesize;
	thisline = Fileinmem;
	Estline = filesize / 8;
	if (Estline <10) Estline = 10;
	Sortlist = calloc(Estline,sizeof(char *));
	if (!Sortlist) {
	    fprintf(stderr,"Can't allocate %s bytes for sortlist\n",commify(Estline*8));
	    fprintf(stderr,"All %"PRIu64" bytes of the input file read ok, but there is\nno memory left to build the sort table.\nMake more memory available, or decrease the size of the input file\n",filesize);
	    exit(1);
	}


	launch(filljob,NULL);
	for (curpos = 0; curpos < filesize; ) {
	    possess(WUWaiting);
	    wait_for(WUWaiting, NOT_TO_BE, 0);
	    wulast = NULL;
	    for (x=0,ch = 0,wu = WUHead; wu; wulast = wu, wu = wu->next) {
		    x++;
		if (wu->start == curpos) {
		    if ((Line+wu->count) >= (Estline-2)) {
			if (filesize)
			    RC = Estline + (((filesize - curpos)*Estline)/filesize);
			else
			    RC = Estline + wu->count;
			if (RC < (Line+wu->count)) RC = Line+wu->count;
			Estline = RC;
			Sortlist = realloc(Sortlist,(Estline+16) * sizeof(char *));
			if (!Sortlist) {
			    fprintf(stderr,"Could not re-allocate for Sortlist\n");
			    fprintf(stderr,"This means we read all %"PRIu64"bytes of the input file\nbut we ran out of memory allocating for the sort list\nMake more memory available, or decrease the size of the input file\n",filesize);
			    exit(1);
			}
		    }
		    if (wu->count) {
			memcpy(&Sortlist[Line],wu->Sortlist,wu->count*sizeof(char *));
			Line += wu->count;
		    }
		    curpos = wu->end;
		    if (wu == WUHead) {
			WUHead = wu->next;
		    } else {
			if (wulast != NULL) {
			    wulast->next = wu->next;
			}
		    }
		    if (WUTail == &(wu->next)) {
		       if (wulast == NULL)
			    WUTail = &WUHead;
		       else
			    WUTail = &(wulast->next);
		    }
		    wu->next = NULL;
		    possess(wu->wulock);
		    twist(wu->wulock,BY,-1);
		    ch = -1;
		    break;
		}
	    }
	    if (ch == 0) {
		last = peek_lock(WUWaiting);
		wait_for(WUWaiting, NOT_TO_BE,last);
	    }
	    twist(WUWaiting, BY, ch);
	}
	possess(Common_lock);
	wait_for(Common_lock, TO_BE, 1);
	twist(Common_lock, BY, -1);
	possess(FreeWaiting);
	if (peek_lock(FreeWaiting) != Maxt) {
	    fprintf(stderr,"Line count failure - free waiting is %ld\n",peek_lock(FreeWaiting));
	    wait_for(FreeWaiting, TO_BE,Maxt);
	}
	release(FreeWaiting);
	Sortlist = realloc(Sortlist,(Line+16) * sizeof(char *));
	if (!Sortlist) {
	    fprintf(stderr,"Final Sortlist shrink failed\n");
	    fprintf(stderr,"This means we read all %"PRIu64" bytes of the input file,\nand were able to create the sortlist for all %"PRIu64" lines we found\nLikely, there is a bug in the program\n",filesize,Line);
	    exit(1);
	}
	Sortlist[Line] = NULL;
	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"%c%c%c%cFound %"PRIu64" line%s in %.4f seconds\n",8,8,8,8,(uint64_t)Line,(Line==1)?"":"s",wtime);
	current_utc_time(&starttime);
	Line_global = Line;
	if (DoCommon) {
	    Common = calloc((filesize+64)/64,sizeof(uint64_t));
	    if (!Common || !Common_lock) {
		fprintf(stderr,"Could not allocate space for common array\n");
		fprintf(stderr,"Make more memory available, or reduce size of input file\n");
		exit(1);
	    }
	}

	if (Line) {
	    WorkUnitLine =  WorkUnitSize * (filesize/Line);
	    if (WorkUnitLine > filesize)
		WorkUnitLine = filesize;
	}
	RC = (uint64_t)&Fileinmem[0];
	RC |= (uint64_t)&Fileinmem[filesize];
	Hidebit = (RC & (1LL<<63)) ? 0 : 1;
	if (Hidebit == 0) {
	    fprintf(stderr,"Can't hide the bit\n");
	    exit(1);
	}
	memsize = MAXCHUNK +
		  MAXLINEPERCHUNK*2*sizeof(struct LineInfo)+32 +
		  filesize +
		  Line * sizeof(char **);

	if (ProcMode == 0) {
	    HashSize = HashMask = 0;
	    HashPrime = 513;
	    for (x=0; Hashsizes[x].size != 0; x++) {
		HashPrime = Hashsizes[x].prime;
		if ((Line*2) < Hashsizes[x].size) break;
	    }
	    fprintf(stderr,"Optimal HashPrime is %"PRIu64" ",HashPrime);
	    HashSize = HashPrime;
	    if (HashOpt) {
		fprintf(stderr,"but user requested %d",HashOpt);
		HashPrime = HashOpt;
		HashSize = HashPrime;
		for (work=1024; work && work != HashOpt; work *= 2);
		if (work == HashOpt) {
		    HashMask = work -1;
		    HashSize = work;
		    HashPrime = 0;
		    fprintf(stderr,"\nRequested value is a power-of-two, HashMask=%"PRIu64"x",HashMask);
		}
	    }
	    fprintf(stderr,"\n");

	    memsize += sizeof(struct LineList *)*HashSize +
		      (Line*sizeof(struct Linelist));
	}
    } else {
	if ((x = db_create(&db, NULL,0))) {
	    fprintf(stderr,"db_create: %s\n",db_strerror(x));
	    exit(1);
	}
	db->set_pagesize(db,32768);
	db->set_cachesize(db,MaxMem/(uint64_t)2048L*1024L*1024L*1024L,MaxMem%(uint64_t)2048L*1024L*1024L*1024L,1);
	if ((x = db->open(db, NULL,DBNAME,NULL,DB_BTREE,DB_CREATE|DB_THREAD ,0664))) {
	    fprintf(stderr,"Could not create database \"%s\"\n",DBNAME);
	    fprintf(stderr,"db_open: %s\n",db_strerror(x));
	    exit(1);
	}

	Bloom = calloc(BLOOMSIZE/64 +8,1);
	if (!Bloom) {
	    fprintf(stderr,"Bloom filter could not be allocated\nMake more memory available, or use -M option to reduce cache size from\nthe current %"PRIu64" bytes\n",MaxMem);
	    exit(1);
	}
	while ((Linecount = cacheline(fi,&readbuf,&readindex))) {
	    numline = Linecount;
	    for (curline = 0; curline < Linecount; curline += numline) {
		possess(FreeWaiting);
		wait_for(FreeWaiting, NOT_TO_BE,0);
		job = FreeHead;
		FreeHead = job->next;
		if (FreeHead == NULL) FreeTail = &FreeHead;
		twist(FreeWaiting, BY, -1);
		job->next = NULL;
		job->func = JOB_BUILDDB;
		job->db = db;
		job->start = 0;
		job->end = Line;
		job->startline = curline;
		if ((curline + numline) > Linecount )
		    job->numline = Linecount - curline;
		else
		    job->numline = numline;
		job->readindex = readindex;
		job->readbuf = readbuf;
		if (readbuf == Readbuf) {
		    possess(ReadBuf0);
		    twist(ReadBuf0,BY,+1);
		} else {
		    possess(ReadBuf1);
		    twist(ReadBuf1,BY,+1);
		}
		if (Workthread < Maxt) {
		    launch(procjob,NULL);
		    Workthread++;
		}
		possess(WorkWaiting);
		*WorkTail = job;
		WorkTail = &(job->next);
		twist(WorkWaiting,BY,+1);
		possess(FreeWaiting);
		wait_for(FreeWaiting,TO_BE,Maxt);
		release(FreeWaiting);
	    }
	    Line += Linecount;
	}
	possess(FreeWaiting);
	wait_for(FreeWaiting,TO_BE,Maxt);
	release(FreeWaiting);
	fprintf(stderr,"%"PRIu64" bytes total\nCounting lines...     ",ftell(fi));
	fclose(fi);

	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"%c%c%c%c%"PRIu64" unique (%"PRIu64" duplicate lines) in %.4f seconds\n",8,8,8,8,(uint64_t)Unique_global,(uint64_t)Currem_global,wtime);fflush(stderr);
	current_utc_time(&starttime);
	memsize = MaxMem + BLOOMSIZE/8 + MAXCHUNK;
	if (DoCommon) {
	    Common = calloc(Line/64+16,sizeof(uint64_t));
	    memsize += Line/64+16;
	    if (!Common || !Common_lock) {
		fprintf(stderr,"Could not allocate space for common array\n");
		fprintf(stderr,"Make more memory available, or reduce size of input file\n");
		exit(1);
	    }
	}
    }


    for (x=0 ; x < 4; x++) {
       if (memsize < Memscale[x].size) break;
    }
    fprintf(stderr,"Estimated memory required: %s (%.02f%s)\n",
	 commify(memsize),(double)memsize/Memscale[x].scale,
	 Memscale[x].name);


    switch (ProcMode) {
    	case 0:
	    HashLine = calloc(sizeof(struct Linelist *),HashSize);
	    Linel = malloc(sizeof(struct Linelist)*(Line+2));

	    if (!HashLine ||  !Linel) {
		fprintf(stderr,"Can't allocate processing space for lines\n");
		fprintf(stderr,"Make more memory available, or consider using -b option.\n");
		exit(1);
	    }

	    Currem = 0;

	    fprintf(stderr,"Processing input list...     ");fflush(stderr);
	    curpos = (Line / Maxt);
	    if (curpos < Maxt) curpos = Line;
	    for (work = 0; work < Line; work += curpos) {
		possess(FreeWaiting);
		wait_for(FreeWaiting, NOT_TO_BE,0);
		job = FreeHead;
		FreeHead = job->next;
		if (FreeHead == NULL) FreeTail = &FreeHead;
		twist(FreeWaiting, BY, -1);
		job->next = NULL; job->func = JOB_GENHASH; job->start = work;
		if ((work + curpos) > Line )
		    job->end = Line;
		else
		    job->end = work + curpos;
		if (Workthread < Maxt) {
		    launch(procjob,NULL);
		    Workthread++;
		}
		possess(WorkWaiting);
		*WorkTail = job;
		WorkTail = &(job->next);
		twist(WorkWaiting,BY,+1);
	    }
	    possess(FreeWaiting);
	    wait_for(FreeWaiting,TO_BE,Maxt);
	    release(FreeWaiting);

	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"%c%c%c%c%"PRIu64" unique (%"PRIu64" duplicate lines) in %.4f seconds\n",8,8,8,8,(uint64_t)Unique_global,(uint64_t)Currem_global,wtime);fflush(stderr);
	    current_utc_time(&starttime);

	    fprintf (stderr,"Occupancy is %"PRIu64"/%"PRIu64" %.04f%%, Maxdepth=%"PRIu64"\n",(uint64_t)Occ_global,HashSize ,(double)(Occ_global)*100.0 / (double)(HashSize),Maxdepth_global);
	   break;

    	case 1:
	    fprintf(stderr,"Sorting...");fflush(stderr);
	    WorkUnitLine = Line / Maxt;
	    if (WorkUnitLine < LINELIMIT)
		WorkUnitLine = LINELIMIT;
	    forkelem = 65536; if (forkelem > Line) forkelem = Line /2; if (forkelem < 1024) forkelem= 1024;
	    qsort_mt(Sortlist,Line,sizeof(char **),comp1,Maxt,forkelem);
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr," took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	    thisline = Sortlist[0];
	    Unique_global = Line;
	    Currem = 0;
	    if (Dedupe) {
		fprintf(stderr,"De-duplicating:     ");fflush(stderr);
		Unique_global = Currem_global = 0;
		work = 0;
		while (work < Line) {
		    possess(FreeWaiting);
		    wait_for(FreeWaiting, NOT_TO_BE,0);
		    job = FreeHead;
		    FreeHead = job->next;
		    if (FreeHead == NULL) FreeTail = &FreeHead;
		    twist(FreeWaiting, BY, -1);
		    job->next = NULL;
		    job->func = JOB_DEDUPE;
		    job->start = work;
		    curpos = work + WorkUnitLine;
		    if (curpos > Line) curpos = Line;
		    while (curpos >0 && curpos < Line && curpos > work) {
			if (comp1(&Sortlist[curpos-1],&Sortlist[curpos]) == 0)
			    curpos++;
			else
			    break;
		    }
		    job->end = curpos;
		    work = curpos;
		    possess(WorkWaiting);
		    *WorkTail = job;
		    WorkTail = &(job->next);
		    twist(WorkWaiting,BY,+1);
		}
		possess(FreeWaiting);
		wait_for(FreeWaiting,TO_BE,Maxt);
		release(FreeWaiting);
	    }

	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"%c%c%c%c%"PRIu64" unique (%"PRIu64" duplicate lines) in %.4f seconds\n",8,8,8,8,Unique_global,Currem_global,wtime);fflush(stderr);
	    current_utc_time(&curtime);
	    break;

	case 2:
	    break;
	default:
	    fprintf(stderr,"Unknown ProcMode=%d\n",ProcMode);
	    exit(1);
    }

    Totrem = 0;
    for (x=2; x < argc; x++) {
	Currem_global = 0;
	fprintf(stderr,"%s from \"%s\"... ",(DoCommon)?"Checking common":"Removing",argv[x]);fflush(stderr);
	stat(argv[x],&sb1);
	if (sb1.st_mode & S_IFDIR) {
	    fprintf(stderr,"skipping directory\n");
	    continue;
	}
	if (strcmp(argv[x],"stdin") == 0) {
		fi = stdin;
#ifdef _WIN32
  setmode(0,O_BINARY);
#endif
	} else
	    fi = fopen(argv[x],"rb");
	if (!fi) {
	    fprintf(stderr,"Can't open:");
	    perror(argv[x]);
	    continue;
	}
	while ((Linecount = cacheline(fi,&readbuf,&readindex))) {
	    numline = (Linecount / Maxt);
	    if (numline < Maxt) numline = Linecount;
	    for (curline = 0; curline < Linecount; curline += numline) {
		possess(FreeWaiting);
		wait_for(FreeWaiting, NOT_TO_BE,0);
		job = FreeHead;
		FreeHead = job->next;
		if (FreeHead == NULL) FreeTail = &FreeHead;
		twist(FreeWaiting, BY, -1);
		job->next = NULL;
		switch (ProcMode) {
		    case 0:
			job->func = JOB_FINDHASH;
			break;
		    case 1:
			job->func = JOB_SEARCH;
			break;
		    case 2:
			job->func = JOB_FINDDB;
			job->db = db;
			numline = Linecount;
			break;
		    default:
		        fprintf(stderr,"Unkown ProcMode=%d\n",ProcMode);
			exit(1);
		}
		job->start = 0;
		job->end = Line;
		job->startline = curline;
		if ((curline + numline) > Linecount )
		    job->numline = Linecount - curline;
		else
		    job->numline = numline;
		job->readindex = readindex;
		job->readbuf = readbuf;
		if (readbuf == Readbuf) {
		    possess(ReadBuf0);
		    twist(ReadBuf0,BY,+1);
		} else {
		    possess(ReadBuf1);
		    twist(ReadBuf1,BY,+1);
		}
		if (Workthread < Maxt) {
		    launch(procjob,NULL);
		    Workthread++;
		}
		possess(WorkWaiting);
		*WorkTail = job;
		WorkTail = &(job->next);
		twist(WorkWaiting,BY,+1);
		if (ProcMode == 2) {
		    possess(FreeWaiting);
		    wait_for(FreeWaiting, TO_BE, Maxt);
		    release(FreeWaiting);
		}
	    }
	}
	possess(FreeWaiting);
	wait_for(FreeWaiting, TO_BE, Maxt);
	release(FreeWaiting);
	possess(Currem_lock);
	fprintf(stderr,"%"PRIu64" %s\n",(uint64_t)Currem_global,(DoCommon)?"in common":"removed");
	Totrem += Currem_global;
	release(Currem_lock);
	fclose(fi);
	if (Unique_global <= Totrem) break;
    }
    current_utc_time(&curtime);
    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
    fprintf(stderr,"\n%s total line%s %s in %.4f seconds\n",commify(Totrem),(Totrem==1)?"":"s",(DoCommon)?"in common":"removed",wtime);
    current_utc_time(&starttime);
    if (ProcMode == 0 && SortOut) {
	fprintf(stderr,"Final sort ");fflush(stdout);
	forkelem = 65536; if (forkelem > Line) forkelem = Line /2; if (forkelem < 1024) forkelem= 1024;
	qsort_mt(Sortlist,Line,sizeof(char **),comp1,Maxt,forkelem);
	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"in %.4f seconds\n",wtime);
	current_utc_time(&starttime);
    }
    if (ProcMode == 1 && SortOut == 0) {
	fprintf(stderr,"Final sort ");fflush(stdout);
	qsort_mt(Sortlist,Line,sizeof(char **),comp3,Maxt,forkelem);
	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"in %.4f seconds\n",wtime);
	current_utc_time(&starttime);
    }

    if (strcmp(argv[1],"stdout") == 0) {
	fo = stdout;
#ifdef _WIN32
  setmode(1,O_BINARY);
#endif
    } else
	fo = fopen(argv[1],"wb");;
    if (!fo) {
	fprintf(stderr,"Can't create: ");
	perror(argv[1]);
	exit(1);
    }
    Currem = 0;
    if (ProcMode == 2) {

	memset(&dbkey,0,sizeof(dbkey));
	memset(&dbdata,0,sizeof(dbdata));
	dbkey.flags = DB_DBT_MALLOC;
	dbdata.flags = DB_DBT_MALLOC;
	if (SortOut == 0) {
	    if ((x = db_create(&dbo, NULL,0))) {
		fprintf(stderr,"db_create: %s\n",db_strerror(x));
		exit(1);
	    }
	    dbo->set_pagesize(dbo,32768);
	    dbo->set_cachesize(dbo,MaxMem/(uint64_t)2048L*1024L*1024L*1024L,MaxMem%(uint64_t)2048L*1024L*1024L*1024L,1);
	    dbo->set_bt_compare(dbo,comp4);
	    if ((x = dbo->open(dbo, NULL,DBOUT,NULL,DB_BTREE,DB_CREATE|DB_THREAD ,0664))) {
		fprintf(stderr,"Could not create database \"%s\"\n",DBOUT);
		fprintf(stderr,"db_open: %s\n",db_strerror(x));
		exit(1);
	    }

	    if ((x = db->cursor(db,NULL,&dbcur,0))) {
		fprintf(stderr,"Database corrupt - cannot get cursor\n%s\n",db_strerror(x));
		exit(1);
	    }
	    fprintf(stderr,"Building final output\n");
	    while (1) {
		x = dbcur->c_get(dbcur,&dbkey,&dbdata,DB_NEXT);
		if (x) {
		    if (x == DB_NOTFOUND) break;
		    fprintf(stderr,"Database corrupt on cursor read\n%s\n",db_strerror(x));
		    exit(1);
		}
		if (DoCommon && dbdata.size == 8) {
		    work = *(uint64_t *)dbdata.data;
		    if (Commontest(work) == 0) {
			free(dbkey.data);
			free(dbdata.data);
			continue;
		    }
		}
		x = dbo->put(dbo,NULL,&dbdata,&dbkey,0);

		if (x) {
		    fprintf(stderr,"Can't write final database.  Disk full?\n%s\n",db_strerror(x));
		    exit(1);
		}
		free(dbkey.data);
		free(dbdata.data);
	    }
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Build final output took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	    dbcur->c_close(dbcur);
	    db->close(db,0);
	    unlink(DBNAME);
	    if ((x = dbo->cursor(dbo,NULL,&dbcur,0))) {
		fprintf(stderr,"Database corrupt - cannot get cursor\n%s\n",db_strerror(x));
		exit(1);
	    }
	    fprintf(stderr,"Writing %sto \"%s\"\n",(DoCommon)?"common lines ":"",argv[1]);
	    Write_global = 0;
	    while (1) {
		x = dbcur->c_get(dbcur,&dbkey,&dbdata,DB_NEXT);
		if (x) {
		    if (x == DB_NOTFOUND) break;
		    fprintf(stderr,"Database corrupt on cursor read\n%s\n",db_strerror(x));
		    exit(1);
		}

		if (fwrite(dbdata.data,dbdata.size,1,fo) != 1 || fputc('\n',fo) == EOF) {
		    fprintf(stderr,"Write failed to output file.  Disk full?\n");
		    exit(1);
		}
		free(dbkey.data);
		free(dbdata.data);
		Write_global++;
	    }
	    dbcur->close(dbcur);
	    dbo->close(dbo,0);
	    unlink(DBOUT);
	} else {
	    if ((x = db->cursor(db,NULL,&dbcur,0))) {
		fprintf(stderr,"Database corrupt - cannot get cursor\n%s\n",db_strerror(x));
		exit(1);
	    }
	    fprintf(stderr,"Writing %sto \"%s\"\n",(DoCommon)?"common lines ":"",argv[1]);
	    Write_global = 0;
	    while (1) {
		x = dbcur->c_get(dbcur,&dbkey,&dbdata,DB_NEXT);
		if (x) {
		    if (x == DB_NOTFOUND) break;
		    fprintf(stderr,"Database corrupt on cursor read\n%s\n",db_strerror(x));
		    exit(1);
		}
		if (DoCommon && Commontest(*(uint64_t *)dbdata.data) == 0) {
		    free(dbkey.data);
		    free(dbdata.data);
		    continue;
		}
		if (fwrite(dbkey.data,dbkey.size,1,fo) != 1 || fputc('\n',fo) == EOF) {
		    fprintf(stderr,"Write failed to output file.  Disk full?\n");
		    exit(1);
		}
		Write_global++;
		free(dbkey.data);
		free(dbdata.data);
	    }
	    dbcur->close(dbcur);
	    db->close(db,0);
	    unlink(DBNAME);
	}

    } else {
        fprintf(stderr,"Writing %sto \"%s\"\n",(DoCommon)?"common lines ":"",argv[1]);
	work = Line / Maxt;
	if (work < Maxt) work = Line;
	curline = 1;
	possess(Common_lock);
	Write_global = 0;
	twist(Common_lock,TO,curline);
	for (curpos=0; curpos < Line; curpos += work) {
	    possess(FreeWaiting);
	    wait_for(FreeWaiting, NOT_TO_BE,0);
	    job = FreeHead;
	    FreeHead = job->next;
	    if (FreeHead == NULL) FreeTail = &FreeHead;
	    twist(FreeWaiting, BY, -1);
	    job->next = NULL;
	    job->func = JOB_WRITE;
	    job->fo = fo;
	    job->fn = argv[1];
	    job->startline = curline++;
	    job->start = curpos;
	    job->end = curpos + work;
	    if (job->end > Line) job->end = Line;
	    if (Workthread < Maxt) {
		launch(procjob,NULL);
		Workthread++;
	    }
	    possess(WorkWaiting);
	    *WorkTail = job;
	    WorkTail = &(job->next);
	    twist(WorkWaiting,BY,+1);
	}
	possess(FreeWaiting);
	wait_for(FreeWaiting,TO_BE,Maxt);
	release(FreeWaiting);
	possess(Common_lock);
	release(Common_lock);
    }
    fclose(fo);
    current_utc_time(&curtime);
    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
    fprintf(stderr,"\nWrote %s lines in %.4f seconds\n",commify(Write_global),wtime);

    if (Workthread) {
	possess(FreeWaiting);
	wait_for(FreeWaiting, NOT_TO_BE,0);
	job = FreeHead;
	FreeHead = job->next;
	if (FreeHead == NULL) FreeTail = &FreeHead;
	twist(FreeWaiting, BY, -1);
	job->next = NULL;
	job->func = JOB_DONE;
	possess(WorkWaiting);
	*WorkTail = job;
	WorkTail = &(job->next);
	twist(WorkWaiting,BY,+1);
	x = join_all();
    }

    return(0);
}











