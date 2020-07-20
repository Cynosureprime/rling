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
 * rling infile infile /dev/null (or nul: on Windows)
 * Reads infile, removes duplicate lines, and writes the output back to
 * infile when done.
 *
 * rling -b infile infile /dev/null 
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

 static char *Version = "$Header: /home/dlr/src/mdfind/RCS/rling.c,v 1.31 2020/07/20 02:45:24 dlr Exp dlr $";
/*
 * $Log: rling.c,v $
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

struct JOB {
    struct JOB *next;
    uint64_t start,end;
    int startline, numline;
    char *readbuf, *fn;
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
#define MDXMAXPATHLEN 5000



char *Fileinmem, *Fileend;
uint64_t Filesize;
uint64_t WorkUnitLine, WorkUnitSize;
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
int DoCommon = 0;
uint64_t *Common;
#define Commonset(offset) {__sync_or_and_fetch(&Common[(uint64_t)(offset)/64],(uint64_t)1L << ((uint64_t)(offset) & 0x3f)); }

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
    char *a1 = (char *)(((uint64_t)*((char **)a)) & 0x7fffffffffffffffL);
    char *b1 = (char *)(((uint64_t)*((char **)b)) & 0x7fffffffffffffffL);
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
		fflush(job->fo);
		Write_global += unique;
		twist(Common_lock,BY, +1);
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
    int ch,  x, y, progress, Dobin, Hidebit, last, DoDebug, forkelem;
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
#ifndef _AIX
    struct option longopt[] = {
	{NULL,0,NULL,0}
    };
#endif
   
    ErrCheck = 1;
    DoDebug = 0;
    Maxdepth_global = 0;
    Workthread = 0;
    last = 99;
    mask = 0xffff;

    Hidebit = Dobin = DoCommon = 0;
    Maxt = get_nprocs();
    current_utc_time(&starttime);
#ifdef _AIX
    while ((ch = getopt(argc, argv, "?hbicdnvt:p:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "?hbicdnvt:p:",longopt,NULL)) != -1) {
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
		fprintf(stderr,"rling input output remfil1 remfile2...\n\n");
		fprintf(stderr,"\t-i\t\tIgnore any error/missing files on remove list\n");
		fprintf(stderr,"\t-d\t\tRemoves duplicate lines from input (on by default)\n");
		fprintf(stderr,"\t-n\t\tDo not remove duplicate lines from input\n");
		fprintf(stderr,"\t-t number\tNumber of threads to use\n");
		fprintf(stderr,"\t-p prime\tForce size of hash table\n");
		fprintf(stderr,"\t-b\t\tUse binary search vs hash (slower, but less memory)\n");
		fprintf(stderr,"\t-c\t\tOutput lines common to input and remove files\n");
		fprintf(stderr,"\t-h\t\tThis help\n");
		fprintf(stderr,"\n\tstdin and stdout can be used in the place of any filename\n");
		exit(1);
		break;

	    case 'b':
	        Dobin = 1;
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
	fprintf(stderr,"This means that you don't have enough memory available to even\nstart processing.  Please make more ram available.\n");
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

    if (argc < 3) {
        fprintf(stderr,"Need at least 3 files to process.\n\n");
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
    Line = 0;

    Fileinmem = malloc(MAXCHUNK + 16);
    fprintf(stderr,"Reading \"%s\"...",argv[0]);fflush(stderr);
    for (filesize = 0; !feof(fi); ) {
	readsize = fread(&Fileinmem[filesize],1,MAXCHUNK,fi);
	if (readsize <= 0) {
	    if (feof(fi) || readsize <0) break;
	}
	filesize += readsize;
	Fileinmem = realloc(Fileinmem,filesize + MAXCHUNK + 16);
	if (!Fileinmem) {
	    fprintf(stderr,"Can't get %"PRIu64" more bytes for read buffer\n",(uint64_t)MAXCHUNK);
	    fprintf(stderr,"This means we were able to read %"PRIu64" bytes of the input file\nbut that's not the end of the file.\nMake more ram available, or decrease the size of the input file\n",filesize);
	    exit(1);
	}
    }
    fprintf(stderr,"%"PRIu64" bytes total\n",filesize);
    
    Fileinmem = realloc(Fileinmem,filesize + 16);
    if (!Fileinmem) {
	fprintf(stderr,"Could not shrink memory buffer\n");
	exit(1);
    }
    fclose(fi);
    if (DoDebug) {
	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"Read took %.4f seconds\n",wtime);
	current_utc_time(&starttime);
    }

    Fileinmem[filesize] = '\n';
    Fileend = &Fileinmem[filesize];
    Filesize = filesize;
    fprintf(stderr,"Counting lines...    ");fflush(stderr);

    thisline = Fileinmem;
    Estline = filesize / 8;
    if (Estline <10) Estline = 10;
    Sortlist = calloc(Estline,sizeof(char *));
    if (!Sortlist) {
	fprintf(stderr,"Can't allocate %s bytes for sortlist\n",commify(Estline*8));
	fprintf(stderr,"This means we were able to read all %"PRIu64" bytes of\nthe input file, but have no memory left to build the sort table.\nMake more ram available, or decrease the size of the input file\n",filesize);
	exit(1);
    }

    WorkUnitLine =  WorkUnitSize *8;
    if (WorkUnitLine > filesize)
        WorkUnitLine = filesize;

    Line = 0;
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
    fprintf(stderr,"%c%c%c%cFound %"PRIu64" line%s\n",8,8,8,8,(uint64_t)Line,(Line==1)?"":"s");
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
    if (DoDebug) {
	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"Linecount took %.4f seconds\n",wtime);
	current_utc_time(&starttime);
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

    if (Dobin == 0) {
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
    for (x=0 ; x < 4; x++) {
       if (memsize < Memscale[x].size) break;
    }
    fprintf(stderr,"Estimated memory required: %s (%.02f%s)\n",
	 commify(memsize),(double)memsize/Memscale[x].scale,
	 Memscale[x].name);
    

    if (Dobin) {
	fprintf(stderr,"Sorting...\n");
	WorkUnitLine = Line / Maxt;
	if (WorkUnitLine < LINELIMIT)
	    WorkUnitLine = LINELIMIT;
	forkelem = 65536; if (forkelem > Line) forkelem = Line /2; if (forkelem < 1024) forkelem= 1024;
	qsort_mt(Sortlist,Line,sizeof(char **),comp1,Maxt,forkelem);
	if (DoDebug) {
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Primary sort took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	}
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

	
	fprintf(stderr,"%c%c%c%c%"PRIu64" unique (%"PRIu64" duplicate lines)\n",8,8,8,8,Unique_global,Currem_global);fflush(stderr);
	if (Dedupe && DoDebug) {
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Deduplication took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	}
	
	Totrem = 0; 
	for (x=2; x < argc; x++) {
	    Currem_global = 0;
	    fprintf(stderr,"Removing from \"%s\"... ",argv[x]);fflush(stderr);
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
		    job->func = JOB_SEARCH;
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
		}
	    }
	    possess(FreeWaiting);
	    wait_for(FreeWaiting, TO_BE, Maxt);
	    release(FreeWaiting);
	    possess(Currem_lock);
	    fprintf(stderr,"%"PRIu64" removed\n",(uint64_t)Currem_global);
	    Totrem += Currem_global;
	    release(Currem_lock);
	    fclose(fi);
	    if (Unique_global <= Totrem) break;
	}
	fprintf(stderr,"\n%s total line%s removed\n",commify(Totrem),(Totrem==1)?"":"s");

	if (DoDebug) {
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Removal process took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	}
	fprintf(stderr,"Final sort\n");
	qsort_mt(Sortlist,Line,sizeof(char **),comp3,Maxt,forkelem); 
	if (DoDebug) {
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Final sort took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	}
    } else {
		 
	HashLine = calloc(sizeof(struct Linelist *),HashSize);
	Linel = malloc(sizeof(struct Linelist)*(Line+2));

	if (!HashLine ||  !Linel) {
	    fprintf(stderr,"Can't allocate processing space for lines\n");
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

	fprintf(stderr,"%c%c%c%c%"PRIu64" unique (%"PRIu64" duplicate lines)\n",8,8,8,8,(uint64_t)Unique_global,(uint64_t)Currem_global);fflush(stderr);
	if (DoDebug) {
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Hash table creation took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	}



	fprintf (stderr,"Occupancy is %"PRIu64"/%"PRIu64" %.04f%%, Maxdepth=%"PRIu64"\n",(uint64_t)Occ_global,HashSize ,(double)(Occ_global)*100.0 / (double)(HashSize),Maxdepth_global);



	Totrem = 0; 
	for (x=2; x < argc; x++) {
	    Currem_global = 0;
	    fprintf(stderr,"Removing from \"%s\"... ",argv[x]);fflush(stderr);
	    stat(argv[x],&sb1);
	    if (sb1.st_mode & S_IFDIR) {
   		fprintf(stderr,"skipping directory\n");
		continue;
	    }
	    if (strcmp(argv[x], "stdin") == 0) {
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
		    job->func = JOB_FINDHASH;
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
		}
	    }
	    possess(FreeWaiting);
	    wait_for(FreeWaiting, TO_BE,Maxt);
	    release(FreeWaiting);
	    possess(Currem_lock);
	    fprintf(stderr,"%"PRIu64" removed\n",(uint64_t)Currem_global);
	    Totrem += Currem_global;
	    release(Currem_lock);
	    fclose(fi);
	    if (Unique_global <= Totrem) break;
	}
	fprintf(stderr,"\n%s total line%s removed\n",commify(Totrem),(Totrem==1)?"":"s");
	if (DoDebug) {
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Remove file process took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	}
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
    fprintf(stderr,"Writing %sto \"%s\"\n",(DoCommon)?"common lines ":"",argv[1]);
    if (DoCommon) {
	for (curpos = 0; curpos < (filesize/64 + 1);curpos++) {
	    if ((RC = Common[curpos])) {
		for (x=0; RC && x < 64; x++, RC = RC >> 1) {
		    if (RC &1) {
			Currem++;
			newline = &Fileinmem[curpos*64+x];
			eol = findeol(newline,newline - Fileend);
			if (!eol) eol = newline;
			if (fwrite(newline,eol-newline,1,fo) != 1 || fputc('\n',fo) == EOF) {    
			    fprintf(stderr,"write error:");perror(argv[1]);
			    exit(1);
			}
		    }
		}
	    }
	}
	Write_global = Currem;
    } else {
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
	if (DoDebug) {
	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0; 
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"Write process took %.4f seconds\n",wtime);
	    current_utc_time(&starttime);
	}
    }
    fclose(fo);
    fprintf(stderr,"\nWrote %s lines\n",commify(Write_global));

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
    










