#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#ifndef _AIX
#include <getopt.h>
#endif
#ifdef INTEL
#include <emmintrin.h>
#include <xmmintrin.h>
#endif

#ifndef PATH_MAX
#define MAXPATHLEN 1024
#else
#define MAXPATHLEN PATH_MAX
#endif

/*
 * splitlen allows you to split files by line length.
 * you can specify the position in the output file to place the line
 * length, or splitlen will simply append the length to the output file
 * name.
 * Any number of lengths are supported.  The program will 
 * automatically open files and close files as required.
 * Any line length is supported.  The input file buffer will
 * automatically expand as required.
 * files are read from the supplied arguments, or from stdin if no
 * filenames are supplied.  Output filename is specified with the
 * -o argument.  Any input file can be replaced with stdin.  Files
 * are read in order.
 * If an output file exists, it is appended to.
 */

static char *Version = "$Header: /home/dlr/src/mdfind/RCS/splitlen.c,v 1.4 2020/07/30 22:02:47 dlr Exp dlr $";

/*
 * $Log: splitlen.c,v $
 * Revision 1.4  2020/07/30 22:02:47  dlr
 * Portability improvements for clang
 *
 * Revision 1.3  2020/07/30 16:07:22  dlr
 * Minor optimization
 *
 * Revision 1.2  2020/07/29 07:13:47  dlr
 * Add missing time.h include
 *
 * Revision 1.1  2020/07/29 06:13:06  dlr
 * Initial revision
 *
 *
 */

/* start with a 10k line size.  It will expand this as required, if you
 * have long lines
 */
#define CACHESIZE 10240

char *Cache;
uint64_t Cachesize;
int Unhex;
int _dowildcard = -1; /* enable wildcard expansion for Windows */

char OutLenId;
char OutName[MAXPATHLEN*3];

int OutCacheSize, OutCacheActive;
struct OutCache {
    int64_t len;
    uint64_t lines;
    time_t last;
    FILE *fo;
    char OutName[MAXPATHLEN*3];
    enum {idle=0,ready=1,active=2} state;
} *OutCache;
uint64_t *OutCacheIndex;


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

char ToHex[] = "0123456789abcdef";
unsigned char trhex[] = {
    17, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 16, 16, 17, 16, 16, /* 00-0f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 10-1f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 20-2f */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 16, 16, 16, 16, 16,           /* 30-3f */
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 40-4f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 50-5f */
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 60-6f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 70-7f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 80-8f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 90-9f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* a0-af */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* b0-bf */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* c0-cf */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* d0-df */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* e0-ef */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16};/* f0-ff */



int get32(char *iline, char *dest) {
  unsigned char c,c1,c2, *line = (unsigned char *)iline;
  int cnt;

  cnt = 0;
  while ((c=*line++)) {
     c1 = trhex[c];
     c2 = trhex[*line++];
     if (c1 > 15 || c2 >15)
      break;
     cnt++;
     *dest++ = (c1<<4) + c2;
  }
  return(cnt);
}

void closesome(int some) {
    uint64_t x;
    int any;
    time_t last;

    any = 0;
    last =0;
    if (some) {
	for (x=0; x < OutCacheSize; x++) 
	    if (OutCache[x].state == active) 
		last = (last < OutCache[x].last)?OutCache[x].last : last;
	for (; some; ) {
	    for (x=0; x <OutCacheSize; x++) {
		if (OutCache[x].state == active) {
		    any =1;
		    if (OutCache[x].last < last) {
			fclose(OutCache[x].fo);
			OutCache[x].state = ready;
			some--;
			if (some == 0) return;
		    }
		}
	    }
	    last = last * 2 +1;
	    if (any == 0) return;
	    any = 0;
	}
    } else {
        for (x=0; x < OutCacheSize; x++)  {
	    if (OutCache[x].state == active) {
	        fclose(OutCache[x].fo);
		OutCache[x].state = ready;
	    }
	}
    }
}


FILE *getfo(int64_t len, struct OutCache **outcache) {
    uint64_t x,y, newsize;
    char *dest, *src;
    char delim = OutLenId;
    
    for (x=0; x < OutCacheSize && OutCacheIndex[x] != -1; x++) if (OutCacheIndex[x] == len || OutCacheIndex[x] ==-1) break;
    if (x >= OutCacheSize) {
        newsize = OutCacheSize * 2;
	OutCache = realloc(OutCache, newsize * sizeof(struct OutCache));
	OutCacheIndex = realloc(OutCacheIndex,newsize * sizeof(int64_t));
	if (!OutCache || !OutCacheIndex) {
	    fprintf(stderr,"Could not get additional memory for OutCache.\nPlease make more memory available\n");
	    exit(1);
	}
	for (y=x; y < newsize; y++) {
	    OutCache[y].state = idle;
	    OutCache[y].lines = 0;
	    OutCache[y].len = -1;
	    OutCacheIndex[y] = -1;
	}
	OutCacheSize = newsize;
    }
    if (OutCacheIndex[x] == -1) {
	if (OutCache[x].state != idle) {
	    fprintf(stderr,"Internal program error. Length slot %"PRIu64" was suppposed to be idle, but was not\n",len);
	    exit(1);
	}
        OutCacheIndex[x] = len;
	OutCache[x].len = len;
	OutCache[x].lines = 0;
	src = OutName;
	for (dest=OutCache[x].OutName; *src && *src != delim; src++) 
	    *dest++ = *src;
	dest += sprintf(dest,"_%"PRIi64,len);
	if (*src == delim && src[1]) strncpy(dest,src+1,(MAXPATHLEN*2)-(src-OutName));
	OutCache[x].state = ready;
    }

    if (OutCacheIndex[x] == len && OutCache[x].len == len) {
	if (OutCache[x].state == ready) {
	    OutCache[x].fo = fopen(OutCache[x].OutName,"ab");
	    if (!OutCache[x].fo) {
		perror(OutCache[x].OutName);
		if (errno == ENFILE || errno == EMFILE) {
		    closesome(OutCacheSize/2);
		    OutCache[x].fo = fopen(OutCache[x].OutName,"ab");
		}
	    }
	    if (!OutCache[x].fo) {
		fprintf(stderr,"Could not open file for append\n");
		perror(OutCache[x].OutName);
		exit(1);
	    }
	    OutCache[x].state = active;
	    time(&OutCache[x].last);
	}
	if (OutCache[x].state == active)  {
	    *outcache = &OutCache[x];
	    return(OutCache[x].fo);
	}
    }
    fprintf(stderr,"Unexpected error in getfo.  len=%"PRIi64", x=%"PRIu64"\n",len,x);
    exit(1);
}

void Write(int64_t len,char *out,size_t size) {
    FILE *fo;
    struct OutCache *OutCache;

    fo = getfo(len,&OutCache);
    if (fo && size) {
        if (fwrite(out,size,1,fo) != 1) {
	   fprintf(stderr,"Write error - could not write %"PRIu64" bytes\n",(uint64_t)size);
	   perror(OutCache->OutName);
	   exit(1);
	}
	if (out[size-1] == '\n')
	    OutCache->lines++;
    }
}

void process(FILE *fi, char *fn) {
    char *in, *eol, *end;
    size_t readsize;
    int64_t cur,size, len, offset;
    int64_t x, needshex, hexlen, llen, flen;
    int Tlen;
    char Temp[CACHESIZE];
    int Ateof;

    if (!Cache || Cachesize == 0) {
	Cache = malloc(CACHESIZE + 16);
	if (!Cache) {
	    fprintf(stderr,"Could not allocate %d bytes for cache\n",CACHESIZE);
	    exit(1);
	}
	Cachesize = CACHESIZE;
    }

    readsize = fread(Cache,1,Cachesize,fi);
    if (readsize == 0) return;
    cur = 0;
    size = readsize;
    in = &Cache[cur];
    end = &Cache[size];
    Ateof = 0;
    while (!Ateof) {
again:
	if (size)
	    eol = findeol(in,size-cur);
	else
	    eol = NULL;
	if (!eol && !Ateof) {  /* Can't find end of line */
	    if (cur >= size) { /* out of buffer */
		if (cur > size) cur = size;
		len = size - cur;
		if (len >0) memcpy(Cache,&Cache[cur],len);
		size -= cur;
		cur = 0;
		readsize = fread(&Cache[size],1,Cachesize - size,fi);
		if (readsize == 0) Ateof = 1;
		size += readsize;
		end = &Cache[size];
		in = &Cache[cur];
		if (size == cur) break;
		goto again;
	    }
	    /* Not in the cache.  increase size */
	    Cache = realloc(Cache, (Cachesize *2) + 16);
	    if (!Cache) {
	        fprintf(stderr,"Could not expand cache to %"PRIu64" bytes.  Make more memory\navailable, or check the input file \"%s\"\n",Cachesize*2,fn);
		exit(1);
	    }
	    Cachesize = (Cachesize*2);
	    readsize = fread(&Cache[size],1,Cachesize - size,fi);
	    if (readsize == 0) Ateof = 1;
	    size += readsize;
	    end = &Cache[size];
	    in = &Cache[cur];
	    goto again;
	}
	if (!eol && Ateof) eol = end;
	llen = len = eol - in;
	if (eol > in && eol[-1] == '\r') llen--;
	if (Unhex) {
	    if (strncmp(in,"$HEX[",5) == 0) {
		in[llen] = 0;
	        hexlen = get32(&in[5],in);
	    } else
	        hexlen = llen;
	    in[hexlen] = '\n';
	    Write(hexlen,in,hexlen+1);
	} else {
	    for (needshex = x = 0; !needshex && x <llen; x++) {
		needshex = in[x] <= ' '  || in[x] > 126;
	    }
	    if (needshex) {
		flen = llen * 2 + 6;
		Write(flen,"$HEX[",5);
		for (Tlen = x=0; x < llen; x++) {
		    Temp[Tlen++] = ToHex[(in[x]>>4) & 0xf];
		    Temp[Tlen++] = ToHex[(in[x]) & 0xf];
		    if (Tlen > (CACHESIZE -4)) {
		        Write(flen,Temp,Tlen);
			Tlen = 0;
		    }
		}
		if (Tlen) Write(flen,Temp,Tlen);
		Write(flen,"]\n",2);
	    } else {
		in[llen] ='\n';
                Write(llen, in, llen+1);
	    }
	}
	cur += len + 1;
	in = &Cache[cur];
    }
}


int main(int argc,char **argv) {
    int ch,x;
    FILE *fi;
    char *v;
#ifndef _AIX
    struct option longopt[] = {
	{NULL,0,NULL,0}
    };
#endif

    OutLenId = '#';
    Cache = NULL;
    Cachesize = 0;
    Unhex = 0;

#ifdef _AIX
    while ((ch = getopt(argc, argv, "?huo:c:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "?huo:c:",longopt,NULL)) != -1) {
#endif
	switch(ch) {
	    case 'c':
	        OutLenId = optarg[0];
		break;

	    case 'o':
	        if (strlen(optarg) > MAXPATHLEN) {
		    fprintf(stderr,"The output path you asked for is bigger than the system limit of %d\n",MAXPATHLEN);
		    if (strlen(optarg) > MAXPATHLEN *2) {
		        fprintf(stderr,"It's likely to crash your system.  Use a shorter length.");
			exit(1);
		    }
		    fprintf(stderr,"I'll try it, but don't be surprised if it doesn't work.\n");
		}
		strcpy(OutName,optarg);
		fprintf(stderr,"Output set to: %s\n",OutName);
	        break;
	    case 'u':
	        Unhex = 1;
		break;
	    case '?':
	    case 'h':
	    default:
		v = Version;
		while (*v++ != ' ')
		    ;
		while (*v++ !=' ')
		    ;
	        fprintf(stderr,"splitlen Version %s\n\n",v);
		fprintf(stderr,"splitlen -o filename file [..file]\n");
		fprintf(stderr,"\t-u\t\tRemove $HEX[] encoding from input\n");
		fprintf(stderr,"\t-o filename\tOutput to filename, modified with lengths\n");
		fprintf(stderr,"\t\t\tThe char %c will be replaced with _length in filename\n",OutLenId);
		fprintf(stderr,"\t\t\tIf no %c is in filename, _len will len appended to name\n",OutLenId);
		fprintf(stderr,"\t-c char\t\tUse char as place to insert number in -o file\n");
		
		exit(1);
	}
    }
    argc -= optind;
    argv += optind;
    if (!OutName[0]) {
        fprintf(stderr,"You must supply an output name with -o\n");
	exit(1);
    }

    OutCacheSize = CACHESIZE / sizeof(struct OutCache);
    OutCacheActive = 0;
    if (OutCacheSize < 16) OutCacheSize = 16;
    OutCache = calloc(sizeof(struct OutCache), OutCacheSize);
    OutCacheIndex = calloc(sizeof(int64_t), OutCacheSize);
    if (!OutCache || !OutCacheIndex) {
        fprintf(stderr,"Not enough memory to allocate %d cache slots\n",OutCacheSize);
	exit(1);
    }
    for (x=0; x < OutCacheSize; x++) {
        OutCache[x].state = idle;
	OutCache[x].len = -1;
	OutCacheIndex[x] = -1;
	OutCache[x].lines = 0;
    }

    if (argc == 0) {
#ifdef _WIN32
setmode(0,O_BINARY);
#endif
        process(stdin,"stdin");
    }
    for (x=0; x<argc; x++) {
	if (strcmp(argv[x],"stdin") == 0) {
	    fi = stdin;
#ifdef _WIN32
setmode(0,O_BINARY);
#endif
	} else
	    fi = fopen(argv[x],"rb");
	if (!fi) {
	    fprintf(stderr,"Can't open %s, skipping\n",argv[x]);
	    continue;
	}
	process(fi,argv[x]);
	fclose(fi);
    }
    closesome(0);
    for (x=0; x<OutCacheSize; x++) {
	if (OutCache[x].state == ready) {
	    fprintf(stderr,"Wrote %9"PRIu64" lines to %s\n",OutCache[x].lines,OutCache[x].OutName);
	}
    }
    return(0);
}














