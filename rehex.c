#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#ifndef _AIX
#include <getopt.h>
#endif
#ifdef INTEL
#include <emmintrin.h>
#include <xmmintrin.h>
#endif

/*
 * rehex is a tool used to change encoding of a line.  If a line
 * has characters that can't be easily viewed as plain text (like embedded
 * NUL characters, or high-bit set) it will wrap the result in $HEX[]
 * to make it more useful.
 *
 * you can "unhex" the input with the -u flag, but no one should do that.
 * Ever. :-)
 *
 * -S and -U allows you specify which characters are considered for $HEX[]
 * encoding.  You can specify them as characters "abc", or "a,b,f", as
 * decimal values like "0,1,2,3,4,5,10,15", or hex values "0x00,0x1,0x02"
 * or as ranges "a-f", "0-10","0x1a-0x1f".   -S sets, and -U unsets the
 * character as being considered.  If any character in a given line contains
 * one or more marked values (appearing as a 1 in the map), then the entire
 * line is marked as $HEX[] required.  You can force no hex conversion
 * with -U 0-255.
 */

static char *Version = "$Header: /home/dlr/src/mdfind/RCS/rehex.c,v 1.7 2020/07/31 02:36:55 dlr Exp dlr $";

/*
 * $Log: rehex.c,v $
 * Revision 1.7  2020/07/31 02:36:55  dlr
 * Add -S/-U to allow $HEX[] map forcing.
 *
 * Revision 1.6  2020/07/30 22:02:47  dlr
 * Portability improvements for clang
 *
 * Revision 1.5  2020/07/29 06:13:42  dlr
 * Better support for windows binary i/o
 *
 * Revision 1.4  2020/07/26 16:53:22  dlr
 * wildcard expansion for windows
 *
 * Revision 1.3  2020/07/25 01:17:14  dlr
 * Minor updates for llen
 *
 * Revision 1.2  2020/07/24 22:18:15  dlr
 * Improve version handling
 *
 * Revision 1.1  2020/07/24 22:15:33  dlr
 * Initial revision
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

char MustHex[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 00-0f */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 10-1f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 20-2f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, /* 30-3f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 40-4f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 50-5f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 60-6f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, /* 70-7f */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 80-8f */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 90-9f */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* a0-af */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* b0-bf */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* c0-cf */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* d0-df */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* e0-ef */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};/* f0-ff */

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


char *Lbuf;
int64_t Lbufsize;

void process(FILE *fi, char *fn) {
    char *in, *eol, *end;
    size_t readsize;
    int64_t cur,size, len, offset;
    int64_t x, needshex, hexlen, llen, ilen;
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
	    if (fwrite(in,hexlen+1,1,stdout) != 1) {
		fprintf(stderr,"Write error.\n");
		perror("stdout");
		exit(1);
	    }
	} else {
	    for (needshex = x = 0; !needshex && x <llen; x++) 
		needshex |= MustHex[(unsigned char)in[x]];
	    if (needshex) {
                if (Lbufsize < (llen*2+7)) {
                    if (!Lbuf) {
                        Lbufsize = (llen*2+7) + CACHESIZE;
                        Lbuf = malloc(Lbufsize);
                        if (!Lbuf) {
                            fprintf(stderr,"Could not allocate memory for local buffer\n");
                            exit(1);
                        }   
                    } else {
                        Lbuf = realloc(Lbuf,Lbufsize + (llen*2+7));
                        if (!Lbuf) {
                            fprintf(stderr,"Could not grow local buffer by %"PRIu64" bytes\n",(uint64_t)(llen)*2 + 7L);
                            exit(1);
                        }
                        Lbufsize += (llen*2)+7;
                    }
                }
		ilen = 5;
		strcpy(Lbuf,"$HEX[");
		for (x=0; x < llen; x++) {
		   Lbuf[ilen++] = ToHex[(in[x] >>4)&0xf];
		   Lbuf[ilen++] = ToHex[(in[x])&0xf];
		}
		Lbuf[ilen++] = ']';
		llen = ilen; in = Lbuf;
	    }
	    in[llen] = '\n';
	    if (fwrite(in,llen+1,1,stdout) != 1) {
		fprintf(stderr,"Write error.\n");
		perror("stdout");
		exit(1);
	    }
	}
	cur += len + 1;
	in = &Cache[cur];
    }
}

void getval (char **i, int *val) {
    char *v = *i;
    if (!*v) return;
    if (*v == '-' || *v == ',') v++;
    if (*v == '0' && v[1] == 'x' && sscanf(v,"0x%x",val) == 1) {
        if (*val < 0 || *val > 255) {
            fprintf(stderr,"Hex value out of range at: %s\n",*i);
	    exit(1);
	}
	v += 2;
	while (*v) {
	    if (*v == ',' || *v == '-') break;
	    v++;
	}
	*i = v;
	return;
    }
    if (isdigit(*v)) {
        *val = atoi(v);
	if (*val < 0 || *val > 255) {
	    fprintf(stderr,"Invalid number at: %s\n",*i);
	    exit(1);
	}
	while (*v && isdigit(*v)) {
	    v++;
	}
	*i = v;
	return;
    }
    *val = *v++;
    if (*val < 0 || *val > 255) {
	fprintf(stderr,"Invalid number at: %s\n",*i);
	exit(1);
    }
    *i = v;
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

    Cache = NULL;
    Cachesize = 0;
    Unhex = 0;

#ifdef _AIX
    while ((ch = getopt(argc, argv, "?huU:S:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "?huU:S:",longopt,NULL)) != -1) {
#endif
	switch(ch) {
	    case 'S':
	    case 'U':
	        v = optarg;
		while (*v) {
		    int start,end;
		    getval(&v,&start);
		    end = start;
		    if (*v == '-') getval(&v, &end);
		    for (x=start; x <= end; x++)
		       MustHex[x] = (ch =='S')? 1 : 0;
		}
		fprintf(stderr,"Will map characters to $HEX[] if a 1 in that character position");
		for (x=0; x <256; x++) {
		    if ((x%32) == 0) fprintf(stderr,"\n%02x-%02x:",x,x+31);
		    fprintf(stderr,"%d",MustHex[x]);
		}
		fprintf(stderr,"\n");
		break;
	        
	    case 'u':
	        Unhex = 1;
		break;
	    case 'h':
	    case '?':
	    default:
		v = Version;
		while (*v++ != ' ')
		    ;
		while (*v++ !=' ')
		    ;
	        fprintf(stderr,"rehex Version %s\n\nrehex [-u] [file file...]\nIf no files supplied, reads from stdin.  Always writes to stdout\nIf stdin is used as a filename, the actual stdin will read\n",v);
		fprintf(stderr,"\t-S exp\t\tSets $HEX[] conversion for char or range\n");
		fprintf(stderr,"\t-U exp\t\tResets $HEX[] conversion for char or range\n");
		fprintf(stderr,"\t\t\tSpecify a character like a,b,c, or a range like a-f,\n");
		fprintf(stderr,"\t\t\t0x61-0x66 or as decimal values line 0-32.\n");
		exit(1);
	}
    }
    argc -= optind;
    argv += optind;
#ifdef _WIN32
setmode(1,O_BINARY);
#endif

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
    return(0);
}














