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
#include <Judy.h>
#ifdef INTEL
#include <emmintrin.h>
#include <xmmintrin.h>
#endif

#include "xxh3.h"

/*
 * dedupe is a simple program to de-duplicate a (group of) file, or simply
 * stdin.  It works by creating a Judy array of either the actual input
 * line, or (using -h) a hashed representation of each line.
 * Using the hash will save memory, but may have false positives (because
 * different lines may hash to the same value).  
 */

static char *Version = "$Header: /home/dlr/src/mdfind/RCS/dedupe.c,v 1.5 2020/07/31 02:36:55 dlr Exp dlr $";

/*
 * $Log: dedupe.c,v $
 * Revision 1.5  2020/07/31 02:36:55  dlr
 * Add -S/-U to allow $HEX[] map forcing.
 *
 * Revision 1.4  2020/07/30 23:07:20  dlr
 * change -h to -x, add -h and -? as help
 *
 * Revision 1.3  2020/07/30 22:02:47  dlr
 * Portability improvements for clang
 *
 * Revision 1.2  2020/07/30 17:47:42  dlr
 * Add some comments
 *
 * Revision 1.1  2020/07/30 17:44:59  dlr
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
int Unhex, Dohash;
int _dowildcard = -1; /* enable wildcard expansion for Windows */

Pvoid_t PLhash = (Pvoid_t) NULL;
Pvoid_t PLstr = (Pvoid_t) NULL;

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
    uint64_t hash;
    int Ateof;
    PWord_t ret;

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

	    if (Dohash) {
	        hash = XXH3_64bits(in,hexlen);
		JLG(ret, PLhash, hash);
		if (ret) 
		    *ret = *ret + 1;
		else {
		    JLI(ret,PLhash, hash);
		    if (!ret) {
		        fprintf(stderr,"Could add hash to list.  Out of memory\n");
			exit(1);
		    }
		    *ret = 1;
		    in[hexlen] = '\n';
		    if (fwrite(in,hexlen+1,1,stdout) != 1) {
		        fprintf(stderr,"Write error. Disk full?\n");
			perror("stdout");
			exit(1);
		    }
		}
	    } else {
     		in[hexlen] = 0;
	        JSLG(ret,PLstr,(unsigned char *)in);
		if (ret) 
		    *ret = *ret + 1;
		else {
		    JSLI(ret,PLstr, (unsigned char *)in);
		    if (!ret) {
		        fprintf(stderr,"Could add hash to list.  Out of memory\n");
			exit(1);
		    }
		    *ret = 1;
		    in[hexlen] = '\n';
		    if (fwrite(in,hexlen+1,1,stdout) != 1) {
		        fprintf(stderr,"Write error. Disk full?\n");
			perror("stdout");
			exit(1);
		    }
		}
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
		   Lbuf[ilen++] = ToHex[(in[x]>>4)&0xf];
		   Lbuf[ilen++] = ToHex[(in[x]) &0xf];
		}
		Lbuf[ilen++] = ']';
		in = Lbuf;llen = ilen;
	    }
	    if (Dohash) {
	        hash = XXH3_64bits(in,llen);
		JLG(ret, PLhash, hash);
		if (ret) 
		    *ret = *ret + 1;
		else {
		    JLI(ret,PLhash, hash);
		    if (!ret) {
		        fprintf(stderr,"Could add hash to list.  Out of memory\n");
			exit(1);
		    }
		    *ret = 1;
		    in[llen] = '\n';
		    if (fwrite(in,llen+1,1,stdout) != 1) {
		        fprintf(stderr,"Write error. Disk full?\n");
			perror("stdout");
			exit(1);
		    }
		}
	    } else {
     		in[llen] = 0;
	        JSLG(ret,PLstr,(unsigned char *)in);
		if (ret) 
		    *ret = *ret + 1;
		else {
		    JSLI(ret,PLstr, (unsigned char *)in);
		    if (!ret) {
		        fprintf(stderr,"Could add hash to list.  Out of memory\n");
			exit(1);
		    }
		    *ret = 1;
		    in[llen] = '\n';
		    if (fwrite(in,llen+1,1,stdout) != 1) {
		        fprintf(stderr,"Write error. Disk full?\n");
			perror("stdout");
			exit(1);
		    }
		}
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
    while ((ch = getopt(argc, argv, "?huxS:U:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "?huxS:U:",longopt,NULL)) != -1) {
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
	    case 'x':
	        Dohash = 1;
		fprintf(stderr,"xxHash mode active\n");
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
	        fprintf(stderr,"dedupe Version %s\n\ndedupe [-u] [file file...]\nIf no files supplied, reads from stdin.  Always writes to stdout\nIf stdin is used as a filename, the actual stdin will read\n",v);
		fprintf(stderr,"\t-x\t\tUse xxHash to hash each line. Saves memory\n");
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














