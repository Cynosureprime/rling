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
 * getpass looks through a set of files (optionally) skipping those that 
 * look like they are not valid result, looking for deliminator-separated
 * words. The default mode will probably work for most people, but you
 * can override it if you have unusual result files, or want to extract
 * certain fields or columns, and the like.
 * As with the rest of the utilities, getpass strives to have unlimited line
 * lengths, and auto-sizes the buffers to accomplish this.
 */

static char *Version = "$Header: /home/dlr/src/mdfind/RCS/getpass.c,v 1.1 2020/07/25 01:17:14 dlr Exp dlr $";

/*
 * $Log: getpass.c,v $
 * Revision 1.1  2020/07/25 01:17:14  dlr
 * Initial revision
 *
 */

/* start with a 10k line size.  It will expand this as required, if you
 * have long lines
 */
#define CACHESIZE 10240

char *Cache;
uint64_t Cachesize;
int Unhex,Fieldnum,Colstart,Colend;
int Delim;

/*
 * findeol(pointer, length)
 *
 * findeol searches for the next eol character (\n, 0x0a) in a string
 *
 * The Intel version uses SSE to process 128 bits at a time.  This only
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



void process(FILE *fi, char *fn) {
    char *in, *eol, *end, *t;
    char *st, *en, delim;
    size_t readsize;
    int64_t cur,size, len, offset;
    int64_t x, needshex, hexlen, llen;
    int Ateof, field;

    delim = (char)Delim;

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
	len = eol - in;
	llen = len;
	if (eol > in && eol[-1] == '\r') llen--;
	if (Fieldnum) {
	    st = in; en = in;
	    for (field = 0; en < eol;en++) {
	        if (*en == delim) {
		    field++;
		    if (Fieldnum == field) break;
		    st = en + 1;
		}
	    }
	    if (en >= eol) field++;
	    if (Fieldnum != field) goto nextline;
	    in = st;
	    if (in > en) goto nextline;
	    llen = en - in;
	} else if (Colstart || Colend) {
	    if (llen < Colstart) goto nextline;
	    in += Colstart-1; llen -= Colstart-1;
	    if (Colend && Colstart <Colend) 
	        llen = (Colend-Colstart);
	    if (llen > (len-Colstart)) goto nextline;
	} else {
	    for (x=llen-1; x > 0; x--) 
	        if (in[x] == delim) break;
	    if (x>0 && in[x] == ':') {
	        llen -= x +1;
		in = &in[x+1];
		if (llen <0) goto nextline;
	    } else
	        goto nextline;
	}

	if (Unhex) {
	    if (strncmp(in,"$HEX[",5) == 0) {
		in[llen] = 0;
	        hexlen = get32(&in[5],in);
	    } else 
	        hexlen = llen;
	    if(hexlen && fwrite(in,hexlen,1,stdout) != 1) {
		fprintf(stderr,"Write error.\n");
		perror("stdout");
		exit(1);
	    }
	    fputc('\n',stdout);
	} else {
	    for (needshex = x = 0; !needshex && x <llen; x++) {
		needshex = in[x] <= ' '  || in[x] > 126;
	    }

	    if (needshex) {
	        printf("$HEX[");
		for (x=0; x < llen; x++)
		   printf("%02x",in[x] & 0xff);
		printf("]\n");
	    } else {
	        if (llen && fwrite(in,llen,1,stdout) != 1) {
		    fprintf(stderr,"Write error.\n");
		    perror("stdout");
		    exit(1);
		}
		fputc('\n',stdout);
	    }
	}
nextline:
	cur += len + 1;
	in = &Cache[cur];
    }
}


char *Skipfiles[] = {
    ".txt",".orig",".test",".csalt.txt",".fixme",".new",NULL
};


int main(int argc,char **argv) {
    int ch,x,ex,exsize,fsize;
    FILE *fi;
    char *v,buffer[CACHESIZE+16];
    char **Exclude;
    int Excludesize;
#ifndef _AIX
    struct option longopt[] = {
	{NULL,0,NULL,0}
    };
#endif
    Exclude = Skipfiles;
    Cache = NULL;
    Cachesize = 0;
    Unhex = 0;
    Delim = ':';

#ifdef _AIX
    while ((ch = getopt(argc, argv, "unx:d:c:f:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "unx:d:c:f:",longopt,NULL)) != -1) {
#endif
	switch(ch) {
	    case 'n':
	        Exclude = NULL;
		break;
	    case 'd':
	        if (strlen(optarg) >1) {
		    if (strncmp(optarg,"0x",2) == 0)
		        sscanf(optarg,"0x%x",&Delim);
		    else
		        Delim = atoi(optarg);
		    if (Delim <0 || Delim > 255) {
		        fprintf(stderr,"Invalid delimiter %s\n",optarg);
			exit(1);
		    }
		} else 
		    Delim = *optarg;
		break;

	    case 'c':
	        v = optarg;
		Colstart = 0; Colend = 0;
		if (isdigit(*v)) {
		    Colstart = atoi(v);
		    while (isdigit(*++v));
		}
		if (*v == '-') v++;
		if (isdigit(*v))
		   Colend = atoi(v);
		break;

	    case 'f':
	        Fieldnum = atoi(optarg);
		break;
	    case 'u':
	        Unhex = 1;
		break;
	    case 'x':
	        fi = fopen(optarg,"r");
		if (!fi) {
		    fprintf(stderr,"Can't open exclude file %s\n",optarg);
		    perror(optarg);
		    exit(1);
		}
		Excludesize = (CACHESIZE/sizeof(char **));
		Exclude = calloc(Excludesize+4,sizeof(char **));
		if (!Exclude) {
		    fprintf(stderr,"Out of memory allocating for exclude file\n");
		    exit(1);
		}
		x = 0;
		while (fgets(buffer,CACHESIZE,fi)) {
		    Exclude[x] = strdup(buffer);
		    if (!Exclude[x]) {
		        fprintf(stderr,"Out of memory allocating for exclude line %d\n",x);
		        exit(1);
		    }
		    if (++x >= Excludesize) {
		        Exclude = realloc(Exclude,(Excludesize*2) + 4);
			if (!Exclude) {
			    fprintf(stderr,"Out of memory allocating extra space for Exclude line %d\n",x);
			    exit(1);
			}
		    }
		}
		fclose(fi);
		break;

	    default:
		v = Version;while (*v++ != ' ');while (*v++ !=' ');
	        fprintf(stderr,"getpass Version %s\n\n",v);
		fprintf(stderr,"extract passwords from result files\n");
		fprintf(stderr,"\t-d [val]\t\tSet Delimter to character, decimal value, or 0x-style hex value\n");
		fprintf(stderr,"\t-c [colspec]\tSet extraction to N-,N-M, or -M like cut\n");
		fprintf(stderr,"\t-f [field]\tSet extraction to field number. Starts at 1\n");
		fprintf(stderr,"\t-x file\t\tRead exclude extension list from file, replacing default\n");
		exit(1);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc == 0)
        process(stdin,"stdin");
for (x=0; x<argc; x++) {
        if (Exclude) {
	    for (ex=0; Exclude[ex]; ex++) {
	        exsize = strlen(Exclude[ex]);
		fsize = strlen(argv[x]);
		if (exsize < strlen(argv[x])) {
		    if (strcmp(&argv[x][fsize-exsize],Exclude[ex]) == 0) {
		        fprintf(stderr,"Skipping \"%s\" because of exclude %s\n",argv[x],Exclude[ex]);
			goto skip;
		    }
		}
	    }
	}
	
	if (strcmp(argv[x],"stdin") == 0) 
	    fi = stdin;
	else
	    fi = fopen(argv[x],"rb");
	if (!fi) {
	    fprintf(stderr,"Can't open %s, skipping\n",argv[x]);
	    continue;
	}
	process(fi,argv[x]);
	fclose(fi);
skip:   ex = 0;
    }
    return(0);
}

           










        
    
