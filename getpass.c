#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <glob.h>
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
 *
 * By default, getpass does some special processing of file names.  This
 * is an artifact of how I process my local files - you can suppress this
 * processing with the -t and -x options.
 *
 * First, I organize files by name, and then extension.  file.orig is the
 * original file, and is not touched after initial use.
 * file.txt is the list of unsolved hashes
 * file.MD5x01 (for example) is the solved hashes
 * file.SHA1x02 and so on, as each new type of hash is discovered.
 * mdsplit does this automtically.
 *
 * To accomodate this, I have a built-in list of "exclude" extensions, such
 * as .txt, .salt, .orig and so forth.
 * You can replace this with a list of your own, or read a list of new
 * extentions by placing them into a file (one per line), and using
 * x [filename] to read them into getpass
 *
 * The .txt file, therefore, can be used as a sort of "name" for all
 * files associated with a given list.  getpass does this by recognizing
 * .txt, and then expanding that to all files associated with the name
 * by replacing .txt with .*, and looking up all files with matching names.
 *
 * This means getpass 50m.txt will search out all filenames with hash
 * solutions for any kind of hash, associated with the 50m list, and then
 * extract the passwords from from the solved hash lists.
 *
 * You can suppress this behaviour with -n -t (to disable exclude lists, and
 * .txt file processing)
 *
 *
 */

static char *Version = "$Header: /home/dlr/src/mdfind/RCS/getpass.c,v 1.10 2023/09/02 05:27:23 dlr Exp dlr $";

/*
 * $Log: getpass.c,v $
 * Revision 1.10  2023/09/02 05:27:23  dlr
 * Fix memory expansion on read
 *
 * Revision 1.9  2023/09/02 05:16:50  dlr
 * Fix read buffer
 *
 * Revision 1.7  2020/07/31 02:36:55  dlr
 * Add -S/-U to allow $HEX[] map forcing.
 *
 * Revision 1.6  2020/07/30 22:02:47  dlr
 * Portability improvements for clang
 *
 * Revision 1.5  2020/07/29 06:13:42  dlr
 * Better support for windows binary i/o
 *
 * Revision 1.4  2020/07/26 19:05:52  dlr
 * Merge changes from Royce
 *
 * Revision 1.3  2020/07/26 16:52:47  dlr
 * wildcard expansion for windows
 *
 * Revision 1.2  2020/07/26 16:49:28  dlr
 * Add special processing for .txt file
 *
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
int _dowildcard = -1; /* enable wildcard expansion for Windows */

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
    char *in, *eol, *end, *t;
    char *st, *en, delim;
    size_t readsize;
    int64_t cur,size, len, offset;
    int64_t x, needshex, hexlen, llen, ilen;
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
	    if (cur == 0) {
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
nextline:
	cur += len + 1;
	in = &Cache[cur];
    }
}

void fprocess(char *file, char **Exclude) {
    char *cur, *t;
    glob_t myglob;
    size_t f,x, ex;
    int fsize, exsize;
    FILE *fi;

    myglob.gl_offs = 0;
    myglob.gl_pathc = 0;
    myglob.gl_pathv = NULL;
    cur = strdup(file);
    if (!cur) {
        fprintf(stderr,"Out of memory processing wildcard %s\n",file);
	exit(1);
    }
    t = strrchr(cur,'.');
    if (!t) {
        fprintf(stderr,"Can't find final '.' in %s\n",file);
	free(cur);
	return;
    }
    t[1] = '*';t[2] = 0;
    glob(cur,0,NULL,&myglob);
    for (f=0; f < myglob.gl_pathc; f++) {
	fsize = strlen(myglob.gl_pathv[f]);
	for (ex=0; Exclude[ex]; ex++) {
	    exsize = strlen(Exclude[ex]);
	    if (exsize < fsize) {
		if (strcmp(&myglob.gl_pathv[f][fsize-exsize],Exclude[ex]) == 0) {
		    fprintf(stderr,"Skipping \"%s\" because of exclude %s\n",myglob.gl_pathv[f],Exclude[ex]);
		    goto skip;
		}
	    }
	}
	fi = fopen(myglob.gl_pathv[f],"rb");
	if (!fi) {
	    fprintf(stderr,"Can't open %s, skipping\n",myglob.gl_pathv[f]);
	    continue;
	}
	process(fi,myglob.gl_pathv[f]);
	fclose(fi);
skip:   ex = 0;
    }

    globfree(&myglob);
    free(cur);
}






char *Skipfiles[] = {
    ".txt",".orig",".test",".csalt.txt",".fixme",".new",NULL
};


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
    int ch,x,ex,exsize,fsize;
    FILE *fi;
    char *v,buffer[CACHESIZE+16];
    char **Exclude;
    int Excludesize, DisableTxt;
#ifndef _AIX
    struct option longopt[] = {
	{NULL,0,NULL,0}
    };
#endif
    DisableTxt =0;
    Exclude = Skipfiles;
    Cache = NULL;
    Cachesize = 0;
    Unhex = 0;
    Delim = ':';

#ifdef _AIX
    while ((ch = getopt(argc, argv, "htunx:d:c:f:S:U:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "htunx:d:c:f:S:U:",longopt,NULL)) != -1) {
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
	    case 't':
	        DisableTxt = 1;
		break;
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

	    case 'h':
	    default:
		v = Version;
		while (*v++ != ' ')
		    ;
		while (*v++ !=' ')
		    ;
	        fprintf(stderr,"getpass Version %s\n\n",v);
		fprintf(stderr,"extract passwords from result files\n");
		fprintf(stderr,"\n");
		fprintf(stderr,"\t-c [colspec]\tSet extraction to N-, N-M, or -M like cut\n");
		fprintf(stderr,"\t-d [val]\tSet delimiter to character, decimal value, or 0x-style hex value\n");
		fprintf(stderr,"\t-f [field]\tSet extraction to field number. Starts at 1\n");
		fprintf(stderr,"\t-n\t\tDisable extension exclusion entirely (equivalent to -x /dev/null)\n");
		fprintf(stderr,"\t-t\t\tDisable extension expansion (file.txt -> file.txt.[hashtype], etc.)\n");
		fprintf(stderr,"\t-x [file]\tRead excluded extension list from file, replacing default\n");
		fprintf(stderr,"\t-h\t\tThis help\n");
		fprintf(stderr,"\t-S exp\t\tSets $HEX[] conversion for char or range\n");
		fprintf(stderr,"\t-U exp\t\tResets $HEX[] conversion for char or range\n");
		fprintf(stderr,"\t\t\tSpecify a character like a,b,c, or a range like a-f,\n");
		fprintf(stderr,"\t\t\t0x61-0x66 or as decimal values line 0-32.\n");
		fprintf(stderr,"\n");
		fprintf(stderr,"Default excluded extensions:\n\t");
		for (x=0; Skipfiles[x]; x++) fprintf(stderr,"%s ",Skipfiles[x]);
		fprintf(stderr,"\n\n");
		exit(1);
	}
    }
    argc -= optind;
    argv += optind;
#if defined _WIN32 || defined __MSYS__
setmode(1,O_BINARY);
#endif

    if (argc == 0) {
#if defined _WIN32 || defined __MSYS__
setmode(0,O_BINARY);
#endif
        process(stdin,"stdin");
    }
for (x=0; x<argc; x++) {
        if (Exclude) {
	    fsize = strlen(argv[x]);
	    if (DisableTxt == 0 && fsize > 4 && strcmp(&argv[x][fsize-4],".txt") == 0) {
	       fprocess(argv[x],Exclude);
	       goto skip;
	    } else {
		for (ex=0; Exclude[ex]; ex++) {
		    exsize = strlen(Exclude[ex]);
		    if (exsize < fsize) {
			if (strcmp(&argv[x][fsize-exsize],Exclude[ex]) == 0) {
			    fprintf(stderr,"Skipping \"%s\" because of exclude %s\n",argv[x],Exclude[ex]);
			    goto skip;
			}
		    }
		}
	    }
	}

	if (strcmp(argv[x],"stdin") == 0) {
	    fi = stdin;
#if defined _WIN32 || defined __MSYS__
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
skip:   ex = 0;
    }
    return(0);
}














