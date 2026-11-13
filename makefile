#select compile-time options for various operating systems
#though it might be possible to compile for 32-bit environment,
#its not likely to work well.  Use 64 bit operating environments
#for rling

#COPTS=-DPOWERPC -maltivec
#COPTS=-DPOWERPC -DAIX -maltivec -maix64

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  COPTS=-DINTEL
else ifeq ($(UNAME_M),i386)
  COPTS=-DINTEL
else
  COPTS=
endif

# GCC needs -fgnu89-inline to emit out-of-line copies of inline functions
UNAME_S := $(shell uname -s)
ifneq ($(UNAME_S),Darwin)
  COPTS += -fgnu89-inline
endif

# rling reads gzip/xz/bzip2/zstd input transparently, so it links the matching
# decoders: zlib, liblzma, libbz2 and libzstd.  Install their dev packages first:
#   Debian/Ubuntu : zlib1g-dev liblzma-dev libbz2-dev libzstd-dev
#   Fedora/RHEL   : zlib-devel xz-devel bzip2-devel libzstd-devel
#   macOS (brew)  : brew install xz zstd        (zlib and bzip2 ship with macOS)
#   FreeBSD       : pkg install zstd            (lzma, bz2 and z are in base)
#
# Resolution: zlib, liblzma and libzstd ship pkg-config files, so we take their
# include and library flags from pkg-config when it can describe them.  That is
# the only thing that gets the paths right everywhere without hardcoding --
# notably the BSDs, where ports headers land in /usr/local/include (which the
# base compiler does not search), and Homebrew/MacPorts on macOS.  When
# pkg-config is absent or a .pc is missing, fall back to bare -l flags, adding
# the macOS package-manager prefixes since the system compiler there searches
# neither /opt/homebrew nor /opt/local.  bzip2 ships no .pc file, but bzlib.h
# and libbz2 sit in a default search path on every target, so it is always a
# plain -lbz2.  The binary links dynamically; the distributed release binaries
# are built statically by a separate script and are unaffected.
COMPRESS_INC := $(shell pkg-config --cflags zlib liblzma libzstd 2>/dev/null)
COMPRESS_LIB := $(shell pkg-config --libs   zlib liblzma libzstd 2>/dev/null)
ifeq ($(strip $(COMPRESS_LIB)),)
  COMPRESS_LIB := -lz -llzma -lzstd
  ifeq ($(UNAME_S),Darwin)
    COMPRESS_INC := $(patsubst %,-I%,$(wildcard /opt/homebrew/include /opt/local/include /usr/local/include))
    COMPRESS_LIB := $(patsubst %,-L%,$(wildcard /opt/homebrew/lib /opt/local/lib /usr/local/lib)) $(COMPRESS_LIB)
  endif
endif
COMPRESS_LIB += -lbz2

all: rling getpass rehex splitlen dedupe

yarn.o: yarn.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c yarn.c

qsort_mt.o: qsort_mt.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c qsort_mt.c

rling.o: rling.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) $(COMPRESS_INC) -c rling.c

rling: rling.o yarn.o qsort_mt.o
	cc  $(COPTS) -pthread -o rling rling.o yarn.o qsort_mt.o $(COMPRESS_LIB)

getpass: getpass.c
	cc -fomit-frame-pointer -O3  $(COPTS) -o getpass getpass.c

rehex: rehex.c
	cc -fomit-frame-pointer -O3  $(COPTS) -o rehex rehex.c

splitlen: splitlen.c
	cc -fomit-frame-pointer -O3  $(COPTS) -o splitlen splitlen.c

dedupe: dedupe.c
	cc -fomit-frame-pointer -O3  $(COPTS) -o dedupe dedupe.c -lJudy

clean:
	rm -f rling getpass rehex splitlen dedupe
	rm -f *.o

# Man pages. Source only -- man renders per terminal width, locale and
# encoding, and every packager expects roff and compresses it itself.
PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man

install-man:
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 man/man1/*.1 $(DESTDIR)$(MANDIR)/man1/
