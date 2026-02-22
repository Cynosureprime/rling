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

all: rling getpass rehex splitlen dedupe

yarn.o: yarn.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c yarn.c

qsort_mt.o: qsort_mt.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c qsort_mt.c

rling.o: rling.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c rling.c

rling: rling.o yarn.o qsort_mt.o
	cc  $(COPTS) -pthread -o rling rling.o yarn.o qsort_mt.o

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
