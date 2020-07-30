#select compile-time options for various operating systems
#though it might be possible to compile for 32-bit environment,
#its not likely to work well.  Use 64 bit operating environments
#for rling
#ensure you have package libdb-dev installed

#COPTS=-DPOWERPC -maltivec
COPTS=-DINTEL
#COPTS=-DPOWERPC -DAIX -maltivec -maix64

all: rling getpass rehex splitlen dedupe

yarn.o: yarn.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c yarn.c

qsort_mt.o: qsort_mt.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c qsort_mt.c

rling.o: rling.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c rling.c

rling: rling.o yarn.o qsort_mt.o
	cc  $(COPTS) -pthread -o rling rling.o yarn.o qsort_mt.o -ldb

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
	rm -f qsort_mt.o rling.o yarn.o
