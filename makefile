#select compile-time options for various operating systems
#though it might be possible to compile for 32-bit environment,
#its not likely to work well.  Use 64 bit operating environments
#for rling

#COPTS=-DPOWERPC -maltivec
COPTS=-DINTEL
#COPTS=-DPOWERPC -DAIX -maltivec -maix64

all: rling

yarn.o: yarn.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c yarn.c

qsort_mt.o: qsort_mt.c
	cc -fomit-frame-pointer -pthread -O3 $(COPTS) -c qsort_mt.c

rling.o: rling.c 
	cc -fomit-frame-pointer -pthread $(COPTS) -O3 -c rling.c

rling: rling.o yarn.o qsort_mt.o
	cc  $(COPTS) -pthread -o rling rling.o yarn.o qsort_mt.o
