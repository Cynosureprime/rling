all: rling

yarn.o: yarn.c
	cc -fomit-frame-pointer -pthread -O3 -c yarn.c

qsort_mt.o: qsort_mt.c
	cc -fomit-frame-pointer -pthread -O3 -c qsort_mt.c

rling: rling.c yarn.o qsort_mt.o
	cc  -pthread -fomit-frame-pointer -DPOWERPC -maltivec -O3 -o rling rling.c yarn.o qsort_mt.o
