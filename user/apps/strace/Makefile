output_dir=$(DADK_BUILD_CACHE_DIR_TEST_STRACE_0_1_0)

all: strace 
	mv strace $(output_dir)

strace: main.c
	x86_64-linux-musl-gcc -static -o strace main.c

clean:
	rm strace
	rm -f *.o