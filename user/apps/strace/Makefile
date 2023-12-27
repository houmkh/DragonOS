tmp_output_dir=/home/mkh/桌面/dgos/DragonOS/bin/sysroot/bin/

all: strace 
	rm $(tmp_output_dir)strace
	mv strace $(tmp_output_dir)

strace: main.c
	x86_64-linux-musl-gcc -static -o strace main.c

clean:
	rm strace
	rm -f *.o