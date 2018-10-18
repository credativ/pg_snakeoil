all: scan-mem
scan-mem: scan-mem.c Makefile
	gcc -g -lclamav -Wall -o scan-mem $<
clean:
	rm scan-mem
