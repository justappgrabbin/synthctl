CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
LDLIBS   = -lz

synthctl: src/main.c src/image.c src/runtime.c src/util.c src/synthctl.h
	$(CC) $(CFLAGS) -o synthctl src/main.c src/image.c src/runtime.c src/util.c $(LDLIBS)

test: synthctl
	sh tests/e2e.sh

clean:
	rm -f synthctl

.PHONY: test clean
