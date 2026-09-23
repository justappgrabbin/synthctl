CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
LDLIBS   = -lz

SRC = src/main.c src/image.c src/runtime.c src/util.c src/snapshot.c src/backend_darwin.c

synthctl: $(SRC) src/synthctl.h
	$(CC) $(CFLAGS) -o synthctl $(SRC) $(LDLIBS)

test: synthctl
	sh tests/e2e.sh

clean:
	rm -f synthctl

.PHONY: test clean
