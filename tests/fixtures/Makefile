CC = gcc
SOURCES = buffer_overflow.c format_string.c command_injection.c use_after_free.c integer_overflow.c

all: binaries $(SOURCES:.c=_O0) $(SOURCES:.c=_O2)

binaries:
	mkdir -p binaries

%_O0: %.c
	$(CC) -O0 -g -o binaries/$@ $<

%_O2: %.c
	$(CC) -O2 -o binaries/$@ $<

clean:
	rm -f binaries/*

.PHONY: all clean
