CC = gcc
CXX = g++
VULN_SOURCES = buffer_overflow.c format_string.c command_injection.c use_after_free.c integer_overflow.c \
               null_pointer.c double_free.c heap_overflow.c race_condition.c signed_unsigned.c
SAFE_SOURCES = buffer_overflow_safe.c command_injection_safe.c format_string_safe.c \
               use_after_free_safe.c heap_overflow_safe.c
CPP_SOURCES = cpp_vulns.cpp
SOURCES = $(VULN_SOURCES) $(SAFE_SOURCES)

# Optimization levels: O0 (debug), O1 (basic), O2 (standard), Os (size), Og (debug-friendly)
OPT_LEVELS = O0 O1 O2 Os Og

all: binaries c_targets cpp_targets multi_file_targets stripped_targets

binaries:
	mkdir -p binaries

# C targets at all optimization levels
c_targets: binaries $(foreach opt,$(OPT_LEVELS),$(SOURCES:.c=_$(opt)))

# C++ targets at O0 and O2
cpp_targets: binaries $(CPP_SOURCES:.cpp=_O0) $(CPP_SOURCES:.cpp=_O2)

# Multi-file target
multi_file_targets: binaries
	$(CC) -O0 -g -o binaries/multi_file_O0 multi_file/main.c multi_file/parser.c multi_file/processor.c -Imulti_file
	$(CC) -O2 -o binaries/multi_file_O2 multi_file/main.c multi_file/parser.c multi_file/processor.c -Imulti_file

# Stripped variants (no symbols — simulates real-world binaries)
stripped_targets: binaries c_targets
	for src in $(VULN_SOURCES:.c=); do \
		cp binaries/$${src}_O0 binaries/$${src}_O0_stripped 2>/dev/null && \
		strip binaries/$${src}_O0_stripped; \
		cp binaries/$${src}_O2 binaries/$${src}_O2_stripped 2>/dev/null && \
		strip binaries/$${src}_O2_stripped; \
	done

%_O0: %.c
	$(CC) -O0 -g -o binaries/$@ $<

%_O1: %.c
	$(CC) -O1 -o binaries/$@ $<

%_O2: %.c
	$(CC) -O2 -o binaries/$@ $<

%_Os: %.c
	$(CC) -Os -o binaries/$@ $<

%_Og: %.c
	$(CC) -Og -g -o binaries/$@ $<

%_O0: %.cpp
	$(CXX) -O0 -g -o binaries/$@ $<

%_O2: %.cpp
	$(CXX) -O2 -o binaries/$@ $<

clean:
	rm -f binaries/*

.PHONY: all clean c_targets cpp_targets multi_file_targets stripped_targets
