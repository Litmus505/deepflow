CC = gcc
CFLAGS = -Wall -Wextra -std=c99
AGENT_CFLAGS = -fPIC -Wall -Wextra -std=c99
LDFLAGS = -shared

JAVA_HOME ?= $(shell dirname $(shell dirname $(shell readlink -f $(shell which javac))))
JAVA_INCLUDE = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

TARGETS = libsimple_agent.so libsimple_agent_file.so receiver symbol_parser

all: $(TARGETS) TestProgram.class

libsimple_agent.so: simple_agent.c
	$(CC) $(AGENT_CFLAGS) $(JAVA_INCLUDE) $(LDFLAGS) -o $@ $<

libsimple_agent_file.so: simple_agent_file.c
	$(CC) $(AGENT_CFLAGS) $(JAVA_INCLUDE) $(LDFLAGS) -o $@ $<

receiver: receiver.c
	$(CC) $(CFLAGS) -o $@ $<

symbol_parser: symbol_parser.c
	$(CC) $(CFLAGS) -o $@ $<

TestProgram.class: TestProgram.java
	javac $<

clean:
	rm -f $(TARGETS) TestProgram.class /tmp/perf-simple.map /tmp/simple_java_profiler.socket *.data *.data.old *.folded *.svg

.PHONY: all clean
