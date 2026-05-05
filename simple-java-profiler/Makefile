CC = gcc
CFLAGS = -fPIC -Wall -Wextra
LDFLAGS = -shared

JAVA_HOME ?= /root/.local/share/mise/installs/java/25.0.2
JAVA_INCLUDE = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

TARGETS = libsimple_agent.so libsimple_agent_file.so receiver

all: $(TARGETS) TestProgram.class

libsimple_agent.so: simple_agent.c
	$(CC) $(CFLAGS) $(JAVA_INCLUDE) $(LDFLAGS) -o $@ $<

libsimple_agent_file.so: simple_agent_file.c
	$(CC) $(CFLAGS) $(JAVA_INCLUDE) $(LDFLAGS) -o $@ $<

receiver: receiver.c
	$(CC) $(CFLAGS) -o $@ $<

TestProgram.class: TestProgram.java
	javac $<

clean:
	rm -f $(TARGETS) TestProgram.class /tmp/perf-simple.map /tmp/simple_java_profiler.socket

.PHONY: all clean
