CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

pactool: pactool.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pactool

.PHONY: clean
