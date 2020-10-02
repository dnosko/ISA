CC = gcc
CFLAGS= -std=c99 -Wall -Wextra -Wno-missing-field-initializers -D_DEFAULT_SOURCE

HEADERF := $(wildcard *.h)
SOURCEF := $(wildcard *.c)
OBJECTF := $(patsubst %.c, %.o, $(SOURCEF))

all: sslsniff

ssl-sniff: $(SOURCEF) $(HEADERF) $(OBJECTF)
	gcc $(CFLAGS) -o ssl-sniff $(OBJECTF) $(LDFLAGS)

%.o: %.c %.h
	gcc -c $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f ssl-sniff $(OBJECTF)

cleano:
	rm -f $(OBJECTF)
