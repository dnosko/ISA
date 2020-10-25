CC = gcc
CFLAGS = -Wall -Wextra -Ilib/ -g
PCAPFLAG = -lpcap

all: sslsniff

bin/format.o: src/format.c src/format.h src/format.h
	$(CC) src/format.c $(CFLAGS) -c -o bin/format.o $(PCAPFLAG)

bin/packet.o: src/packet.c src/packet.h src/packet.h
	$(CC) src/packet.c $(CFLAGS) -c -o bin/packet.o $(PCAPFLAG)

bin/analyser.o: src/analyser.c src/analyser.h src/packet.h src/error.h
	$(CC) src/analyser.c $(CFLAGS) -c -o bin/analyser.o $(PCAPFLAG)

bin/sslsniff.o: src/sslsniff.c src/analyser.h src/packet.h src/error.h
	$(CC) src/sslsniff.c $(CFLAGS) -c -o bin/sslsniff.o $(PCAPFLAG)

sslsniff: bin/sslsniff.o bin/analyser.o bin/packet.o bin/format.o
	$(CC) bin/sslsniff.o bin/analyser.o bin/packet.o bin/format.o $(CFLAGS) -o sslsniff $(PCAPFLAG)


clean:
	rm bin/* sslsniff
