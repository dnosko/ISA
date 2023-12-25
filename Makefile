CC = gcc
CFLAGS = -Wall -Wextra -Ilib/ -g 
PCAPFLAG = -lpcap

all: sslsniff

packet.o: src/packet.c src/packet.h src/packet.h
	$(CC) src/packet.c $(CFLAGS) -c -o packet.o $(PCAPFLAG)

analyser.o: src/analyser.c src/analyser.h src/packet.h src/error.h
	$(CC) src/analyser.c $(CFLAGS) -c -o analyser.o $(PCAPFLAG)

sslsniff.o: src/sslsniff.c src/analyser.h src/packet.h src/error.h
	$(CC) src/sslsniff.c $(CFLAGS) -c -o sslsniff.o $(PCAPFLAG)

sslsniff: sslsniff.o analyser.o packet.o
	$(CC) sslsniff.o analyser.o packet.o $(CFLAGS) -o sslsniff $(PCAPFLAG)


clean:
	rm *.o sslsniff

