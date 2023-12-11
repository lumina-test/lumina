APP = roce-pkt-dump
CC = gcc
PKGCONF ?= pkg-config
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk) -DALLOW_EXPERIMENTAL_API
LDFLAGS = $(shell $(PKGCONF) --static --libs libdpdk) -lpcap

all: $(APP)

$(APP): main.o
	$(CC) $(CFLAGS) main.o -o $(APP) $(LDFLAGS)

main.o: main.c
	$(CC) -c $(CFLAGS) main.c -o main.o

clean:
	rm -f *.o $(APP)
