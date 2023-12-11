.PHONY: all clean

CC = gcc
LDLIBS = -libverbs -lpthread
CFLAGS = -Wall -g
APPS = ib_write_client ib_write_server ib_send_client ib_send_server ib_read_client \
	   ib_read_server ib_send_read_client ib_send_read_server
OBJS = write_client.o write_server.o send_client.o send_server.o read_client.o \
       read_server.o send_read_client.o send_read_server.o common.o
DEPS = common.h

all: ${APPS}

ib_write_client: write_client.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ib_write_server: write_server.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ib_send_client: send_client.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ib_send_server: send_server.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ib_read_client: read_client.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ib_read_server: read_server.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ib_send_read_client: send_read_client.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ib_send_read_server: send_read_server.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(APPS)
