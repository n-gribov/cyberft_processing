CFLAGS  = -Imd5 -Irfc6234 -O2 -Wall -DWITH_BLOBS
LDFLAGS = -levent_core -lkyotocabinet
OBJS    = core.o stomp.o persist.o users.o config.o md5/md5c.o rfc6234/sha256.o

all: $(OBJS)
	g++ $(CFLAGS) -o cftmq main.cpp $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS)

.c.o:
	gcc -c $(CFLAGS) -o $@ $<

.cpp.o:
	g++ -c $(CFLAGS) -o $@ $<
