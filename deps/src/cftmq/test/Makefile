CFLAGS  = -I../
LDFLAGS =
OBJS    = ../stompc.o

all: $(OBJS)
	g++ $(CFLAGS) -o bm2 bm2.cpp $(OBJS) $(LDFLAGS) -luuid
	g++ $(CFLAGS) -o bm_stat bm_stat.cpp -lkyotocabinet
#	g++ $(CFLAGS) -o bm bm.cpp $(OBJS) $(LDFLAGS)
#	g++ $(CFLAGS) -o sender sender.cpp $(OBJS) $(LDFLAGS)
#	g++ $(CFLAGS) -o receiver receiver.cpp $(OBJS) $(LDFLAGS)
#	rm -f $(OBJS)

clean:
	rm -f $(OBJS)

.c.o:
	gcc -c $(CFLAGS) -o $@ $<

.cpp.o:
	g++ -c $(CFLAGS) -o $@ $<
