CFLAGS  = -I../
LDFLAGS =
OBJS    =

all: $(OBJS)
	g++ $(CFLAGS) -o cft_sender main.cpp ../stompc.cpp $(OBJS) $(LDFLAGS)
#	rm -f $(OBJS)

clean:
	rm -f $(OBJS)

.c.o:
	gcc -c $(CFLAGS) -o $@ $<

.cpp.o:
	g++ -c $(CFLAGS) -o $@ $<
