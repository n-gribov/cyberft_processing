CC	= g++
CFLAGS	= `pkg-config libcurl lua5.1 --cflags` -shared -fPIC -fno-rtti -fno-exceptions -I../
LIBS	= `pkg-config libcurl --libs`

all:
	$(CC) $(CFLAGS) -o luastomp.so luastomp.cpp ../stompc.cpp $(LIBS)
	lua sender.lua