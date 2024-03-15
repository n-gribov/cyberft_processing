PERL_INC= `perl -MExtUtils::Embed -e perl_inc`
FLAGS = -Wall -fPIC -shared $(shell /usr/bin/xmlsec1-config --cflags) $(PERL_INC)
FLAGS += -Xlinker -rpath -Xlinker /usr/lib/x86_64-linux-gnu
LIBS = $(shell /usr/bin/xmlsec1-config --libs)

all:
	g++ $(FLAGS) -o xmldsig.so main.cpp xml.cpp perlparams.cpp $(LIBS)
	strip xmldsig.so

clean:
	rm -f xmldsig.so
	rm -f xpath

xpath:
	g++ -Wall -I/usr/include/libxml2 -o xpath xpath.cpp $(LIBS)
