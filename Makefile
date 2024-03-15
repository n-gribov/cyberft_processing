start:
	cd ./app && ./forwarder start && ./processor start && ./router start

stop:
	cd ./app && ./forwarder stop && ./processor stop && ./router stop

restart:
	cd ./app && ./forwarder restart && ./processor restart && ./router restart

build-deps:
	mkdir tmp && cp -rf deps/src/* tmp
	cd tmp/xmldsig/ && make && cp xmldsig.so xmldsig.pm /usr/local/cyberplat/lib/perl5/5.28/
	cd tmp/cftmq-agent && make && cp cftcp /usr/local/cyberplat/bin/
	cd tmp/cftmq && make && cp cftmq /usr/local/cyberplat/bin/
	rm -rf tmp
	chmod a+x /usr/local/cyberplat/bin/cftmq /usr/local/cyberplat/bin/cftcp
	chmod a+r /usr/local/cyberplat/lib/perl5/5.28/xmldsig.so /usr/local/cyberplat/lib/perl5/5.28/xmldsig.pm
