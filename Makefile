ef:	src/elfuck
src/elfuck:src/elfuck.c src/getpw.c src/nrv2e.c src/poly.c src/stubify.c src/decompress.S src/execelf.S src/lock.S include/decompress.h include/elfuck.h include/execelf.h include/getpw.h include/lock.h include/nrv2e.h include/poly.h include/stubify.h
	(cd src; make elfuck)
clean:
	rm -f ef core
	(cd src; make clean)
