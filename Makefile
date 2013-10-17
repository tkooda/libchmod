# Makefile

libchmod: libchmod.c
	gcc -fPIC -rdynamic -Wall -g -c libchmod.c
	gcc -shared -Wl,-soname,libchmod.so.1 -o libchmod.so.1.0.1 libchmod.o -lc -ldl

clean:
	rm -f libchmod.o libchmod.so.*
