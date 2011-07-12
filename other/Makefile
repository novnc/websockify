TARGETS=websockify wswrapper.so kumina
CFLAGS += -fPIC

all: $(TARGETS)

websockify: websockify.o websocket.o md5.o
	$(CC) $(LDFLAGS) $^ -lssl -lcrypto -lresolv -o $@

wswrapper.o: wswrapper.h
wswrapper.so: wswrapper.o md5.o
	$(CC) $(LDFLAGS) $^ -shared -fPIC -ldl -lresolv -o $@

websocket.o: websocket.c websocket.h md5.h
websockify.o: websockify.c websocket.h
wswrapper.o: wswrapper.c
	$(CC) -c $(CFLAGS) -o $@ $*.c
md5.o: md5.c md5.h
	$(CC) -c $(CFLAGS) -o $@ $*.c -DHAVE_MEMCPY -DSTDC_HEADERS

kumina: kumina.o
	$(CC) $(LDFLAGS) $^ -lresolv -lssl -o $@

clean:
	rm -f websockify wswrapper.so *.o

