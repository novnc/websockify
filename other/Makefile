TARGETS=websockify kumina
CFLAGS += -fPIC

all: $(TARGETS)

websockify: websockify.o websocket.o
	$(CC) $(LDFLAGS) $^ -lssl -lcrypto -lresolv -o $@

websocket.o: websocket.c websocket.h
websockify.o: websockify.c websocket.h

kumina: kumina.o
	$(CC) $(LDFLAGS) $^ -lresolv -lssl -o $@

clean:
	rm -f websockify kumina *.o

