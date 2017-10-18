TARGETS=websockify
CFLAGS += -fPIC

all: $(TARGETS)

websockify: websockify.o websocket.o base64.o
	$(CC) $(LDFLAGS) $^ -lssl -lcrypto -o $@

websocket.o: websocket.c websocket.h
websockify.o: websockify.c websocket.h
base64.o: base64.c

clean:
	rm -f websockify *.o

