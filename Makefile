CFLAGS=-Wall -Wmissing-prototypes -Wstrict-prototypes -Wold-style-definition -Werror -O2
LDFLAGS=-lresolv -lssl

all: wsproxy

clean:
	rm -f wsproxy
