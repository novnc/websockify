/*-
 * Copyright (c) 2011 Ed Schouten <ed@kumina.nl>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <fcntl.h>
#include <resolv.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#define	MAXOFRAME		UINT16_MAX
#define	HYBI10_ACCEPTHDRLEN	29

#ifdef DEBUG
#define	DPRINTF(fmt, ...)	fprintf(stderr, fmt "\n", ## __VA_ARGS__)
#else
#define	DPRINTF(fmt, ...)
#endif

static pid_t other = -1;
static int hybi10 = 0;

static void
die(int exitcode)
{

	if (other != -1)
		kill(other, SIGTERM);
	exit(exitcode);
}

static void
usage(void)
{

	fprintf(stderr, "usage: wsproxy minport maxport\n");
	exit(1);
}

static unsigned char
pgetc(FILE *fp)
{
	int ret;

	ret = fgetc(fp);
	if (ret == EOF)
		die(0);
	return (ret);
}

static void
putb64(FILE *out, const char *inb, size_t *inblen)
{
	char inbuf[5] = { 0 };
	unsigned char outbuf[3];
	ssize_t outbuflen;

	if (*inblen == 0)
		return;

	assert(*inblen <= 4);
	memcpy(inbuf, inb, *inblen);
	outbuflen = b64_pton(inbuf, outbuf, sizeof outbuf);
	if (outbuflen <= 0) {
		DPRINTF("invalid Base64 data");
		die(1);
	}
	if (fwrite(outbuf, outbuflen, 1, out) != 1) {
		perror("fwrite");
		die(1);
	}
	*inblen = 0;
}

/*
 * Support for HyBi10.
 */

static void
hybi10_calcaccepthdr(const char *key, char *out)
{
	SHA_CTX c;
	unsigned char hash[SHA_DIGEST_LENGTH];
	int r;

	SHA1_Init(&c);
	SHA1_Update(&c, key, strlen(key));
	SHA1_Update(&c, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
	SHA1_Final(hash, &c);

	r = b64_ntop(hash, sizeof hash, out, HYBI10_ACCEPTHDRLEN);
	assert(r == HYBI10_ACCEPTHDRLEN - 1);
}

static uint64_t
hybi10_getlength(FILE *in)
{
	uint64_t len;
	int lenlen;
	unsigned char ch;

	ch = pgetc(in);
	if (!(ch & 0x80)) {
		DPRINTF("mask bit not set");
		die(1);
	}
	ch &= ~0x80;

	/* Two or eight bytes of input length? */
	switch (ch) {
	case 126:
		lenlen = 2;
		break;
	case 127:
		lenlen = 8;
		break;
	default:
		/* Small packet, length encoded directly. */
		return (ch);
	}

	len = 0;
	while (lenlen-- > 0)
		len = len << 8 | pgetc(in);
	return (len);
}

static void
hybi10_getmasks(FILE *in, unsigned char masks[4])
{
	int i;

	for (i = 0; i < 4; i++)
		masks[i] = pgetc(in);
}

static void
hybi10_decode(FILE *in, int outfd)
{
	FILE *out;
	unsigned char ch, masks[4];
	char inb[4];
	size_t inblen = 0;
	uint64_t i, framelen;

	out = fdopen(outfd, "w");
	if (out == NULL) {
		perror("fdopen");
		die(1);
	}

	for (;;) {
		/* Frame header. */
		ch = pgetc(in);
		if (ch != 0x81) {
			DPRINTF("unsupported packet received: %#hhx", ch);
			die(1);
		}

		/* Payload length. */
		framelen = hybi10_getlength(in);
		hybi10_getmasks(in, masks);
		for (i = 0; i < framelen; i++) {
			ch = pgetc(in) ^ masks[i % 4];
			if (!((ch >= 'A' && ch <= 'Z') ||
			    (ch >= 'a' && ch <= 'z') ||
			    (ch >= '0' && ch <= '9') ||
			    ch == '+' || ch == '/' || ch == '=')) {
				DPRINTF("non-Base64 character received");
				die(1);
			}

			/* Base64 character. */
			inb[inblen++] = ch;
			if (inblen == sizeof inb)
				putb64(out, inb, &inblen);
		}

		/* Frame trailer. */
		putb64(out, inb, &inblen);
		if (fflush(out) == -1) {
			perror("fflush");
			die(1);
		}
	}
}

static void
hybi10_encode(int in, int out)
{
	unsigned char inbuf[MAXOFRAME / 4 * 3];
	char outbuf[MAXOFRAME + 5]; /* Four-byte header + nul. */
	ssize_t len, wlen;

	for (;;) {
		len = read(in, inbuf, sizeof inbuf);
		if (len == -1) {
			perror("read");
			die(1);
		} else if (len == 0)
			die(0);

		/* Encode data as Base64. */
		len = b64_ntop(inbuf, len, outbuf + 4, sizeof outbuf - 4);
		assert(len > 0 && len <= MAXOFRAME);
		/* Frame header. */
		outbuf[0] = 0x81;
		outbuf[1] = 126;
		outbuf[2] = len >> 8;
		outbuf[3] = len;
		len += 4;

		wlen = write(out, outbuf, len);
		if (wlen == -1) {
			perror("write");
			die(1);
		} else if (wlen != len)
			die(0);
	}
}

/*
 * Support for Hixie 76.
 */

static void
hixie76_calcresponse(uint32_t key1, uint32_t key2, const char *key3, char *out)
{
	MD5_CTX c;
	char in[16] = {
	    key1 >> 24, key1 >> 16, key1 >> 8, key1,
	    key2 >> 24, key2 >> 16, key2 >> 8, key2,
	    key3[0], key3[1], key3[2], key3[3],
	    key3[4], key3[5], key3[6], key3[7]
	};

	MD5_Init(&c);
	MD5_Update(&c, (void *)in, sizeof in);
	MD5_Final((void *)out, &c);
}

static void
hixie76_decode(FILE *in, int outfd)
{
	FILE *out;
	unsigned char ch;
	char inb[4];
	size_t inblen = 0;

	out = fdopen(outfd, "w");
	if (out == NULL) {
		perror("fdopen");
		die(1);
	}

	for (;;) {
		/* Frame header. */
		ch = pgetc(in);
		if (ch != 0x00) {
			DPRINTF("unsupported packet received: %#hhx", ch);
			die(1);
		}

		while ((ch = pgetc(in)) != 0xff) {
			if (!((ch >= 'A' && ch <= 'Z') ||
			    (ch >= 'a' && ch <= 'z') ||
			    (ch >= '0' && ch <= '9') ||
			    ch == '+' || ch == '/' || ch == '=')) {
				DPRINTF("non-Base64 character received");
				die(1);
			}

			/* Base64 character. */
			inb[inblen++] = ch;
			if (inblen == sizeof inb)
				putb64(out, inb, &inblen);
		}

		/* Frame trailer. */
		putb64(out, inb, &inblen);
		if (fflush(out) == -1) {
			perror("fflush");
			die(1);
		}
	}
}

static void
hixie76_encode(int in, int out)
{
	unsigned char inbuf[MAXOFRAME / 4 * 3];
	char outbuf[MAXOFRAME + 2];
	ssize_t len, wlen;

	for (;;) {
		len = read(in, inbuf, sizeof inbuf);
		if (len == -1) {
			perror("read");
			die(1);
		} else if (len == 0)
			die(0);

		/* Frame header. */
		outbuf[0] = 0x00;
		/* Encode data as Base64. */
		len = b64_ntop(inbuf, len, outbuf + 1, sizeof outbuf - 1);
		assert(len > 0 && len <= MAXOFRAME);
		/* Frame trailer. */
		outbuf[len + 1] = 0xff;

		wlen = write(out, outbuf, len + 2);
		if (wlen == -1) {
			perror("write");
			die(1);
		} else if (wlen != len + 2)
			die(0);
	}
}

static char *
do_strndup(const char *str, size_t n)
{
	size_t len;
	char *copy;

	for (len = 0; len < n && str[len]; len++)
		continue;

	if ((copy = malloc(len + 1)) == NULL)
		return (NULL);
	memcpy(copy, str, len);
	copy[len] = '\0';
	return (copy);
}

static char *
parsestring(const char *in)
{
	size_t len;

	len = strlen(in);
	if (len > 0 && in[len - 1] == '\n')
		len--;
	if (len > 0 && in[len - 1] == '\r')
		len--;
	if (len == 0)
		return (NULL);
	return (do_strndup(in, len));
}

static uint32_t
parsehdrkey(const char *key)
{
	uint32_t sum = 0, spaces = 0;

	for (; *key != '\0'; key++) {
		if (*key >= '0' && *key <= '9')
			sum = sum * 10 + *key - '0';
		else if (*key == ' ')
			spaces++;
	}
	return (spaces == 0 ? 0 : sum / spaces);
}

static void
eat_flash_magic(void)
{
	static const char flash_magic[] = "<policy-file-request/>";
	size_t i;
	char ch;

	for (i = 0; i < sizeof flash_magic - 1; i++) {
		ch = pgetc(stdin);
		/* Not a Flash applet.  Roll back. */
		if (ch != flash_magic[i]) {
			ungetc(ch, stdin);
			while (i-- > 0)
				ungetc(flash_magic[i], stdin);
			return;
		}
	}

	printf("<cross-domain-policy>"
	    "<allow-access-from domain=\"*\" to-ports=\"*\"/>"
	    "</cross-domain-policy>\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	union {
		struct sockaddr sa;
		struct sockaddr_in sa_in;
		struct sockaddr_in6 sa_in6;
	} sa;
	char line[512], key3[8], *host = NULL,
	    *origin = NULL, *key = NULL, *protocol;
	unsigned long minport, maxport, port;
	uint32_t key1 = 0, key2 = 0;
	socklen_t salen;
	pid_t pid;
	int fd, monitoring = 0, s;

	/* Squelch stderr when it is a socket. */
	if (!isatty(STDERR_FILENO)) {
		fd = open("/dev/null", O_WRONLY);
		if (fd == -1) {
			perror("open");
			return (1);
		}
		if (fd != STDERR_FILENO) {
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
	}

	if (argc != 3)
		usage();
	minport = strtoul(argv[1], NULL, 10);
	maxport = strtoul(argv[2], NULL, 10);
	if (1 > minport || minport > maxport || maxport > 65535)
		usage();
	
	eat_flash_magic();

	/* GET / header. */
	if (fgets(line, sizeof line, stdin) == NULL) {
		perror("fgets");
		return (1);
	}
	if (strncmp(line, "GET /", 5) != 0) {
		DPRINTF("malformed HTTP header received");
		return (1);
	}
	if (strncmp(line, "GET /wsproxy-monitoring/ ", 25) == 0) {
		monitoring = 1;
		port = 0; /* Keep compiler happy. */
	} else if (minport == maxport) {
		/* Simply ignore URL and connect to a single host. */
		port = minport;
	} else {
		/* Multiplexing mode.  Use port number in URL. */
		port = strtoul(line + 5, NULL, 10);
		if (port < minport || port > maxport) {
			DPRINTF("port not allowed");
			return (1);
		}
	}
	
	/* Parse HTTP headers. */
	do {
		if (fgets(line, sizeof line, stdin) == NULL) {
			DPRINTF("partial HTTP header received");
			return (1);
		}
		if (strncasecmp(line, "Host: ", 6) == 0) {
			host = parsestring(line + 6);
		} else if (strncasecmp(line, "Origin: ", 8) == 0) {
			origin = parsestring(line + 8);
		} else if (strncasecmp(line, "Sec-WebSocket-Key: ", 19) == 0) {
			hybi10 = 1;
			key = parsestring(line + 19);
		} else if (strncasecmp(line, "Sec-WebSocket-Key1: ", 20) == 0) {
			key1 = parsehdrkey(line + 20);
		} else if (strncasecmp(line, "Sec-WebSocket-Key2: ", 20) == 0) {
			key2 = parsehdrkey(line + 20);
		} else if (strncasecmp(line, "Sec-WebSocket-Protocol: ",
		    24) == 0) {
			protocol = parsestring(line + 24);
			if (strcmp(protocol, "base64") != 0) {
				DPRINTF("Unsupported protocol: %s", protocol);
				return (1);
			}
		}
	} while (strcmp(line, "\n") != 0 && strcmp(line, "\r\n") != 0);

	/* Simple monitoring. */
	if (monitoring) {
		printf("HTTP/1.1 200 OK\r\n"
		    "Content-Type: text/plain\r\n"
		    "\r\n"
		    "RUNNING\n");
		return (0);
	}

	/* Eight byte payload. */
	if (!hybi10)
		if (fread(key3, sizeof key3, 1, stdin) != 1) {
			DPRINTF("key data missing");
			return (1);
		}

	/* Use our own address. Fall back to 127.0.0.1 on failure. */
	salen = sizeof sa;
	if (getsockname(STDIN_FILENO, &sa.sa, &salen) == -1) {
		salen = sizeof sa.sa_in;
		memset(&sa.sa_in, 0, salen);
		sa.sa_in.sin_family = AF_INET;
		sa.sa_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	}
	switch (sa.sa.sa_family) {
	case AF_INET:
		sa.sa_in.sin_port = htons(port);
		break;
	case AF_INET6:
		sa.sa_in6.sin6_port = htons(port);
		break;
	default:
		/* Unknown protocol. */
		DPRINTF("unsupported network protocol");
		return (1);
	}
	s = socket(sa.sa.sa_family, SOCK_STREAM, 0);
	if (s == -1) {
		perror("socket");
		return (1);
	}
	if (connect(s, &sa.sa, salen) == -1) {
		perror("connect");
		return (1);
	}

	/* Send HTTP response, based on protocol version. */
	if (hybi10) {
		char accepthdr[HYBI10_ACCEPTHDRLEN];

		hybi10_calcaccepthdr(key, accepthdr);
		printf("HTTP/1.1 101 Switching Protocols\r\n"
		    "Upgrade: websocket\r\n"
		    "Connection: Upgrade\r\n"
		    "Sec-WebSocket-Accept: %s\r\n"
		    "Sec-WebSocket-Protocol: base64\r\n\r\n", accepthdr);
	} else {
		char response[MD5_DIGEST_LENGTH];

		hixie76_calcresponse(key1, key2, key3, response);
		printf("HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
		    "Upgrade: WebSocket\r\n"
		    "Connection: Upgrade\r\n"
		    "Sec-WebSocket-Origin: %s\r\n"
		    "Sec-WebSocket-Location: ws://%s/%lu\r\n"
		    "Sec-WebSocket-Protocol: base64\r\n\r\n",
		    origin, host, port);
		fwrite(response, sizeof response, 1, stdout);
	}
	fflush(stdout);

	/* Spawn child process for bi-directional pipe. */
	pid = fork();
	if (pid == -1) {
		perror("fork");
		return (1);
	} else if (pid == 0) {
		other = getppid();
		if (hybi10)
			hybi10_decode(stdin, s);
		else
			hixie76_decode(stdin, s);
	} else {
		other = pid;
		if (hybi10)
			hybi10_encode(s, STDOUT_FILENO);
		else
			hixie76_encode(s, STDOUT_FILENO);
	}
	assert(0);
}
