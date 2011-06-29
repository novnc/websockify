/*-
 * Copyright (c) 2011 Ed Schouten <ed@kumina.nl>
 * All rights reserved.
 *
 * Portions of this software were developed under sponsorship from Snow
 * B.V., the Netherlands.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/md5.h>

static pid_t other;

static void
die(int exitcode)
{

	kill(other, SIGTERM);
	exit(exitcode);
}

static void
usage(void)
{

	fprintf(stderr, "usage: wsproxy minport maxport\n");
	exit(1);
}

static int
pgetc(FILE *fp)
{
	int ret;

	ret = fgetc(fp);
	if (ret == EOF)
		die(0);
	return (ret);
}

#if 0 /* UTF-8 */

static void
pputc(FILE *fp, unsigned char ch)
{
	int ret;

	ret = fputc(ch, fp);
	if (ret == EOF)
		die(0);
}

static void
decode(FILE *in, int outfd)
{
	FILE *out;
	int ch;
	unsigned char och;

	out = fdopen(outfd, "w");
	if (out == NULL) {
		perror("fdopen");
		die(1);
	}

	for (;;) {
		/* Frame header. */
		ch = pgetc(in);
		if (ch != 0x00) {
			fprintf(stderr, "malformed frame header received\n");
			die(1);
		}

		for (;;) {
			/* Frame trailer. */
			ch = pgetc(in);
			if (ch == EOF)
				die(0);
			if (ch == 0xff) {
				fflush(out);
				break;
			}

			/* UTF-8 character, only allowing points 0 to 255. */
			if (ch < 0x80)
				och = ch;
			else if ((ch & 0xf3) == 0xc0) {
				och = ch << 6;
				ch = pgetc(in);
				if ((ch & 0xc0) != 0x80)
					goto malformed;
				och |= ch & 0x3f;
			} else
				goto malformed;
			pputc(out, och);
		}
	}

malformed:
	fprintf(stderr, "malformed UTF-8 sequence received\n");
	die(1);
}

static int
encode(int in, int out)
{
	unsigned char inbuf[512];
	unsigned char outbuf[sizeof inbuf * 2 + 2];
	unsigned char *op;
	ssize_t len, i;

	for (;;) {
		len = read(in, inbuf, sizeof inbuf);
		if (len == -1) {
			perror("read");
			die(1);
		} else if (len == 0)
			die(0);

		op = outbuf;
		/* Frame header. */
		*op++ = 0x00;
		for (i = 0; i < len; i++) {
			/* Encode data as UTF-8. */
			if (inbuf[i] < 0x80)
				*op++ = inbuf[i];
			else {
				*op++ = 0xc0 | (inbuf[i] >> 6);
				*op++ = 0x80 | (inbuf[i] & 0x3f);
			}
		}
		/* Frame trailer. */
		*op++ = 0xff;
		assert(op <= outbuf + sizeof outbuf);
		len = write(out, outbuf, op - outbuf);
		if (len == -1) {
			perror("write");
			die(1);
		} else if (len != op - outbuf)
			die(0);
	}
}

#else /* base64 */

static void
putb64(FILE *out, char *inb, size_t *inblen)
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
		fprintf(stderr, "invalid Base64 data\n");
		die(1);
	}
	if (fwrite(outbuf, outbuflen, 1, out) != 1) {
		perror("fwrite");
		die(1);
	}
	*inblen = 0;
}

static void
decode(FILE *in, int outfd)
{
	FILE *out;
	int ch;
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
			fprintf(stderr, "malformed frame header received\n");
			die(1);
		}

		for (;;) {
			ch = pgetc(in);
			if (ch == EOF) {
				putb64(out, inb, &inblen);
				die(0);
			}
			/* Frame trailer. */
			if (ch == 0xff) {
				putb64(out, inb, &inblen);
				if (fflush(out) == -1) {
					perror("fflush");
					die(1);
				}
				break;
			}

			if (!((ch >= 'A' && ch <= 'Z') ||
			    (ch >= 'a' && ch <= 'z') ||
			    (ch >= '0' && ch <= '9') ||
			    ch == '+' || ch == '/' || ch == '=')) {
				fprintf(stderr,
				    "non-Base64 character received\n");
				die(1);
			}

			/* Base64 character. */
			inb[inblen++] = ch;
			if (inblen == sizeof inb)
				putb64(out, inb, &inblen);
		}
	}
}

static int
encode(int in, int out)
{
	unsigned char inbuf[512];
	char outbuf[sizeof inbuf * 2 + 2];
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
		len = b64_ntop(inbuf, len, outbuf + 1, sizeof outbuf - 1) + 1;
		assert(len >= 1);
		/* Frame footer. */
		outbuf[len++] = 0xff;

		wlen = write(out, outbuf, len);
		if (wlen == -1) {
			perror("write");
			die(1);
		} else if (wlen != len)
			die(0);
	}
}

#endif

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
calcresponse(uint32_t key1, uint32_t key2, const char *key3, char *out)
{
	MD5_CTX c;
	char in[16];

	in[0] = key1 >> 24;
	in[1] = key1 >> 16;
	in[2] = key1 >> 8;
	in[3] = key1;
	in[4] = key2 >> 24;
	in[5] = key2 >> 16;
	in[6] = key2 >> 8;
	in[7] = key2;
	memcpy(in + 8, key3, 8);

	MD5_Init(&c);
	MD5_Update(&c, (void *)in, sizeof in);
	MD5_Final((void *)out, &c);
}

static void
eat_flash_magic(void)
{
	static const char flash_magic[] = "<policy-file-request/>";
	ssize_t i;
	int ch;

	for (i = 0; i < sizeof flash_magic - 1; i++) {
		ch = getchar();
		if (ch == EOF) {
			perror("getc");
			exit(1);
		}
		/* Not a Flash applet.  Roll back. */
		if (ch != flash_magic[i]) {
			ungetc(ch, stdin);
			while (--i >= 0)
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
	char line[512], key3[8], response[16], *host = NULL, *origin = NULL;
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
		fprintf(stderr, "malformed HTTP header received\n");
		return (1);
	}
	if (strncmp(line, "GET /wsproxy-monitoring/ ", 25) == 0)
		monitoring = 1;
	port = strtoul(line + 5, NULL, 10);
	if (!monitoring && (port < minport || port > maxport)) {
		fprintf(stderr, "port not allowed\n");
		return (1);
	}
	
	/* Parse HTTP headers. */
	do {
		if (fgets(line, sizeof line, stdin) == NULL) {
			fprintf(stderr, "partial HTTP header received\n");
			return (1);
		}
		if (strncasecmp(line, "Host: ", 6) == 0) {
			host = parsestring(line + 6);
		} else if (strncasecmp(line, "Origin: ", 8) == 0) {
			origin = parsestring(line + 8);
		} else if (strncasecmp(line, "Sec-WebSocket-Key1: ", 20) == 0) {
			key1 = parsehdrkey(line + 20);
		} else if (strncasecmp(line, "Sec-WebSocket-Key2: ", 20) == 0) {
			key2 = parsehdrkey(line + 20);
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
	if (fread(key3, sizeof key3, 1, stdin) != 1) {
		fprintf(stderr, "key data missing\n");
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
		fprintf(stderr, "unsupported network protocol\n");
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

	/* Send HTTP response. */
	calcresponse(key1, key2, key3, response);
	printf("HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
	    "Upgrade: WebSocket\r\n"
	    "Connection: Upgrade\r\n"
	    "Sec-WebSocket-Origin: %s\r\n"
	    "Sec-WebSocket-Location: ws://%s/%lu\r\n"
	    "Sec-WebSocket-Protocol: base64\r\n\r\n", origin, host, port);
	fwrite(response, sizeof response, 1, stdout);
	fflush(stdout);

	/* Spawn child process for bi-directional pipe. */
	pid = fork();
	if (pid == -1) {
		perror("fork");
		return (1);
	} else if (pid == 0) {
		other = getppid();
		decode(stdin, s);
	} else {
		other = pid;
		encode(s, STDOUT_FILENO);
	}
	assert(0);
}
