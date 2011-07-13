/*
 * A WebSocket to TCP socket proxy with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 */
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#ifdef WIN32
#include <Windows.h>
#include <realpath.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/select.h>
#include <fcntl.h>
#endif
#include <sys/stat.h>
#include "websocket.h"

char traffic_legend[] = "\n\
Traffic Legend:\n\
    }  - Client receive\n\
    }. - Client receive partial\n\
    {  - Target receive\n\
\n\
    >  - Target send\n\
    >. - Target send partial\n\
    <  - Client send\n\
    <. - Client send partial\n\
";

char USAGE[] = "Usage: [options] " \
               "[source_addr:]source_port target_addr:target_port\n\n" \
               "  --verbose|-v       verbose messages and per frame traffic\n" \
               "  --daemon|-D        become a daemon (background process)\n" \
               "  --cert CERT        SSL certificate file\n" \
               "  --key KEY          SSL key file (if separate from cert)\n" \
               "  --ssl-only         disallow non-encrypted connections";

#define usage(fmt, ...) \
    fprintf(stderr, "%s\n\n", USAGE); \
    fprintf(stderr, fmt , ## __VA_ARGS__); \
    exit(1);

char target_host[256];
int target_port;

extern int pipe_error;
extern settings_t settings;
extern char *tbuf, *cbuf, *tbuf_tmp, *cbuf_tmp;
extern unsigned int bufsize, dbufsize;

#ifdef _DEBUG

void dump_buffer( char *buffer, size_t size, const char *title )
{
	char line[4096];
	unsigned i;
	int ch;
	unsigned cu;
	assert( size < 4096 );
	for ( i = 0; i < size; i ++ ) {
		line[i] = buffer[i] >= 32 && buffer[i] <= 126 ? buffer[i] : ' ';
	}
	line[i] = 0;
	printf( "%s, %u bytes: \"%s\"", title, (unsigned) size, line );
	for ( i = 0; i < size; i ++ ) {
		if ( i % 8 == 0 ) printf("\n"); else printf("  ");
		ch = buffer[i];
		cu = (ch < 0 ? 65536 + ch : *((unsigned*)&ch)) & 0xff;
		ch =  ch >= 32 && ch <= 126 ? ch : ' ';
		printf( "'%c' ($%2.2x) (%3.3u)", ch, cu, cu );
	}
	if ( i % 8 != 0 ) printf("\n");
}

#else
#define dump_buffer( b, s, t )
#endif

void do_proxy(ws_ctx_t *ws_ctx, int target) {
    fd_set rlist, wlist, elist;
    struct timeval tv;
    int maxfd, client = ws_ctx->sockfd;
    unsigned int tstart, tend, cstart, cend, ret;
    ssize_t len, bytes;

    tstart = tend = cstart = cend = 0;
    maxfd = client > target ? client+1 : target+1;

    while (1) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&rlist);
        FD_ZERO(&wlist);
        FD_ZERO(&elist);

        FD_SET(client, &elist);
        FD_SET(target, &elist);

        if (tend == tstart) {
            // Nothing queued for target, so read from client
            FD_SET(client, &rlist);
        } else {
            // Data queued for target, so write to it
            FD_SET(target, &wlist);
        }
        if (cend == cstart) {
            // Nothing queued for client, so read from target
            FD_SET(target, &rlist);
        } else {
            // Data queued for client, so write to it
            FD_SET(client, &wlist);
        }

        ret = select(maxfd, &rlist, &wlist, &elist, &tv);
        if (pipe_error) { break; }

        if (FD_ISSET(target, &elist)) {
            handler_emsg("target exception\n");
            break;
        }
        if (FD_ISSET(client, &elist)) {
            handler_emsg("client exception\n");
            break;
        }

        if (ret == -1) {
            handler_emsg("select(): %s\n", strerror(errno));
            break;
        } else if (ret == 0) {
            //handler_emsg("select timeout\n");
            continue;
        }

        if (FD_ISSET(target, &wlist)) {
            len = tend-tstart;
			dump_buffer( tbuf+tstart, len, "Sending to target" );
            bytes = send(target, tbuf + tstart, len, 0);
            if (pipe_error) { break; }
            if (bytes < 0) {
                handler_emsg("target connection error: %s\n",
                             strerror(errno));
                break;
            }
            tstart += bytes;
            if (tstart >= tend) {
                tstart = tend = 0;
                traffic(">");
            } else {
                traffic(">.");
            }
        }

        if (FD_ISSET(client, &wlist)) {
            len = cend-cstart;
			dump_buffer( cbuf+cstart, len, "Sending to client" );
            bytes = ws_send(ws_ctx, cbuf + cstart, len);
            if (pipe_error) { break; }
            if (len < 3) {
                handler_emsg("len: %d, bytes: %d: %d\n", len, bytes, *(cbuf + cstart));
            }
            cstart += bytes;
            if (cstart >= cend) {
                cstart = cend = 0;
                traffic("<");
            } else {
                traffic("<.");
            }
        }

        if (FD_ISSET(target, &rlist)) {
            bytes = recv(target, cbuf_tmp, dbufsize , 0);
			dump_buffer( cbuf_tmp, bytes, "Received from target" );
            if (pipe_error) { break; }
            if (bytes <= 0) {
				if (bytes < 0) {
					handler_emsg("error receiving from target");
				}
				else
					handler_emsg("target closed connection\n");
                break;
            }
            cstart = 0;
            cend = encode(cbuf_tmp, bytes, cbuf, bufsize);
            /*
            printf("encoded: ");
            for (i=0; i< cend; i++) {
                printf("%u,", (unsigned char) *(cbuf+i));
            }
            printf("\n");
            */
            if (cend < 0) {
                handler_emsg("encoding error\n");
                break;
            }
            traffic("{");
        }

        if (FD_ISSET(client, &rlist)) {
            bytes = ws_recv(ws_ctx, tbuf_tmp, bufsize-1);
			dump_buffer( tbuf_tmp, bytes, "Received from client" );
            if (pipe_error) { break; }
            if (bytes <= 0) {
                handler_emsg("client closed connection\n");
                break;
            } else if ((bytes == 2) &&
                       (tbuf_tmp[0] == '\xff') && 
                       (tbuf_tmp[1] == '\x00')) {
                handler_emsg("client sent orderly close frame\n");
                break;
            }
            /*
            printf("before decode: ");
            for (i=0; i< bytes; i++) {
                printf("%u,", (unsigned char) *(tbuf_tmp+i));
            }
            printf("\n");
            */
            len = decode(tbuf_tmp, bytes, tbuf, bufsize-1);
			//if ( len == 1 && tbuf[0] == '\x0a' ) tbuf[0] = '\x0d';
            /*
            printf("decoded: ");
            for (i=0; i< len; i++) {
                printf("%u,", (unsigned char) *(tbuf+i));
            }
            printf("\n");
            */
            if (len < 0) {
                handler_emsg("decoding error\n");
                break;
            }
            traffic("}");
            tstart = 0;
            tend = len;
        }
    }
}

void proxy_handler(ws_ctx_t *ws_ctx) {
    int tsock = 0;
    struct sockaddr_in taddr;

    handler_msg("connecting to: %s:%d\n", target_host, target_port);

    tsock = socket(AF_INET, SOCK_STREAM, 0);
    if (tsock < 0) {
        handler_emsg("Could not create target socket: %s\n",
                     strerror(errno));
        return;
    }
    memset((char *) &taddr, 0, sizeof(taddr));
    taddr.sin_family = AF_INET;
    taddr.sin_port = htons(target_port);

    /* Resolve target address */
    if (resolve_host(&taddr.sin_addr, target_host) < -1) {
        handler_emsg("Could not resolve target address: %s\n",
                     strerror(errno));
    }

    if (connect(tsock, (struct sockaddr *) &taddr, sizeof(taddr)) < 0) {
        handler_emsg("Could not connect to target: %s\n",
                     strerror(errno));
        _close(tsock);
        return;
    }

    if ((settings.verbose) && (! settings.daemon)) {
        printf("%s", traffic_legend);
    }

    do_proxy(ws_ctx, tsock);

#ifdef _WIN32
	closesocket(tsock);
#else
    _close(tsock);
#endif
}

#ifdef _WIN32

static int initWinSocks()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

	return 0;
}

#endif // _WIN32

int main(int argc, char *argv[])
{
    int c, option_index = 0;
    static int ssl_only = 0, daemon = 0, verbose = 0;
    char *found;
    static struct option long_options[] = {
        {"verbose",    no_argument,       &verbose,    'v'},
        {"ssl-only",   no_argument,       &ssl_only,    1 },
        {"daemon",     no_argument,       &daemon,     'D'},
        /* ---- */
        {"cert",       required_argument, 0,           'c'},
        {"key",        required_argument, 0,           'k'},
        {0, 0, 0, 0}
    };

#ifdef _WIN32
	if ( initWinSocks() != 0 ) return 1;
#endif

	settings.cert = realpath("self.pem", NULL);
    if (!settings.cert) {
        /* Make sure it's always set to something */
        settings.cert = "self.pem";
    }
    settings.key = "";

    while (1) {
        c = getopt_long (argc, argv, "vDc:k:",
                         long_options, &option_index);

        /* Detect the end */
        if (c == -1) { break; }

        switch (c) {
            case 0:
                break; // ignore
            case 1:
                break; // ignore
            case 'v':
                verbose = 1;
                break;
            case 'D':
                daemon = 1;
                break;
            case 'c':
                settings.cert = realpath(optarg, NULL);
                if (! settings.cert) {
                    usage("No cert file at %s\n", optarg);
                }
                break;
            case 'k':
                settings.key = realpath(optarg, NULL);
                if (! settings.key) {
                    usage("No key file at %s\n", optarg);
                }
                break;
            default:
                usage("");
        }
    }
    settings.verbose      = verbose;
    settings.ssl_only     = ssl_only;
    settings.daemon       = daemon;

    if ((argc-optind) != 2) {
        usage("Invalid number of arguments\n");
    }

    found = strstr(argv[optind], ":");
    if (found) {
        memcpy(settings.listen_host, argv[optind], found-argv[optind]);
        settings.listen_port = strtol(found+1, NULL, 10);
    } else {
        settings.listen_host[0] = '\0';
        settings.listen_port = strtol(argv[optind], NULL, 10);
    }
    optind++;
    if (settings.listen_port == 0) {
        usage("Could not parse listen_port\n");
    }

    found = strstr(argv[optind], ":");
    if (found) {
        memcpy(target_host, argv[optind], found-argv[optind]);
        target_port = strtol(found+1, NULL, 10);
    } else {
        usage("Target argument must be host:port\n");
    }
    if (target_port == 0) {
        usage("Could not parse target port\n");
    }

    if (ssl_only) {
        if (!access(settings.cert, R_OK)) {
            usage("SSL only and cert file '%s' not found\n", settings.cert);
        }
    } else if (access(settings.cert, R_OK) != 0) {
        fprintf(stderr, "Warning: '%s' not found\n", settings.cert);
    }

    //printf("  verbose: %d\n",   settings.verbose);
    //printf("  ssl_only: %d\n",  settings.ssl_only);
    //printf("  daemon: %d\n",    settings.daemon);
    //printf("  cert: %s\n",      settings.cert);
    //printf("  key: %s\n",       settings.key);

    settings.handler = proxy_handler; 
    start_server();

    free(tbuf);
    free(cbuf);
    free(tbuf_tmp);
    free(cbuf_tmp);
}
