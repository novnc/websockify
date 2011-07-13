/*
 * WebSocket lib with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h> 
#ifdef _WIN32
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <osisock.h>
//#include <base64-decode.h>
//#define b64_ntop(in, ilen, out, osize) lws_b64_encode_string(in, ilen, out, osize)
//#define b64_pton(in, out, osize) lws_b64_decode_string(in, out, osize)
#define snprintf sprintf_s 
#else
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>      /* base64 encode/decode */
#endif
#include <signal.h> // daemonizing
#include <fcntl.h>  // daemonizing
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "md5.h"
#include "websocket.h"

const char server_handshake_hixie[] = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
Upgrade: WebSocket\r\n\
Connection: Upgrade\r\n\
%sWebSocket-Origin: %.*s\r\n\
%sWebSocket-Location: %s://%.*s%.*s\r\n\
%sWebSocket-Protocol: base64\r\n\
\r\n%s";

const char server_handshake_hybi[] = "HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\
Sec-WebSocket-Protocol: %.*s\r\n\
\r\n\
";

const char policy_response[] = "<cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\" /></cross-domain-policy>\n";

/*
 * Get the path from the handhake header.
 */
static int get_path(const char *handshake, const char* *value, size_t *len) {
	const char *start, *end;

    if ((strlen(handshake) < 92) || (memcmp(handshake, "GET ", 4) != 0)) {
        return 0;
    }

    start = handshake+4;
    end = strstr(start, " HTTP/1.1");
    if (!end) { return 0; }

	*value = start;
	*len = end - start;

	return *len;
}

/*
 * Gets a header field from an HTTP header.
 * Returns non-zero if successful, 0 if the header does not contain
 * the specified field.
 */

static int get_header_field(const char *handshake, const char *name, const char* *value, size_t *len) {
	char key[64];
	const char *p, *q;
	size_t lk;

	lk = sprintf_s(key, sizeof(key), "\r\n%s: ", name );
	p = strstr(handshake, key);
	if (p) {
		*value = p + lk;
		q = strstr(*value, "\r\n");
		if (!q) return 0;
		return (*len = (q - *value));
	}
	else return 0;
}

static const char * skip_header(const char *handshake) {
	const char *p;
	p = strstr(handshake, "\r\n\r\n");
	if (!p) return 0;
	return p + 4;
}

/*
 * Global state
 *
 *   Warning: not thread safe
 */
int ssl_initialized = 0;
int pipe_error = 0;
char *tbuf, *cbuf, *tbuf_tmp, *cbuf_tmp;
unsigned int bufsize, dbufsize;
settings_t settings;

void traffic(char * token) {
    if ((settings.verbose) && (! settings.daemon)) {
        fprintf(stdout, "%s", token);
        fflush(stdout);
    }
}

void error(char *msg)
{
    perror(msg);
}

void fatal(char *msg)
{
    perror(msg);
    exit(1);
}

/* resolve host with also IP address parsing */ 
int resolve_host(struct in_addr *sin_addr, const char *hostname) 
{ 
    if (!inet_pton(AF_INET, hostname, sin_addr)) { 
        struct addrinfo *ai, *cur; 
        struct addrinfo hints; 
        memset(&hints, 0, sizeof(hints)); 
        hints.ai_family = AF_INET; 
        if (getaddrinfo(hostname, NULL, &hints, &ai)) 
            return -1; 
        for (cur = ai; cur; cur = cur->ai_next) { 
            if (cur->ai_family == AF_INET) { 
                *sin_addr = ((struct sockaddr_in *)cur->ai_addr)->sin_addr; 
                freeaddrinfo(ai); 
                return 0; 
            } 
        } 
        freeaddrinfo(ai); 
        return -1; 
    } 
    return 0; 
} 


/*
 * SSL Wrapper Code
 */

ssize_t ws_recv(ws_ctx_t *ctx, void *buf, size_t len) {
    if (ctx->ssl) {
        //handler_msg("SSL recv\n");
        return SSL_read(ctx->ssl, buf, len);
    } else {
        return recv(ctx->sockfd, buf, len, 0);
    }
}

ssize_t ws_send(ws_ctx_t *ctx, const void *buf, size_t len) {
    if (ctx->ssl) {
        //handler_msg("SSL send\n");
        return SSL_write(ctx->ssl, buf, len);
    } else {
        return send(ctx->sockfd, buf, len, 0);
    }
}

ws_ctx_t *ws_socket(int socket) {
    ws_ctx_t *ctx;
    ctx = malloc(sizeof(ws_ctx_t));
    ctx->sockfd = socket;
    ctx->ssl = NULL;
    ctx->ssl_ctx = NULL;
    return ctx;
}

ws_ctx_t *ws_socket_ssl(int socket, char * certfile, char * keyfile) {
    int ret;
    char msg[1024];
    char * use_keyfile;
    ws_ctx_t *ctx;
    ctx = ws_socket(socket);

    if (keyfile && (keyfile[0] != '\0')) {
        // Separate key file
        use_keyfile = keyfile;
    } else {
        // Combined key and cert file
        use_keyfile = certfile;
    }

    // Initialize the library
    if (! ssl_initialized) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ssl_initialized = 1;

    }

    ctx->ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    if (ctx->ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        fatal("Failed to configure SSL context");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, use_keyfile,
                                    SSL_FILETYPE_PEM) <= 0) {
        sprintf(msg, "Unable to load private key file %s\n", use_keyfile);
        fatal(msg);
    }

    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, certfile,
                                     SSL_FILETYPE_PEM) <= 0) {
        sprintf(msg, "Unable to load certificate file %s\n", certfile);
        fatal(msg);
    }

//    if (SSL_CTX_set_cipher_list(ctx->ssl_ctx, "DEFAULT") != 1) {
//        sprintf(msg, "Unable to set cipher\n");
//        fatal(msg);
//    }

    // Associate socket and ssl object
    ctx->ssl = SSL_new(ctx->ssl_ctx);
    SSL_set_fd(ctx->ssl, socket);

    ret = SSL_accept(ctx->ssl);
    if (ret < 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

void ws_socket_free(ws_ctx_t *ctx) {
    if (ctx->ssl) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
    if (ctx->sockfd) {
        shutdown(ctx->sockfd, SHUT_RDWR);
        close(ctx->sockfd);
        ctx->sockfd = 0;
    }
    free(ctx);
}

/* ------------------------------------------------------- */


int encode(u_char const *src, size_t srclength, char *target, size_t targsize) {
    int sz = 0, len = 0;
    target[sz++] = '\x00';
    len = b64_ntop(src, srclength, target+sz, targsize-sz);
    if (len < 0) {
        return len;
    }
    sz += len;
    target[sz++] = '\xff';
    return sz;
}

int decode(char *src, size_t srclength, u_char *target, size_t targsize) {
    char *start, *end, cntstr[4];
    int len, framecount = 0, retlen = 0;
    if ((src[0] != '\x00') || (src[srclength-1] != '\xff')) {
        handler_emsg("WebSocket framing error\n");
        return -1;
    }
    start = src+1; // Skip '\x00' start
    do {
        /* We may have more than one frame */
        end = memchr(start, '\xff', srclength);
        *end = '\x00';
        len = b64_pton(start, target+retlen, targsize-retlen);
        if (len < 0) {
            return len;
        }
        retlen += len;
        start = end + 2; // Skip '\xff' end and '\x00' start 
        framecount++;
    } while (end < (src+srclength-1));
    if (framecount > 1) {
        snprintf(cntstr, 3, "%d", framecount);
        traffic(cntstr);
    }
    return retlen;
}

int gen_md5(const char *handshake, char *target) {
    unsigned int i, spaces1 = 0, spaces2 = 0;
    unsigned long num1 = 0, num2 = 0;
    unsigned char buf[17];
	const char *value;
	size_t len;

	if (!get_header_field(handshake, "Sec-WebSocket-Key1", &value, &len)) return 0;

    for (i=0; i < len; i++) {
        if (value[i] == ' ') {
            spaces1 += 1;
        }
        if ((value[i] >= 48) && (value[i] <= 57)) {
            num1 = num1 * 10 + (value[i] - 48);
        }
    }
    num1 = num1 / spaces1;

	if (!get_header_field(handshake, "Sec-WebSocket-Key2", &value, &len)) return 0;
    for (i=0; i < len; i++) {
        if (value[i] == ' ') {
            spaces2 += 1;
        }
        if ((value[i] >= 48) && (value[i] <= 57)) {
            num2 = num2 * 10 + (value[i] - 48);
        }
    }
    num2 = num2 / spaces2;

    /* Pack it big-endian */
    buf[0] = (num1 & 0xff000000) >> 24;
    buf[1] = (num1 & 0xff0000) >> 16;
    buf[2] = (num1 & 0xff00) >> 8;
    buf[3] =  num1 & 0xff;

    buf[4] = (num2 & 0xff000000) >> 24;
    buf[5] = (num2 & 0xff0000) >> 16;
    buf[6] = (num2 & 0xff00) >> 8;
    buf[7] =  num2 & 0xff;

	if (!(value = skip_header(handshake))) return 0;
	strncpy(buf+8, value, 8);
    buf[16] = '\0';

    md5_buffer(buf, 16, target);
    target[16] = '\0';

    return 1;
}

    

ws_ctx_t *do_handshake(int sock) {
    char handshake[4096], response[4096], trailer[17], keynguid[1024+36+1], hash[20+1], accept[30+1];
    char *scheme, *pre, *protocol;
    int len;
    ws_ctx_t * ws_ctx;
	const char *value;
	size_t vlen;
	size_t rlen;

    // Peek, but don't read the data
    len = recv(sock, handshake, 1024, MSG_PEEK);
    handshake[len] = 0;
	printf("Handshake:\n%s\n", handshake);
    if (len == 0) {
        handler_msg("ignoring empty handshake\n");
        return NULL;
    } else if (memcmp(handshake, "<policy-file-request/>", 22) == 0) {
        len = recv(sock, handshake, 1024, 0);
        handshake[len] = 0;
        handler_msg("sending flash policy response\n");
        send(sock, policy_response, sizeof(policy_response), 0);
        return NULL;
    } else if (handshake[0] == '\x16' || handshake[0] == '\x80') {
        // SSL
        if (!settings.cert) {
            handler_msg("SSL connection but no cert specified\n");
            return NULL;
        } else if (access(settings.cert, R_OK) != 0) {
            handler_msg("SSL connection but '%s' not found\n",
                        settings.cert);
            return NULL;
        }
        ws_ctx = ws_socket_ssl(sock, settings.cert, settings.key);
        if (! ws_ctx) { return NULL; }
        scheme = "wss";
        handler_msg("using SSL socket\n");
    } else if (settings.ssl_only) {
        handler_msg("non-SSL connection disallowed\n");
        return NULL;
    } else {
        ws_ctx = ws_socket(sock);
        if (! ws_ctx) { return NULL; }
        scheme = "ws";
        handler_msg("using plain (not SSL) socket\n");
    }
    len = ws_recv(ws_ctx, handshake, 4096);
    if (len == 0) {
        handler_emsg("Client closed during handshake\n");
        return NULL;
    }
    handshake[len] = 0;

	// HyBi/IETF version of the protocol ?
	if (get_header_field(handshake, "Sec-WebSocket-Version", &value, &vlen)) {
		int ver;
		const char *key, *protocol;
		size_t kl, el, pl;
		ver = atoi(value);
		if (!get_header_field(handshake, "Sec-WebSocket-Protocol", &protocol, &pl)) return 0;
		ws_ctx->protocol = strncmp(protocol, "base64", pl) == 0 ? base64 : binary;
		if (!get_header_field(handshake, "Sec-WebSocket-Key", &key, &kl)) return 0;
		strncpy_s(keynguid, sizeof(keynguid), key, kl);
		strcat_s(keynguid, sizeof(keynguid), "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		SHA1((const unsigned char*)keynguid, strlen(keynguid), hash);
		b64_ntop(hash, 20, accept, sizeof(accept));
		rlen = sprintf(response, server_handshake_hybi, accept, pl, protocol);
	}
	else // Hixie version of the protocol (75 or 76)
	{
		const char *key3, *orig, *host, *path;
		size_t kl, ol, hl, pl;
		key3 = skip_header(handshake);
		if (key3 && *key3) {
			gen_md5(handshake, trailer);
			pre = "Sec-";
			handler_msg("using protocol version 76\n");
		} else {
			trailer[0] = '\0';
			pre = "";
			handler_msg("using protocol version 75\n");
		}
		ws_ctx->protocol = base64; 
		if (!get_header_field(handshake, "Origin", &orig, &ol)) return NULL;
		if (!get_header_field(handshake, "Host", &host, &hl)) return NULL;
		if (!get_path(handshake, &path, &pl)) return NULL;
		rlen = sprintf(response, server_handshake_hixie, pre, ol, orig, pre, scheme,
			hl, host, pl, path, pre, trailer);
	}
	printf("\nResponse:\n%s\n--------------------------\n", response);
    
    //handler_msg("response: %s\n", response);
    ws_send(ws_ctx, response, rlen);

    return ws_ctx;
}

void signal_handler(sig) {
    switch (sig) {
		// TODO: Windows equivalents ?
        //case SIGHUP: break; // ignore for now			
        //case SIGPIPE: pipe_error = 1; break; // handle inline
		//---
        case SIGTERM: exit(0); break;
    }
}

#ifndef _WIN32

void daemonize(int keepfd) {
    int pid, i;

    umask(0);
    chdir("/");
    setgid(getgid());
    setuid(getuid());

    /* Double fork to daemonize */
    pid = fork();
    if (pid<0) { fatal("fork error"); }
    if (pid>0) { exit(0); }  // parent exits
    setsid();                // Obtain new process group
    pid = fork();
    if (pid<0) { fatal("fork error"); }
    if (pid>0) { exit(0); }  // parent exits

    /* Signal handling */
    signal(SIGHUP, signal_handler);   // catch HUP
    signal(SIGTERM, signal_handler);  // catch kill

    /* Close open files */
    for (i=getdtablesize(); i>=0; --i) {
        if (i != keepfd) {
            close(i);
        } else if (settings.verbose) {
            printf("keeping fd %d\n", keepfd);
        }
    }
    i=open("/dev/null", O_RDWR);  // Redirect stdin
    dup(i);                       // Redirect stdout
    dup(i);                       // Redirect stderr
}

#endif // ! _WIN32

// TODO: move to websockify module ?

#ifdef _WIN32

static DWORD WINAPI proxy_thread( LPVOID lpParameter )
{
	int csock = (int) lpParameter;
    ws_ctx_t *ws_ctx;

    ws_ctx = do_handshake(csock);
    if (ws_ctx == NULL) {
        //handler_msg("No connection after handshake\n");
        return 0;
    }

    settings.handler(ws_ctx);
	// TODO: error handling
    //if (pipe_error) {
    //    handler_emsg("Closing due to SIGPIPE\n");
    //}

	return 0;
}

#endif

void start_server() {
    int lsock, csock, pid, clilen, sopt = 1;
    struct sockaddr_in serv_addr, cli_addr;
#ifdef _WIN32
	HANDLE hThread;
#else
    ws_ctx_t *ws_ctx;
#endif

    /* Initialize buffers */
    bufsize = 65536;
    if (! (tbuf = malloc(bufsize)) )
            { fatal("malloc()"); }
    if (! (cbuf = malloc(bufsize)) )
            { fatal("malloc()"); }
    if (! (tbuf_tmp = malloc(bufsize)) )
            { fatal("malloc()"); }
    if (! (cbuf_tmp = malloc(bufsize)) )
            { fatal("malloc()"); }

    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) { error("ERROR creating listener socket"); }
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(settings.listen_port);

    /* Resolve listen address */
    if (settings.listen_host && (settings.listen_host[0] != '\0')) {
        if (resolve_host(&serv_addr.sin_addr, settings.listen_host) < -1) {
            fatal("Could not resolve listen address");
        }
    } else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }

    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *)&sopt, sizeof(sopt));
    if (bind(lsock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		int err = WSAGetLastError();
        fatal("ERROR on binding listener socket");
    }
    listen(lsock,100);

#ifndef _WIN32
    signal(SIGPIPE, signal_handler);  // catch pipe
#endif

    if (settings.daemon) {
#ifndef _WIN32
        daemonize(lsock);
#endif
    }

#ifndef _WIN32
    // Reep zombies
    signal(SIGCHLD, SIG_IGN);
#endif

    printf("Waiting for connections on %s:%d\n",
            settings.listen_host, settings.listen_port);

    while (1) {
        clilen = sizeof(cli_addr);
        pipe_error = 0;
        pid = 0;
        csock = accept(lsock, 
                       (struct sockaddr *) &cli_addr, 
                       &clilen);
        if (csock < 0) {
            error("ERROR on accept");
            continue;
        }
        handler_msg("got client connection from %s\n",
                    inet_ntoa(cli_addr.sin_addr));
        /* base64 is 4 bytes for every 3
         *    20 for WS '\x00' / '\xff' and good measure  */
        dbufsize = (bufsize * 3)/4 - 20;

#ifdef _WIN32
		hThread = CreateThread(NULL, 0, proxy_thread, (LPVOID) csock, 0, NULL );
		if (hThread == NULL) {
			error("failed to create proxy thread");
			break;
		}
		settings.handler_id += 1;
#else
        handler_msg("forking handler process\n");
        pid = fork();

        if (pid == 0) {  // handler process
            ws_ctx = do_handshake(csock);
            if (ws_ctx == NULL) {
                handler_msg("No connection after handshake\n");
                break;   // Child process exits
            }

            settings.handler(ws_ctx);
            if (pipe_error) {
                handler_emsg("Closing due to SIGPIPE\n");
            }
            break;   // Child process exits
        } else {         // parent process
            settings.handler_id += 1;
        }
#endif
    }
#ifdef _WIN32
#else
    if (pid == 0) {
        if (ws_ctx) {
            ws_socket_free(ws_ctx);
        } else {
            shutdown(csock, SHUT_RDWR);
            close(csock);
        }
        handler_msg("handler exit\n");
    } else {
		// TODO: can this ever be reached ?
        handler_msg("wsproxy exit\n");
    }
#endif
}

