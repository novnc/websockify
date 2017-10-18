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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
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
               "[source_addr:]source_port target_addr{:target_port}\n\n" \
               "  --verbose|-v         verbose messages and per frame traffic\n" \
               "  --daemon|-D          become a daemon (background process)\n" \
               "  --cert CERT          SSL certificate file\n" \
               "  --key KEY            SSL key file (if separate from cert)\n" \
               "  --ssl-only           disallow non-encrypted connections\n" \
               "  --whitelist|-w LIST  new-line separated target port whitelist file\n" \
               "                       (target_port is not required only with this option)\n" \
               "  --pattern|-P         target port request pattern. Default: '/%d'\n" \
               "  --pid|-p             desired path of pid file. Default: '/var/run/websockify.pid'";

#define usage(fmt, args...) \
    do { \
        fprintf(stderr, "%s\n\n", USAGE); \
        fprintf(stderr, fmt , ## args); \
        exit(1); \
    } while(0)

char target_host[256];
int target_port;
int *target_ports;

extern pipe_error;
extern settings_t settings;

void do_proxy(ws_ctx_t *ws_ctx, int target) {
    fd_set rlist, wlist, elist;
    struct timeval tv;
    int i, maxfd, client = ws_ctx->sockfd;
    unsigned int opcode, left, ret;
    unsigned int tout_start, tout_end, cout_start, cout_end;
    unsigned int tin_start, tin_end;
    ssize_t len, bytes;

    tout_start = tout_end = cout_start = cout_end;
    tin_start = tin_end = 0;
    maxfd = client > target ? client+1 : target+1;

    while (1) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&rlist);
        FD_ZERO(&wlist);
        FD_ZERO(&elist);

        FD_SET(client, &elist);
        FD_SET(target, &elist);

        if (tout_end == tout_start) {
            // Nothing queued for target, so read from client
            FD_SET(client, &rlist);
        } else {
            // Data queued for target, so write to it
            FD_SET(target, &wlist);
        }
        if (cout_end == cout_start) {
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
            len = tout_end-tout_start;
            bytes = send(target, ws_ctx->tout_buf + tout_start, len, 0);
            if (pipe_error) { break; }
            if (bytes < 0) {
                handler_emsg("target connection error: %s\n",
                             strerror(errno));
                break;
            }
            tout_start += bytes;
            if (tout_start >= tout_end) {
                tout_start = tout_end = 0;
                traffic(">");
            } else {
                traffic(">.");
            }
        }

        if (FD_ISSET(client, &wlist)) {
            len = cout_end-cout_start;
            bytes = ws_send(ws_ctx, ws_ctx->cout_buf + cout_start, len);
            if (pipe_error) { break; }
            if (len < 3) {
                handler_emsg("len: %d, bytes: %d: %d\n",
                             (int) len, (int) bytes,
                             (int) *(ws_ctx->cout_buf + cout_start));
            }
            cout_start += bytes;
            if (cout_start >= cout_end) {
                cout_start = cout_end = 0;
                traffic("<");
            } else {
                traffic("<.");
            }
        }

        if (FD_ISSET(target, &rlist)) {
            bytes = recv(target, ws_ctx->cin_buf, DBUFSIZE , 0);
            if (pipe_error) { break; }
            if (bytes <= 0) {
                handler_emsg("target closed connection\n");
                break;
            }
            cout_start = 0;
            if (ws_ctx->hybi) {
                cout_end = encode_hybi(ws_ctx->cin_buf, bytes,
                                   ws_ctx->cout_buf, BUFSIZE, ws_ctx->opcode);
            } else {
                cout_end = encode_hixie(ws_ctx->cin_buf, bytes,
                                    ws_ctx->cout_buf, BUFSIZE);
            }
            /*
            printf("encoded: ");
            for (i=0; i< cout_end; i++) {
                printf("%u,", (unsigned char) *(ws_ctx->cout_buf+i));
            }
            printf("\n");
            */
            if (cout_end < 0) {
                handler_emsg("encoding error\n");
                break;
            }
            traffic("{");
        }

        if (FD_ISSET(client, &rlist)) {
            bytes = ws_recv(ws_ctx, ws_ctx->tin_buf + tin_end, BUFSIZE-1);
            if (pipe_error) { break; }
            if (bytes <= 0) {
                handler_emsg("client closed connection\n");
                break;
            }
            tin_end += bytes;
            /*
            printf("before decode: ");
            for (i=0; i< bytes; i++) {
                printf("%u,", (unsigned char) *(ws_ctx->tin_buf+i));
            }
            printf("\n");
            */
            if (ws_ctx->hybi) {
                len = decode_hybi(ws_ctx->tin_buf + tin_start,
                                  tin_end-tin_start,
                                  ws_ctx->tout_buf, BUFSIZE-1,
                                  &opcode, &left);
            } else {
                len = decode_hixie(ws_ctx->tin_buf + tin_start,
                                   tin_end-tin_start,
                                   ws_ctx->tout_buf, BUFSIZE-1,
                                   &opcode, &left);
            }

            if (opcode == 8) {
                handler_msg("client sent orderly close frame\n");
                break;
            }

            /*
            printf("decoded: ");
            for (i=0; i< len; i++) {
                printf("%u,", (unsigned char) *(ws_ctx->tout_buf+i));
            }
            printf("\n");
            */
            if (len < 0) {
                handler_emsg("decoding error\n");
                break;
            }
            if (left) {
                tin_start = tin_end - left;
                //printf("partial frame from client");
            } else {
                tin_start = 0;
                tin_end = 0;
            }

            traffic("}");
            tout_start = 0;
            tout_end = len;
        }
    }
}

void proxy_handler(ws_ctx_t *ws_ctx) {
    int tsock = 0;
    struct sockaddr_in taddr;

    if (target_ports != NULL) {
        if (sscanf(ws_ctx->headers->path, settings.pattern, &target_port) != 1) {
        handler_emsg("Could not match pattern '%s' to request path '%s'\n",
                     settings.pattern, ws_ctx->headers->path);
        return;
        }
        int *p;
        int found = 0;
        for (p = target_ports; *p; p++) {
            if (*p == target_port) {
                found = 1;
                break;
            }
        }
        if (!found) {
            handler_emsg("Rejecting connection to non-whitelisted port: '%d'\n",
                         target_port);
            return;
        }
    }

    handler_msg("connecting to: %s:%d\n", target_host, target_port);

    tsock = socket(AF_INET, SOCK_STREAM, 0);
    if (tsock < 0) {
        handler_emsg("Could not create target socket: %s\n",
                     strerror(errno));
        return;
    }
    bzero((char *) &taddr, sizeof(taddr));
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
        close(tsock);
        return;
    }

    if ((settings.verbose) && (! settings.daemon)) {
        printf("%s", traffic_legend);
    }

    do_proxy(ws_ctx, tsock);

    shutdown(tsock, SHUT_RDWR);
    close(tsock);
}

int load_whitelist() {
  printf("loading port whitelist '%s'\n", settings.whitelist);
  FILE *whitelist = fopen(settings.whitelist, "r");
  if (whitelist == NULL) {
    fprintf(stderr, "Error opening whitelist file '%s':\n\t%s\n",
          settings.whitelist, strerror(errno));
    return -1;
  }

  const int tplen_grow = 512;
  int tplen = tplen_grow, tpcount = 0;
  target_ports = (int*)malloc(tplen*sizeof(int));
  if (target_ports == NULL) {
    fprintf(stderr, "Whitelist port malloc error");
    return -2;
  }

  char *line = NULL;
  ssize_t n = 0, nread = 0;
  while ((nread = getline(&line, &n, whitelist)) > 0) {
      if (line[0] == '\n') continue;
      line[nread-1] = '\x00';
      long int port = strtol(line, NULL, 10);
      if (port < 1 || port > 65535) {
          fprintf(stderr,
            "Whitelist port '%s' is not between valid range 1 and 65535", line);
          return -3;
      }
      tpcount++;
      if (tpcount >= tplen) {
          tplen += tplen_grow;
          target_ports = (int*)realloc(target_ports, tplen*sizeof(int));
          if (target_ports == NULL) {
              fprintf(stderr, "Whitelist port realloc error");
              return -2;
          }
      }
      target_ports[tpcount-1] = port;
  }
  if (line != NULL) free(line);

  if (tpcount == 0) {
      fprintf(stderr, "0 ports read from whitelist file '%s'\n",
                      settings.whitelist);
      return -4;
  }

  target_ports = (int*)realloc(target_ports, (tpcount + 1)*sizeof(int));
  if (target_ports == NULL) {
      fprintf(stderr, "Whitelist port realloc error");
      return -2;
  }
  target_ports[tpcount] = 0;
  return 0;
}

int main(int argc, char *argv[])
{
    int fd, c, option_index = 0;
    char *found;
    static struct option long_options[] = {
        {"verbose",   no_argument,       0,                 'v'},
        {"ssl-only",  no_argument,       &settings.ssl_only, 1 },
        {"daemon",    no_argument,       0,                 'D'},
        /* ---- */
        {"run-once",  no_argument,       0,                 'r'},
        {"cert",      required_argument, 0,                 'c'},
        {"key",       required_argument, 0,                 'k'},
        {"whitelist", required_argument, 0,                 'w'},
        {"pattern",   required_argument, 0,                 'P'},
        {"pid",       required_argument, 0,                 'p'},
        {0, 0, 0, 0}
    };

    settings.cert = realpath("self.pem", NULL);
    if (!settings.cert) {
        /* Make sure it's always set to something */
        settings.cert = "self.pem";
    }
    settings.key = "";
    settings.pattern = "/%d";
    settings.pid = "/var/run/websockify.pid";

    while (1) {
        c = getopt_long (argc, argv, "vDrc:k:w:p:P:",
                         long_options, &option_index);

        /* Detect the end */
        if (c == -1) break;

        switch (c) {
            case 0:
                break; // ignore
            case 1:
                break; // ignore
            case 'v':
                settings.verbose = 1;
                break;
            case 'D':
                settings.daemon = 1;
                break;
            case 'r':
                settings.run_once = 1;
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
            case 'w':
                settings.whitelist = realpath(optarg, NULL);
                if (! settings.whitelist) {
                    usage("No whitelist file at %s\n", optarg);
                }
                break;
            case 'P':
                settings.pattern = optarg;
                break;
            case 'p':
                settings.pid = optarg;
                break;
            default:
                usage(" ");
        }
    }

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
    if (found && settings.whitelist == NULL) {
        memcpy(target_host, argv[optind], found-argv[optind]);
        target_port = strtol(found+1, NULL, 10);
        target_ports = NULL;
    } else if (!found && settings.whitelist != NULL) {
        if (load_whitelist()) {
          usage("Whitelist error.");
        }
        memcpy(target_host, argv[optind], strlen(argv[optind]));
        target_port = -1;

    } else {
        usage("Target argument must be host:port or provide host and a port whitelist\n");
    }
    if (target_port == 0) {
        usage("Could not parse target port\n");
    }

    if (settings.ssl_only) {
        if (access(settings.cert, R_OK) != 0) {
            usage("SSL only and cert file '%s' not found\n", settings.cert);
        }
    } else if (access(settings.cert, R_OK) != 0) {
        fprintf(stderr, "Warning: '%s' not found\n", settings.cert);
    }

    //printf("  verbose: %d\n",   settings.verbose);
    //printf("  ssl_only: %d\n",  settings.ssl_only);
    //printf("  daemon: %d\n",    settings.daemon);
    //printf("  run_once: %d\n",  settings.run_once);
    //printf("  cert: %s\n",      settings.cert);
    //printf("  key: %s\n",       settings.key);

    settings.handler = proxy_handler;
    start_server();

}
