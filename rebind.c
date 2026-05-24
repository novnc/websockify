/*
 * rebind: Intercept bind calls and bind to a different port
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * Overload (LD_PRELOAD) bind system call. If REBIND_PORT_OLD and
 * REBIND_PORT_NEW environment variables are set then bind on the new
 * port (of localhost) instead of the old port. 
 *
 * This allows a bridge/proxy (such as websockify) to run on the old port and
 * translate traffic to/from the new port.
 *
 * Usage:
 *     LD_PRELOAD=./rebind.so \
 *     REBIND_PORT_OLD=23 \
 *     REBIND_PORT_NEW=2023 \
 *     program
 */

//#define DO_DEBUG 1

#include <stdio.h>
#include <stdlib.h>

#define __USE_GNU 1  // Pull in RTLD_NEXT
#include <dlfcn.h>

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>


#if defined(DO_DEBUG)
#define DEBUG(...) \
    fprintf(stderr, "rebind: "); \
    fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    static int (*func)(int, const struct sockaddr *, socklen_t);
    int do_move = 0;
    struct sockaddr_storage addr_tmp;
    socklen_t addrlen_tmp;
    char * PORT_OLD, * PORT_NEW, * end1, * end2;
    int ret, oldport = 0, newport = 0, askport = 0;
    char addr_str[INET6_ADDRSTRLEN] = "";
    int family = addr ? addr->sa_family : AF_UNSPEC;

    if (!func) {
        func = (int (*)(int, const struct sockaddr *, socklen_t)) dlsym(RTLD_NEXT, "bind");
    }

    if (family == AF_INET) {
        const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
        askport = ntohs(addr_in->sin_port);
        inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
    } else {
        const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)addr;
        askport = ntohs(addr_in6->sin6_port);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
    }

    DEBUG(">> bind(%d, family %d, len %d), askaddr %s, askport %d\n",
          sockfd, family, addrlen, addr_str, askport);

    /* Determine if we should move this socket */
    if (family == AF_INET || family == AF_INET6) {
        PORT_OLD = getenv("REBIND_OLD_PORT");
        PORT_NEW = getenv("REBIND_NEW_PORT");
        if (PORT_OLD && (*PORT_OLD != '\0') &&
            PORT_NEW && (*PORT_NEW != '\0')) {
            oldport = strtol(PORT_OLD, &end1, 10);
            newport = strtol(PORT_NEW, &end2, 10);
            if (oldport && (*end1 == '\0') &&
                newport && (*end2 == '\0') &&
                (oldport == askport)) {
                do_move = 1;
            }
        }
    }

    if (! do_move) {
        /* Just pass everything right through to the real bind */
        ret = func(sockfd, addr, addrlen);
        DEBUG("<< bind(%d, _, %d) ret %d\n", sockfd, addrlen, ret);
        return ret;
    }

    DEBUG("binding fd %d on localhost:%d instead of %s:%d\n",
        sockfd, newport, addr_str[0] ? addr_str : "<unknown>", oldport);

    /* Use a temporary location for the new address information */
    addrlen_tmp = addrlen;
    if (addrlen_tmp > sizeof(addr_tmp)) {
        addrlen_tmp = sizeof(addr_tmp);
    }
    memcpy(&addr_tmp, addr, addrlen_tmp);

    /* Bind to other port on the loopback instead */
    if (family == AF_INET) {
        struct sockaddr_in *addr_in_tmp = (struct sockaddr_in *)&addr_tmp;
        addr_in_tmp->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr_in_tmp->sin_port = htons(newport);
    } else {
        struct sockaddr_in6 *addr_in6_tmp = (struct sockaddr_in6 *)&addr_tmp;
        static const struct in6_addr v4_loopback_mapped = { // ::ffff:127.0.0.1
            .s6_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}
        };
        int v6_only = 0;
        (void)setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only));
        addr_in6_tmp->sin6_addr = v4_loopback_mapped;
        addr_in6_tmp->sin6_port = htons(newport);
        addr_in6_tmp->sin6_scope_id = 0;
    }
    ret = func(sockfd, (const struct sockaddr *)&addr_tmp, addrlen_tmp);

    DEBUG("<< bind(%d, _, %d) ret %d\n", sockfd, addrlen, ret);
    return ret;
}
