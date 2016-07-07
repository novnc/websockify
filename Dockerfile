# This provides a minimal websockify Docker image. The image is based on Alpine
# edge to be able to benefit from the numpy package that is currently in
# testing. This ought to change as soon as numpy has qualified out of testing.
FROM alpine:edge
MAINTAINER Emmanuel Frecon <efrecon@gmail.com>

RUN apk add --update-cache python && \
    apk add --update-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing/ --allow-untrusted py-numpy && \
    rm -rf /var/cache/apk/*

COPY run /opt/websockify/
COPY LICENSE.txt /opt/websockify/
COPY README.md /opt/websockify/
COPY websockify/ /opt/websockify/websockify/

# Copy the demo IRC and Telnet servers into /opt/websockify/web
COPY *.html /opt/websockify/web/
COPY include/ /opt/websockify/web/include/

# Expose two volumes to (possibly) host configuration files needed on the
# command line, e.g. keys and certificates for WSS access, files served for
# --web options, etc.
VOLUME /opt/websockify/data
VOLUME /opt/websockify/config

# Expose regular and encrypted standard web ports, you'll have to specify these
# in the command-line arguments.
EXPOSE 443
EXPOSE 80

ENTRYPOINT ["/websockify/run"]
