FROM alpine
MAINTAINER Emmanuel Frecon <efrecon@gmail.com>

RUN apk add --update-cache python py-numpy && \
    rm -rf /var/cache/apk/*

COPY run /opt/websockify/
COPY websockify/ /opt/websockify/websockify/

# Expose two volumes to (possibly) host configuration files needed on the
# command line, e.g. keys and certificates for WSS access, files served for
# --web options, etc.
VOLUME /opt/websockify/data
VOLUME /opt/websockify/config

# Expose regular and encrypted standard web ports, you'll have to specify these
# in the command-line arguments.
EXPOSE 443
EXPOSE 80

ENTRYPOINT ["/opt/websockify/run"]
