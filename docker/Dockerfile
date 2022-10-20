FROM python:3.6

ENV VERSION 0.10.0

RUN mkdir -p /opt/websockify \
    && curl -SL https://github.com/novnc/websockify/archive/refs/tags/v$VERSION.tar.gz \
    | tar xzC /opt/websockify

RUN python -m pip install 'numpy<1.17' redis simplejson jwcrypto requests

VOLUME /data

EXPOSE 80
EXPOSE 443

WORKDIR /opt/websockify

COPY docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["--help"]
