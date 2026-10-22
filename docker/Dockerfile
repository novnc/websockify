FROM python:3.13-slim-bookworm

COPY websockify-*.tar.gz /tmp/

RUN python3 -m pip install --no-cache-dir /tmp/websockify-*.tar.gz \
    && rm -rf /tmp/websockify-* /root/.cache \
    && useradd --system --uid 1000 --create-home --home-dir /opt/websockify websockify \
    && mkdir -p /data \
    && chown websockify:websockify /data /opt/websockify

VOLUME /data

EXPOSE 80
EXPOSE 443

WORKDIR /opt/websockify

USER websockify

ENTRYPOINT ["/usr/local/bin/websockify"]
CMD ["--help"]
