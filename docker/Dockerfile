FROM python:3-slim AS builder

WORKDIR /build/websockify

COPY ./* /build/websockify

RUN pip3 install setuptools && \
    python3 setup.py sdist --dist-dir docker/

# Actual final image
FROM python:3-slim
COPY --from=builder /build/websockify/websockify-*.tar.gz /
RUN python3 -m pip install websockify-*.tar.gz && \
  rm -rf /websockify-* /root/.cache

VOLUME /data

EXPOSE 80
EXPOSE 443

WORKDIR /opt/websockify

ENTRYPOINT ["/usr/local/bin/websockify"]
CMD ["--help"]
