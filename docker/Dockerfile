FROM python

COPY websockify-*.tar.gz /

RUN python3 -m pip install websockify-*.tar.gz
RUN rm -rf /websockify-* /root/.cache

# Install Tailscale
RUN apt-get update && \
    apt-get install -y curl ca-certificates && \
    curl -fsSL https://tailscale.com/install.sh | sh && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

VOLUME /data

EXPOSE 80
EXPOSE 443

WORKDIR /opt/websockify

ENTRYPOINT ["/usr/local/bin/websockify"]
CMD ["--help"]
