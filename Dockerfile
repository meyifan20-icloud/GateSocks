FROM python:3.12-slim

ARG DEBIAN_FRONTEND=noninteractive
ARG GATESOCKS_VERSION=0.1.0-dev

LABEL org.opencontainers.image.title="GateSocks" \
      org.opencontainers.image.description="SOCKS5 exit manager foundation image" \
      org.opencontainers.image.source="https://github.com/meyifan20-icloud/GateSocks" \
      org.opencontainers.image.version="${GATESOCKS_VERSION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       openvpn \
       iproute2 \
       iptables \
       curl \
       ca-certificates \
       iputils-ping \
       procps \
       tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app.py /app/app.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATESOCKS_BIND=127.0.0.1 \
    GATESOCKS_PORT=19080 \
    GATESOCKS_VERSION=${GATESOCKS_VERSION}

RUN mkdir -p /app/data /app/config /app/run

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["python","/app/app.py"]
