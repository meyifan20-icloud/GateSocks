FROM python:3.12-slim

ARG DEBIAN_FRONTEND=noninteractive
ARG GATESOCKS_VERSION=0.4.12-dev

LABEL org.opencontainers.image.title="GateSocks" \
      org.opencontainers.image.description="SOCKS5 exit manager and web panel" \
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
       util-linux \
       tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY socks_server.py /app/socks_server.py
COPY static /app/static
RUN python -m py_compile /app/app.py /app/socks_server.py \
    && openvpn --version | head -n 1 \
    && setpriv --version \
    && ip -Version \
    && curl --version | head -n 1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATESOCKS_BIND=0.0.0.0 \
    GATESOCKS_PORT=19080 \
    GATESOCKS_VERSION=${GATESOCKS_VERSION} \
    GATESOCKS_SOCKS_START=18001 \
    GATESOCKS_SOCKS_END=18099 \
    GATESOCKS_TEST_START=18100 \
    GATESOCKS_TEST_END=18149

RUN mkdir -p /app/data /app/config /app/run

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["sh","-c","uvicorn app:app --host ${GATESOCKS_BIND} --port ${GATESOCKS_PORT}"]
