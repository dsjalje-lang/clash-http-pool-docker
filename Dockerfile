FROM python:3.13-alpine

ARG MIHOMO_VERSION=v1.19.29
ARG TARGETARCH

RUN set -eux; \
    apk add --no-cache ca-certificates curl tini; \
    case "${TARGETARCH}" in \
      amd64) mihomo_asset="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz" ;; \
      arm64) mihomo_asset="mihomo-linux-arm64-${MIHOMO_VERSION}.gz" ;; \
      *) echo "Unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --silent --show-error \
      "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${mihomo_asset}" \
      --output /tmp/mihomo.gz; \
    gunzip /tmp/mihomo.gz; \
    install -m 0755 /tmp/mihomo /usr/local/bin/mihomo; \
    rm /tmp/mihomo

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./
RUN chmod 0755 /app/entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
