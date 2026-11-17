FROM nginx:1.28-alpine

RUN rm /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/snippets

COPY default.conf /etc/nginx/conf.d/default.conf
COPY training-proxy-headers.conf /etc/nginx/snippets/training-proxy-headers.conf

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/_gateway/health || exit 1
