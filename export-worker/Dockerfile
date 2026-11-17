FROM python:3.12-slim
RUN groupadd --gid 10001 exportlab && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin exportlab \
    && mkdir -p /run/northstar-export /opt/export-worker && chown 10001:10001 /run/northstar-export
WORKDIR /opt/export-worker
COPY worker.py ./worker.py
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-I", "/opt/export-worker/worker.py"]
