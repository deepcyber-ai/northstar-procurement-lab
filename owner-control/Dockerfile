FROM python:3.12-slim
RUN groupadd --gid 10002 owner && useradd --uid 10002 --gid owner --no-create-home owner && mkdir /config && chown owner:owner /config
WORKDIR /app
COPY owner-control/control.py owner-control/local_server.py ./
COPY infra-aws-native/functions/owner-demo.html ./
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10002:10002
EXPOSE 8081
CMD ["python", "local_server.py"]
