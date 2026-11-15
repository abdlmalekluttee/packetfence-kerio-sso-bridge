FROM python:3.12-alpine

# non-root runtime user
RUN apk add --no-cache tzdata && adduser -D -u 10001 bridge

WORKDIR /app
COPY pf_kerio_sso_bridge.py /app/
COPY bridge /app/bridge

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

USER bridge
EXPOSE 9090

# Configuration and durable state live in the restricted /data volume.
ENTRYPOINT ["python3", "/app/pf_kerio_sso_bridge.py"]
