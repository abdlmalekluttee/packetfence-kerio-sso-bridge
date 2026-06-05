FROM python:3.12-alpine

# non-root runtime user
RUN adduser -D -u 10001 bridge

WORKDIR /app
COPY pf_kerio_sso_bridge.py /app/

USER bridge
EXPOSE 9090

# All configuration comes from environment variables (see .env)
ENTRYPOINT ["python3", "/app/pf_kerio_sso_bridge.py"]
