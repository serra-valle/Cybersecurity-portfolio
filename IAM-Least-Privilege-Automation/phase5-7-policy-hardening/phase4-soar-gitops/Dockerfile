ARG PYTHON_BASE_IMAGE=python:3.12.16-alpine3.24
FROM ${PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Refresh the pinned Alpine base and retain CA roots for Kubernetes API TLS.
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates

WORKDIR /app

COPY --chown=10001:10001 app/requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade "pip==26.2.0" \
    && python -m pip install --no-cache-dir --no-compile --requirement /app/requirements.txt \
    && python -m pip check \
    && python -c "from importlib.metadata import version; v=tuple(int(x) for x in version('starlette').split('.')[:3]); assert v >= (1, 3, 1), v" \
    && python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.12/ensurepip /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
    && python -c "import importlib.util; assert importlib.util.find_spec('pip') is None"

COPY --chown=10001:10001 app/aegis_soar /app/aegis_soar

ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Aegis SOAR" \
      org.opencontainers.image.description="Authenticated Kubernetes security response service" \
      org.opencontainers.image.source="https://github.com/serra-valle/Cybersecurity-portfolio" \
      org.opencontainers.image.revision="${VCS_REF}"

USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM

CMD ["uvicorn", "aegis_soar.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
