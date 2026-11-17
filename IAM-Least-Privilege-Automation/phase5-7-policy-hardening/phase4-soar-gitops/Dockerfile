ARG PYTHON_BASE_IMAGE=python:3.12.16-slim-trixie
FROM ${PYTHON_BASE_IMAGE}

ARG VCS_REF=unknown

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

LABEL org.opencontainers.image.title="Aegis SOAR" \
      org.opencontainers.image.description="Authenticated Kubernetes security response service" \
      org.opencontainers.image.source="https://github.com/serra-valle/Cybersecurity-portfolio" \
      org.opencontainers.image.revision="${VCS_REF}"

RUN groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin aegis

WORKDIR /app

COPY --chown=10001:10001 app/requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --no-compile --requirement /app/requirements.txt

COPY --chown=10001:10001 app/aegis_soar /app/aegis_soar

USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM

CMD ["uvicorn", "aegis_soar.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
