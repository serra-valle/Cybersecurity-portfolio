FROM python:3.12.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin aegis

WORKDIR /app

COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt

COPY app/aegis_soar /app/aegis_soar

USER 10001:10001
EXPOSE 8080

CMD ["uvicorn", "aegis_soar.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
