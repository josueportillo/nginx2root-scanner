FROM python:3.12-slim

WORKDIR /app

COPY scanner.py server.py ./
COPY static ./static

RUN useradd --system --uid 10001 scanner && chown -R scanner:scanner /app
USER scanner

ENV NGINX2ROOT_PORT=8095
EXPOSE 8095

CMD ["python3", "server.py"]
