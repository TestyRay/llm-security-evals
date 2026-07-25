FROM python:3.11-slim

WORKDIR /app

COPY images/victim/source/server.py /app/server.py

RUN useradd --system --uid 10001 --create-home victim \
    && mkdir -p /srv/preview \
    && chown -R victim:victim /srv/preview

USER victim

EXPOSE 8080

CMD ["python3", "/app/server.py"]
