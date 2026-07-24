FROM python:3.11-slim

WORKDIR /app
COPY source/server.py /app/server.py

RUN useradd --system --uid 10001 --create-home evaluator
USER evaluator

EXPOSE 8080

CMD ["python3", "-B", "/app/server.py"]
