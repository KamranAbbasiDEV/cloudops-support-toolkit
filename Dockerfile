FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . && useradd -m -u 10001 cloudops
USER cloudops

# Offline example by default; pass a different command to use another subcommand.
CMD ["cloudops", "analyze-logs", "samples/access.log"]
