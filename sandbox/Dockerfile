# ExhibitA verification sandbox.
#
# Built once (with network). At verify time the target app and the harness are
# mounted in, and the container runs with --network none, memory/pid/time limits,
# and no added capabilities. It only ever runs ExhibitA's own demo app.
FROM python:3.12-slim

# Deps the demo app and the verification recipes need. lxml enables the XXE recipe.
RUN pip install --no-cache-dir flask==3.1.3 lxml==5.3.0

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
