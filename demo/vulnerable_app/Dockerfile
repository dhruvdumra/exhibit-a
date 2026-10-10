# Intentionally bad Dockerfile for the demo. DO NOT DEPLOY.
FROM python:latest

ENV API_TOKEN=f3b9c2a1d4e5061728394a5b6c7d8e9f0a1b2c3d4e5f6071

COPY . /app
WORKDIR /app

RUN pip install flask lxml

EXPOSE 8000

CMD python app.py
