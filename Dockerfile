ARG PY_VERSION=3.11
FROM python:${PY_VERSION}-slim-bullseye AS base

ENV LANG "C.UTF-8"
ENV SHELL "/bin/bash"
ENV TZ "UTC"
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ; rm -rf /var/lib/apt/lists/*

WORKDIR /usr/app/huma-utils/
COPY ./ ./

RUN pip install poetry

# Build target for CI and local development
FROM base AS dev
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi
