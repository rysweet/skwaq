FROM python:3.10-slim as python-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VERSION=1.7.1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"

ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:$PATH"

FROM python-base as builder-base
RUN apt-get update --allow-insecure-repositories && apt-get install --no-install-recommends -y \
    curl \
    build-essential \
    gnupg \
    && rm -rf /var/lib/apt/lists/*
# Add the GPG key for the Debian package repository
RUN curl -fsSL https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x648ACFD622F3D138 | gpg --batch --yes --dearmor -o /usr/share/keyrings/debian-archive-keyring.gpg
# Update the package lists again
RUN apt-get update --allow-insecure-repositories

# Install poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

WORKDIR $PYSETUP_PATH
COPY poetry.lock pyproject.toml ./

RUN poetry install --no-root

# Development image
FROM python-base as development
ENV SKWAQ_ENV=development

WORKDIR $PYSETUP_PATH

COPY --from=builder-base $POETRY_HOME $POETRY_HOME
COPY --from=builder-base $PYSETUP_PATH $PYSETUP_PATH

RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN poetry install

# Production image
FROM python-base as production
ENV SKWAQ_ENV=production

COPY --from=builder-base $PYSETUP_PATH $PYSETUP_PATH
COPY . .

RUN poetry install --no-dev

CMD ["poetry", "run", "python", "-m", "skwaq"]