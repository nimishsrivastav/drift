# Build from the repo root: docker build -f scorer/Dockerfile .
FROM python:3.15-slim-bookworm@sha256:4e03260adeeebafccd084f3584e6b84823aba5651cfb53ef8a078ed441ddf9cd AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
COPY gen/python gen/python
COPY scorer scorer
COPY eval/pyproject.toml eval/pyproject.toml
COPY eval/src eval/src
RUN uv sync --frozen --no-dev --no-editable --package drift-scorer

FROM python:3.15-slim-bookworm@sha256:4e03260adeeebafccd084f3584e6b84823aba5651cfb53ef8a078ed441ddf9cd
COPY --from=build /app/.venv /app/.venv
ENV PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["/app/.venv/bin/python", "-m", "drift_scorer.server"]
