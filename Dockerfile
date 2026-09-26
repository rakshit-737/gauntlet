# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY gauntlet ./gauntlet
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/gauntlet" \
      org.opencontainers.image.description="Threat-informed purple-team coverage scoring (lab-only, never executes techniques)" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --create-home --uid 10001 gauntlet
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER gauntlet
WORKDIR /home/gauntlet
ENV GAUNTLET_DATA_DIR=/data
ENTRYPOINT ["gauntlet"]
CMD ["--help"]
