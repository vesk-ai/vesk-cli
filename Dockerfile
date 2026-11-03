# Vesk Verify CLI. Build: docker build -t vesk-cli .
# Run:   docker run --rm -e OPENAI_API_KEY -v "$PWD:/work" vesk-cli scan -c vesk.yaml
FROM python:3.12-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 NO_COLOR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl \
    && useradd --create-home --uid 10001 vesk
USER vesk
WORKDIR /work
ENTRYPOINT ["vesk"]
CMD ["--help"]
