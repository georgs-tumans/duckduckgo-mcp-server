FROM python:3.13-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# Run unprivileged. uid 1000 is fixed so the documented `podman run --user 1000:1000`
# lines up with the user that exists in the image. Nothing is written outside /tmp,
# so the container also runs fine with --read-only --tmpfs /tmp.
RUN useradd --create-home --uid 1000 appuser
USER appuser

# Updated to allow command-line switches to be passed via docker commands
ENTRYPOINT ["python", "-m", "duckduckgo_mcp_server.server"]
CMD []
