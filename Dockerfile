# Dockerfile — a local container image for the dashboard.
#
# WRITTEN, NOT BUILT. This build has not run Docker; doing so is an
# approval-gated action (see docs/deployment-guide.md). The file is here so a
# deployment is a reviewed artefact rather than something improvised later.
#
# BUILD AND RUN (once approved):
#   docker build -t als:1.0.0 .
#   docker run --rm -p 127.0.0.1:8000:8000 \
#       -e PRODUCT_SESSION_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
#       -v "$PWD/data:/app/data" \
#       als:1.0.0
#
# NOTE THE PORT PUBLICATION: `-p 127.0.0.1:8000:8000`, not `-p 8000:8000`.
# The bare form binds 0.0.0.0 on the host and bypasses the application's own
# loopback default — Docker writes its own iptables rules and will happily
# expose a container past a host firewall. The explicit 127.0.0.1 prefix is
# what keeps the deployment local.

FROM python:3.11-slim-bookworm

# Fail fast and log immediately; no .pyc clutter in a layer.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first, so a source edit does not re-resolve the whole tree.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Run as an unprivileged user. The app needs no root capability: it binds an
# unprivileged port, reads files it is given, and writes one SQLite database.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 als

COPY --chown=als:als src/ ./src/
COPY --chown=als:als scripts/ ./scripts/
COPY --chown=als:als configs/ ./configs/

# The two writable locations: the database and the authorised input directory.
# Everything else in the image can stay read-only.
RUN mkdir -p /app/data/product/uploads /app/data/authorised_input \
    && chown -R als:als /app/data

USER als

# Loopback INSIDE the container would be unreachable from the host, so the
# container listens on all its own interfaces and the HOST publishes only to
# 127.0.0.1 (see the run command above). The container's network namespace is
# the boundary here, not the bind address.
EXPOSE 8000

# No outbound traffic is expected in normal operation. To enforce that at the
# container level, run with `--network none` after the database is initialised,
# or attach an internal-only network.
#
# The healthcheck below opens a connection, which deserves a word: it is
# Docker's supervision process, not the product, and it connects to the
# container's OWN loopback. No module under src/ imports urllib.request —
# tests/test_containment_outbound.py fails the build if one ever does. The
# containment claim is about what the application can reach, and this reaches
# only itself.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

# The database must exist before the server starts. init_db is idempotent, so
# running it on every container start is correct and cheap.
CMD ["sh", "-c", "python -m scripts.init_db && exec python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000"]
