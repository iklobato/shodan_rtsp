# The image runs the scanner as a CLI, one command per run:
#
#   docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" \
#     -e DATABASE_HOST=host.docker.internal:5440 shodan-rtsp:0.1.0 scan nmap
#
# Two stages because insightface 0.7.3 ships an sdist only: it is compiled in
# the builder, and the runtime keeps the finished venv without a compiler.

FROM python:3.11-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.9.11 /uv /usr/local/bin/uv

# The venv sits outside /app so the runtime stage copies it as one directory.
# UV_LINK_MODE=copy because a hard link cannot cross the stage boundary.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# The lock first: a source change does not reinstall the dependencies.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev


FROM python:3.11-slim-bookworm AS runtime

# nmap is a hard dependency: python-nmap shells out to the binary. The three
# libraries are what the wheels load at import time: libgomp1 for onnxruntime,
# and libgl1 plus libglib2.0-0 for cv2. insightface pulls the non-headless
# opencv-python in as well as the headless one pyproject pins, and that wheel
# links libGL.so.1, which is the one that fails without libgl1.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      libgl1 \
      libglib2.0-0 \
      libgomp1 \
      nmap \
 && rm -rf /var/lib/apt/lists/*

# The face model is not baked in. insightface downloads buffalo_l on the first
# face run into $HOME/.insightface, which the compose file keeps in a volume.
RUN useradd --create-home --uid 1000 scanner \
 && mkdir -p /home/scanner/.insightface

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv

# HOME is what insightface resolves the model directory from; unbuffered so the
# log lines of a run reach the terminal as they happen.
ENV PATH="/opt/venv/bin:$PATH" \
    HOME=/home/scanner \
    PYTHONUNBUFFERED=1

# The code last, so editing a scanner rebuilds one layer.
COPY . .
RUN mkdir -p /app/logs \
 && chown -R scanner:scanner /app /home/scanner

# Non-root, which is enough: the sweep asks nmap for `-p ... -sV` only. A scan
# type that needs root quits instead of falling back, and --cap-add NET_RAW does
# not help, because nmap checks the user. Run with --user root for one of those.
USER scanner

ENTRYPOINT ["/opt/venv/bin/python", "main.py"]
