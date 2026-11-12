# Run it in Docker

Part of the [Camera Scanner](../README.md) documentation.

The image is the CLI: the entrypoint is `main.py`, so every argument after the
image name is one command of the seven. Nothing is baked into it that holds a
secret or that belongs to one environment.

## Pull it, no build

The image is published, so a run needs no source tree and no build step:

```bash
export SHODAN_IMAGE=iklob1/shodan-rtsp:0.1.0
docker pull "$SHODAN_IMAGE"
docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  "$SHODAN_IMAGE" report faces
```

| Tag | Follows |
|-----|---------|
| `0.1.0` | one release, and the only tag that never moves |
| `0.1` | the patch line, so `0.1.4` replaces `0.1.3` |
| `latest` | the newest release |

Through compose, the same image without a build:

```bash
export SHODAN_IMAGE=iklob1/shodan-rtsp:0.1.0
docker compose pull scanner
docker compose run --rm scanner report faces
```

Docker Hub limits anonymous pulls to 100 per 6 hours per IP, and an authenticated
free account to 200 per 6 hours (`docs.docker.com/docker-hub/usage/`).

## Build

The rest of this page is for building from the source tree, which is what a
change to the scanner needs:

```console
$ docker build -t shodan-rtsp:0.1.0 .
#20 naming to docker.io/library/shodan-rtsp:0.1.0 done
$ docker image ls shodan-rtsp:0.1.0 --format '{{.Repository}}:{{.Tag}} {{.Size}}'
shodan-rtsp:0.1.0 1.82GB
```

## Create the schema

The entrypoint is the CLI, so a migration is one command with the entrypoint
swapped:

```console
$ docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  --entrypoint alembic shodan-rtsp:0.1.0 upgrade head
INFO  [alembic.runtime.migration] Running upgrade  -> 0001, initial schema
INFO  [alembic.runtime.migration] Running upgrade 0001 -> 0002, migrate the legacy cam table into camera and camera_observation
```

## `docker run`

```console
$ docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  shodan-rtsp:0.1.0 report faces
person 1  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
```

That run is real output from this machine on 2026-11-11, against the Postgres
published on the host at 5440.

| Flag | Why |
|------|-----|
| `-v "$PWD/config.yaml:/app/config.yaml:ro"` | the config holds the Shodan key and the database password, so it is mounted, never built in |
| `-e DATABASE_HOST=...` | the address the container reaches the database at (see below) |
| `-v shodan_logs:/app/logs` | the log and the frames outlive the container |
| `-v shodan_face_models:/home/scanner/.insightface` | `buffalo_l` downloads once, not once per run |
| `-v "$PWD/nvdcve-2.0.json:/app/nvdcve-2.0.json:ro"` | the NVD feed is not in the repository, so `scan cve` needs it mounted |

`DATABASE_HOST` overrides `database.host` of the config file, because that is the
one value that differs between a run on the host and a run in a container
(`scanners/config.py`). On Docker Desktop for Mac `host.docker.internal` resolves
already; on Linux add `--add-host=host.docker.internal:host-gateway`.

A command that reaches a device needs the same gate as always, and the range in
the mounted config is the one that decides:

```console
$ docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" shodan-rtsp:0.1.0 scan shodan 'country:NL'
2026-11-11 17:22:07,553 ERROR the query names no `net:` range, so it reaches the whole index; declare the range the scan may reach in the query itself
$ echo $?
1
```

## A scan from the container

The write path works the same way, so a scan run inside the container stores its
row in the database the config names:

```console
$ docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  shodan-rtsp:0.1.0 scan nmap 127.0.0.1/32
2026-11-11 17:25:11,905 INFO Starting nmap scanning on 127.0.0.1/32
2026-11-11 17:25:12,696 INFO Found 1 hosts using nmap scan
2026-11-11 17:25:12,696 INFO nmap XML written to logs/nmap.xml
2026-11-11 17:25:12,715 INFO Executors: finished nmap scan
```

Both runs above, this one and the migration, were taken against a throwaway
database on the same Postgres, dropped afterwards, so the `cameras` database was
never touched. Only the `database` block of the mounted config differs.

## `docker compose run`

The compose file carries a `scanner` service on the same network as Postgres, so
no host address is needed:

```console
$ docker compose run --rm scanner report faces
 Container shodan_pg  Running
person 1  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
```

It sits behind the `cli` profile, so it never starts on its own and the database
command of the quickstart stays as it was:

```console
$ docker compose config --services
postgres
$ docker compose --profile cli config --services
postgres
scanner
```

## What is in the image

| In | Out |
|----|-----|
| Python 3.11 with every dependency from `uv.lock`, compiled in a builder stage | no compiler in the final image |
| `nmap`, plus the three libraries the wheels load (`libgl1`, `libglib2.0-0`, `libgomp1`) | no `ffmpeg` binary: the OpenCV wheel carries its own |
| the code, the wordlists, `brands.yaml`, `cpe_map.yaml`, the lab | no `config.yaml`, no `.env`, no API key |
| a `scanner` user, uid 1000, which is what the CLI runs as | no root, and no capability by default |

The image is 1.82 GB because `insightface` pulls `scipy`, `scikit-learn`,
`matplotlib` and both `opencv-python` wheels behind it. Dropping the face scan
would drop most of that.

One thing happens on the first run instead of at build time: `scan faces`
downloads `buffalo_l`, about 280 MB, into `$HOME/.insightface`, which the compose
file keeps in the `shodan_face_models` volume. Mount that volume, or every run
downloads the model again.

## nmap as a non-root user

The CLI runs as `scanner`, and the sweep asks nmap for `-p ... -sV` only, which
needs no privilege. A scan type that does need it quits instead of falling back:

```console
$ docker run --rm --entrypoint nmap shodan-rtsp:0.1.0 -sS -p 554 127.0.0.1
You requested a scan type which requires root privileges.
QUITTING!
```

`--cap-add NET_RAW` does not change that: nmap checks the user, not the
capability. A scan type that needs root means running the container as root,
which gives up the non-root default:

```bash
docker run --rm --user root -v "$PWD/config.yaml:/app/config.yaml:ro" \
  shodan-rtsp:0.1.0 scan nmap 192.168.1.0/24
```

The scanner itself never asks nmap for those types, so the default non-root run
is enough for the seven commands.

## Publish a release

The image goes out on a version tag, through
`.github/workflows/publish.yml`, and never from a branch:

```bash
git tag v0.1.0
git push origin v0.1.0
```

| Step | What it does |
|------|--------------|
| lint and tests | `ruff check .` and `pytest -q`, the same suite as CI |
| version check | the tag has to equal the version in `pyproject.toml`, or the run stops |
| build | `linux/amd64`, cached in the Actions cache |
| smoke test | `--help`, the imports of `cv2`, `nmap`, `onnxruntime` and `psycopg2`, and `nmap --version` |
| push | the tags `0.1.0`, `0.1` and `latest` |

Two repository secrets and one repository on Docker Hub:

| Piece | Holds |
|-------|-------|
| secret `DOCKERHUB_USERNAME` | the account, which is also the namespace |
| secret `DOCKERHUB_TOKEN` | a personal access token with **Read & Write** |
| the repository | nothing to create: the first push of `v0.1.0` created `iklob1/shodan-rtsp` as a public repository |

The Hub creates a token read-only by default, and a read-only token is refused at
the push, so pick Read & Write when generating it. The Hub docs describe creating
the repository in the UI and do not say a push creates it, so create it there if
a push is ever refused for the missing repository.

A release whose tests fail never reaches the registry, and neither does one whose
tag does not match `pyproject.toml`. A failed run is re-run from the Actions tab.

## The first release, as it went

`v0.1.0` is published. The run of `v0.1.0` built `linux/amd64`, smoke tested the
image and pushed three tags, and a pull from this machine answered:

```console
$ docker pull iklob1/shodan-rtsp:0.1.0
Digest: sha256:967ba68bab12bcf04e06a56cd04aa37d1426690547f4526b598377771674bdb8
$ docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" \
    -e DATABASE_HOST=host.docker.internal:5440 \
    iklob1/shodan-rtsp:0.1.0 report faces
person 1  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
```

The Hub reports 416 MiB per tag, `linux/amd64` only. Nothing here was run on
another architecture, so an arm64 host runs the image through emulation.
