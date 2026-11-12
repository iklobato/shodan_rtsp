# Shodan by location

Part of the [Camera Scanner](../README.md) documentation.

Shodan answers where a camera is, not only that it exists. `find shodan` stores
the place Shodan reports, so a run can be aimed at one country, one city, or one
block of a network range.

## The range always comes first

`find shodan` refuses a query that names no `net:` range, and refuses every
`net:` range that is not inside `targets.allowed_cidrs`. Both checks run before
the API call, so a refused query spends no credit (D18).

A query that is only a location, with no range:

```console
$ uv run python main.py find shodan 'country:NL city:"Amsterdam" has_screenshot:true'
2026-11-11 14:03:52,768 ERROR the query names no `net:` range, so it reaches the whole index; declare the range the scan may reach in the query itself
$ echo $?
1
```

A query that names a range the config does not declare:

```console
$ uv run python main.py find shodan 'net:203.0.113.0/24 country:NL'
2026-11-11 14:03:57,580 ERROR 203.0.113.0/24 is outside the declared ranges ['127.0.0.1/32', '192.168.1.0/24']; declare it in targets.allowed_cidrs
$ echo $?
1
```

Both runs are real output from this machine on 2026-11-11, against the
`targets.allowed_cidrs` of `config.yaml` at the time.

## The shape of a query that runs

```text
net:<range you own> <location filters> <camera filters>
```

Shodan does not index private space, so the range in `net:` is a public range you
own or are authorized to test, declared in `targets.allowed_cidrs` as well (D37).
A narrower range inside a declared one is accepted: with `192.168.1.0/24`
declared, `net:192.168.1.0/28` passes the gate.

## Location filters

| Filter | Takes | Example |
|--------|-------|---------|
| `country` | 2 letter code, comma separated | `country:NL`, `country:DE,CH,FR` |
| `city` | city name, in quotes when it has a space | `city:"Amsterdam"` |
| `region` | region code | `region:NH` |
| `state` | state name | `state:"New York"` |
| `postal` | postal code | `postal:1011` |
| `geo` | radius search | listed by Shodan, syntax not on the pages reachable today |

Filter names and the quoting rule come from the Shodan docs
(`help.shodan.io/the-basics/search-query-fundamentals`,
`shodan.io/search/filters`). Only `net:` is checked by the gate: a `city:` name
and a `geo:` radius go to Shodan as written, and Shodan decides what they match.

## Filters that keep the result set on cameras

| Filter | Why |
|--------|-----|
| `has_screenshot:true` | a result with a screenshot is a device that served an image |
| `screenshot.label:webcam,cam` | Shodan labelled the image as a camera, the default of `config.yaml.example` |
| `port:554` | the RTSP port of D15 |
| `product:` / `device:` | one vendor or device string |

## Run it

Declare the range and the query in the config:

```yaml
shodan:
  api_key: "<your_shodan_api_key>"
  query: "net:203.0.113.0/24 country:NL has_screenshot:true screenshot.label:webcam,cam"
targets:
  allowed_cidrs: ["203.0.113.0/24"]
```

Then run the configured query, or type one for this run only:

```bash
uv run python main.py find shodan
uv run python main.py find shodan 'net:203.0.113.0/24 city:"Amsterdam" port:554'
```

The argument replaces `shodan.query` for that run and nothing else, so the same
`allowed_cidrs` still guards it. One config per country is one file per country:

```bash
uv run python main.py --config lab/nl.yaml find shodan
```

`-v` adds one line per banner, in the formats `scanners/task.py` writes:

```text
198.51.100.7:554 added (priority=high)
Skipped 198.51.100.9:80 (blocked org/tag)
3 cameras added
```

A banner whose org, tags or hostname name an institution (school, hospital,
government, military, and the rest of the lists in `scanners/task.py`) is
skipped, so a country run does not store a hospital camera. A result that names
a residential, office or hotel tag is logged as `priority=high`; the rest are
`medium`. The `scan_run` row records the query itself, so the range a run
reached is written down even when nobody typed it.

## What gets stored

| Column | Holds |
|--------|-------|
| `camera.city` | city Shodan reports |
| `camera.country_code` | 2 letter country code |
| `camera.country_name` | country name |
| `camera.region_code` | region code |

## Read the stored cameras by place

`search` filters on person, camera and time, not on place, so a place question is
one SQL line:

```bash
docker compose exec postgres psql -U scanner -d cameras -c \
  "select country_code, city, count(*) from camera group by 1, 2 order by 3 desc"
```

A stored Shodan result is a public address, so it stays outside a private
`allowed_cidrs`: reach it with `--camera-id N`, or declare the range before
`scan credentials` and `scan vulns` run over it.

## What was not run here

The accepted-query path has no real output in this file. The `config.yaml` of
this machine holds a live API key, so a run would spend credit and reach
`api.shodan.io`, and the ranges it declares are private, which Shodan does not
index (D37). The two refusals above are real; the accepted run is not.
