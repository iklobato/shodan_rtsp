# Contract: brand signature data file

**Feature**: `specs/001-camera-monitoring-pipeline/spec.md` (FR-012, FR-015)
**Decisions**: D3, D22, D27
**Created**: 2026-11-11

Brand detection and the brand specific credential set are data, not code: a new brand is a
line in this file, with no code change and no release (D27). The pattern follows the
existing `cpe_map.yaml`, which is already a data file with the same role for the CVE step.

## File

`brands.yaml` at the repository root, path configurable as `brands.signature_path`.

```yaml
brands:
  - label: hikvision
    vendor: hikvision
    product: ip_camera
    patterns:
      - "Hikvision-IP"
      - "Hikvision"
      - "IpCamera$"
    credentials:
      users: ["admin"]
      passwords: ["12345", "admin", "1234"]
      url_templates:
        - "rtsp://{user}:{password}@{ip}:{port}/Streaming/Channels/101"

  - label: generic_onvif
    vendor: ""
    product: ""
    patterns: ["ONVIF"]
    credentials:
      users: []
      passwords: []
      url_templates: []
```

## Field rules

| Field | Required | Rule |
|-------|----------|------|
| `label` | yes | non-empty, unique in the file, matches `^[a-z][a-z0-9_]*$` |
| `vendor` | yes | the CPE vendor string. Empty means this brand cannot reach the CVE step |
| `product` | yes | the CPE product string, looked up in `cpe_map.yaml`. Empty means the same |
| `patterns` | yes | at least one entry. Each is a regular expression, matched with `search` against the banner text |
| `credentials.users` | no | defaults to empty |
| `credentials.passwords` | no | defaults to empty |
| `credentials.url_templates` | no | defaults to empty. Each carries `{user}`, `{password}`, `{ip}` and `{port}` |

Validation happens when the file is loaded, before any network call, and a violation stops
the run with the offending line named. A pattern that does not compile is an error, not a
warning: a brand that silently never matches is the failure mode this file exists to avoid.

## How it is used

1. The banner text is matched against every `patterns` entry, in file order. The first
   brand whose pattern matches wins, and the label is stored on the camera.
2. When no pattern matches, the camera is stored as unknown with its raw banner kept
   (FR-014). This is a normal outcome, not an error.
3. `vendor` and `product` are joined and looked up in `cpe_map.yaml` to reach the CVE step.
4. When the brand has a credential set, those credentials are tried before the generic
   wordlist files from the config (D22, FR-015).

## Precedence

A brand entry always beats the generic entries. Today `_generic_nginx` is defined twice in
the code, once in `BrandCredentialRegistry` and once in `BrandCredentialLoader`, which is
what makes the current precedence ambiguous; the file has one entry per label, so the
ambiguity cannot exist.

## What this file is not

It is not a watchlist and not a claim that a device is vulnerable. A brand match says what
the banner looks like. Whether a version is vulnerable is decided by the version range in
the CVE map, and whether a proof works is decided by a real attempt whose outcome is
recorded either way (FR-018).
