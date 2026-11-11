# Front 4 rig: a mock camera, not firmware

The device this front was proved against is a mock: a loopback HTTP server in
`lab/mock_camera.py`, started by hand. It is not emulated Hikvision firmware, it
is not a real camera, and nothing in this document or in the front report is
evidence about Hikvision code. It proves the client: the request shape, the one
frame, the rows the run writes, and that nothing was written to the device.

## Why there is no emulated device (T008, D42)

T008 asked for FEMU or FirmAE running an old Hikvision build. D42 allows this
document to record the reason instead, when the emulation cannot be made to
answer. Measured on this host on 2026-11-11:

| What | Command | Output |
| --- | --- | --- |
| Kernel virtualisation on the Mac | `ls -l /dev/kvm` | `ls: /dev/kvm: No such file or directory` |
| The same inside the Docker VM | `docker run --rm alpine ls -l /dev/kvm` | `ls: /dev/kvm: No such file or directory` |
| Virtualisation flags in the Docker VM | `docker run --rm alpine grep -c -E "vmx\|svm" /proc/cpuinfo` | `0` |
| The emulators | `command -v qemu-system-x86_64 lima colima multipass` | all four: not installed |
| Hypervisor.framework | `sysctl -n kern.hv_support` | `1` |

Hypervisor.framework is available, so a virtual machine on this Mac is not
impossible. What is missing is the emulator: FEMU and FirmAE are QEMU forks that
have to be built, and no QEMU is installed. Booting a camera firmware without
KVM, in software emulation, is a multi-hour job with an unknown result, so the
front took the fallback D42 names and this document says so in its first line.

## The device

`lab/mock_camera.py`: the standard library plus the opencv the repository already
uses. It answers one path with a real JPEG and 404 to everything else:

- `GET /onvif-http/snapshot?auth=YWRtaW46MTEK` answers 200, `image/jpeg`, and a
  640x480 frame it encodes once at startup.
- the same path without the `auth` parameter answers 404, and so does every other
  path, including the ones the other three classes read.

The `auth` value is the base64 of `admin:11`, the fixed value the advisory
publishes and the same constant the class carries in `scanners/cve/auth_bypass.py`.

It sends `Server: Hikvision-Webs/DS-2CD2032-I`, so a real `nmap -sV` names the
brand and the model through `brands.yaml` and no camera row is written by hand.
`Hikvision-Webs` is what that series really sends; the model is appended because
the model is what reaches CVE-2017-7921 in the NVD feed, and this device has no
other way to report one.

## How to run it

```
$ .venv/bin/python lab/mock_camera.py --port 8000 2> logs/mock_camera.log
```

The standard library access log on stderr is the device state the run is compared
on: one line per request, and nothing this device accepts is a write.

## The raw answer

The exact request the class sends, and the answer, verbatim:

```
$ curl -sS -D - -o /tmp/snapshot.jpg "http://127.0.0.1:8000/onvif-http/snapshot?auth=YWRtaW46MTEK"
HTTP/1.0 200 OK
Server: Hikvision-Webs/DS-2CD2032-I 
Date: Wed, 11 Nov 2026 14:56:28 GMT
Content-Type: image/jpeg
Content-Length: 5427

$ file /tmp/snapshot.jpg
/tmp/snapshot.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 640x480, components 3
```

The path without the parameter, and one path each of two other classes:

```
$ curl -sS -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8000/onvif-http/snapshot"
404
$ curl -sS -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8000/check.cgi?file=/etc/passwd"
404
$ curl -sS -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8000/common/get_file.php"
404
```

The date on the answer is the host clock of the machine that ran it, not a
timestamp of the device.
