# Mind HealthCheck

A tiny C service health reporter that exposes a **JSON HTTP API** and a **WebSocket stream** with live system stats (CPU, RAM, uptime, users, top processes) and per-service health checks (HTTP/TCP/UNIX sockets).

* **HTTP API:** `:8081` (GET `/`)
* **WebSocket:** `:8082` (protocol name: `websocket`), emits the same payload periodically

> **⚠️ Big Warning / Disclaimer**
>
> * This repo was written with **vibe coding energy** — a handy hack for my own stack, not a product.
> * It primarily powers **my** status project: [https://status.mindhas403.dev](https://status.mindhas403.dev).
> * Assumptions may be brittle; error handling is minimal; security hardening is up to you.
> * If you use it, **you’re on your own** — enjoy responsibly ✨

---

## What it does

* Checks service health via:

  * `http`/`https` (HEAD request; TLS verification currently **disabled** in code)
  * `tcp://host:port`
  * `unix:///path/to/socket`
* Collects host metrics:

  * CPU usage (from `/proc/stat`)
  * Memory usage (from `/proc/meminfo`)
  * Uptime (from `/proc/uptime`)
  * Logged-in users (`users`)
  * Top processes (`ps` sorted by CPU)
* Resolves a coarse **location string** via `ipinfo.io` (region, country, org)
* Serves a compact JSON on HTTP and pushes the same payload over WebSocket

---

## Quick Start

### 1) Dependencies

#### Fedora/RHEL

```bash
sudo dnf install -y gcc make \
  libmicrohttpd-devel libwebsockets-devel jansson-devel libcurl-devel
```

#### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config \
  libmicrohttpd-dev libwebsockets-dev libjansson-dev libcurl4-openssl-dev
```

### 2) Configure

Open `healthcheck.c` and **replace your IPInfo token**:

```c
// CHANGE THIS — put your real token here
#define IPINFO_URL "https://ipinfo.io/json?token=YOUR_TOKEN"
```

> Tip: IPinfo free tier has rate limits; consider caching or removing if unnecessary.

Optionally tune:

* `#define PORT 8081` → HTTP port (WebSocket is `PORT + 1`, i.e. `8082`)
* `WS_REFRESH_INTERVAL` (seconds between WS pushes; default `1`)
* `config.json` → `refresh_time` (seconds between health checks), `version` tag

### 3) Minimal `service.json`

Keep it simple (example only):

```json
{
  "services": [
    { "type": "http", "url": "http://localhost:80", "name": "Caddy" },
    { "type": "tcp",  "url": "tcp://localhost:22", "name": "SSH" }
  ]
}
```

> You can add more (`unix` sockets, extra `http` checks, etc.) later.
> The repo example intentionally stays minimal.

### 4) Build

```bash
gcc -O2 -Wall -o healthcheck healthcheck.c \
  -lmicrohttpd -lwebsockets -ljansson -lcurl -lpthread
```

### 5) Run

```bash
./healthcheck
# HTTP
curl -s http://127.0.0.1:8081 | jq .
# WebSocket (example with websocat)
# websocat ws://127.0.0.1:8082
```

---

## Endpoints

### HTTP (GET `/` on `:8081`)

* **200 OK** → JSON payload (see below)
* **405** → non-GET methods rejected

CORS: `Access-Control-Allow-Origin: *`

### WebSocket (on `:8082`)

* Protocol name: `websocket`
* Server sends the same JSON every `WS_REFRESH_INTERVAL` seconds.

---

## Example JSON

```json
{
  "cpu": { "usage": 3.42 },
  "ram": { "used": 1.23, "total": 7.79 },
  "location": "Bangkok, TH, AS12345-ExampleOrg",
  "uptime": { "seconds": 12345, "readable": "0 days, 3 hours, 25 minutes, 45 seconds" },
  "service_health": {
    "Caddy": true,
    "SSH": true
  },
  "version": "1.0",
  "logged_in_users": ["mind"],
  "top_processes": [
    { "pid": "1234", "name": "someproc", "cpu_usage": "12.3", "ram_usage": "1.1", "uptime": "00:05:12" }
  ]
}
```

> Notes:
>
> * CPU% is a short two-sample delta.
> * RAM values are in **GiB** (MemTotal/MemAvailable from `/proc/meminfo`).
> * `service_health` is a map of `name → boolean`.

---

## Configuration Files

### `config.json`

```json
{
  "refresh_time": 15,
  "version": "1.0"
}
```

* `refresh_time` → interval (seconds) for background health checks
* `version` → arbitrary string surfaced in API

### `service.json` (minimal example above)

* `type`: one of `http`, `https`, `tcp`, `unix`
* `url` format examples:

  * `http://localhost:80`
  * `tcp://localhost:22`
  * `unix:///var/run/libvirt/libvirt-sock`

---

## systemd (User Service)

Run under your user (no root). First, ensure the binary and configs live somewhere stable, e.g. `~/Monitor/mind-healthcheck/`.

**`~/.config/systemd/user/mind-healthcheck.service`**

```ini
[Unit]
Description=Mind Monitor Healthcheck (HTTP 8081, WS 8082)

[Service]
Type=simple
WorkingDirectory=%h/Monitor/mind-monitor
ExecStart=%h/Monitor/mind-monitor/healthcheck
Restart=on-failure
RestartSec=2
StandardOutput=journal
StandardError=journal
ReadWritePaths=%h/Monitor/mind-monitor

[Install]
WantedBy=default.target
```

Enable & start:

```bash
systemctl --user daemon-reload
systemctl --user enable --now mind-healthcheck.service
systemctl --user status mind-healthcheck.service
```

Expose ports (if needed) via your reverse proxy (Caddy/NGINX) and/or firewall.

---

## Security & Ops Notes

* **TLS verification is disabled** for HTTP checks inside the code (both `CURLOPT_SSL_VERIFYPEER` and `VERIFYHOST` set off). For production, consider enabling verification if you check HTTPS endpoints you control.
* The WebSocket pushes every second; tune `WS_REFRESH_INTERVAL` and `refresh_time` to reduce load.
* Commands used (`users`, `ps`, `awk`, `head`) must exist in PATH.
* CORS is `*` for convenience; narrow it via a proxy if you expose publicly.
* If `ipinfo.io` fails or rate limits, `location` may remain `"Unknown"`.

---

## Related Projects (that use this)

* **🌸 MindTheNerd Monitor (Frontend/Dashboard)**
  [https://github.com/blueskychan-dev/MindTheNerd-Monitor](https://github.com/blueskychan-dev/MindTheNerd-Monitor)

* **🩺 Mind HealthCheck (This repo)**
  [https://github.com/blueskychan-dev/mind\_healthcheck](https://github.com/blueskychan-dev/mind_healthcheck)

* **🔌 tasmota\_tiny\_monitor**
  [https://github.com/blueskychan-dev/tasmota\_tiny\_monitor](https://github.com/blueskychan-dev/tasmota_tiny_monitor)

---

## License

**MIT License** — do what you want, no warranty.
See `LICENSE` file or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT).

---

## Author’s Note

Built for my own infra and dashboard — **fun + utility**.
If you fork it, tweak boldly, and vibe responsibly 😺

