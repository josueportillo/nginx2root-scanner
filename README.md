# nginx2root-scanner

A self-hosted web app that probes a target host for the [**nginx2root**](https://nginx2root.com) vulnerabilities and renders a full per-CVE report — all in one dark-themed UI. **Detection only**: it fingerprints the server and inspects protocol negotiation the same way `testssl.sh`, `nuclei`, and `nmap` do. It never sends exploit payloads, never corrupts memory, and never attempts remote code execution.

---

## What it detects

| ID | Vulnerability | Affected nginx | Exposure signal used |
|----|---------------|----------------|----------------------|
| **CVE-2026-123007** | HTTP/2 flow-control integer overflow → remote code execution (pre-auth) | 1.9.5 – 1.31.8 | TLS **ALPN `h2`** negotiation |
| **CVE-2026-123634** | DNS resolver use-after-free (variable `proxy_pass` + `mirror`) | 1.13.4+ | config-dependent (reported, needs review) |
| **CVE-2026-123633** | HTTP/2 use-after-free with upstream forwarding | 1.19.7+ | HTTP/2 reachable + upstream |
| **CVE-2026-121810** | HTTP/3 (QUIC) use-after-free with upstream forwarding | 1.25.0+ | **Alt-Svc `h3`** advertisement |
| **CVE-2026-113425** | Mail proxy `auth_http` use-after-free | 0.5.15+ | mail-proxy ports listening |
| **SCTP-LPE** | Linux kernel SCTP use-after-free (post-exploitation root) | kernel ≥ 4.15 | informational (chained step) |

**Patched releases (2026-11-18):** stable **1.30.7** and mainline **1.31.9**. The scanner is branch-aware — it checks the fixed release in the version's *own* branch, so `1.30.x` and `1.31.x` are each compared against the correct cutoff.

---

## How detection works

For a given host the scanner runs, in order:

1. **DNS** — resolves all A/AAAA records.
2. **HTTP/1.1** on `:80` — reads the `Server` header.
3. **HTTPS** on `:443` — TLS handshake with ALPN offering `h2` and `http/1.1`; records the negotiated protocol, TLS version, `Server` header, and `Alt-Svc` header.
4. **h2c cleartext HTTP/2** on `:80` — attempts the `Upgrade: h2c` dance and the HTTP/2 prior-knowledge preface.
5. **Mail-proxy ports** — banner-grabs `25, 110, 143, 465, 587, 993, 995` to detect an nginx `mail{}` front.
6. **Assessment** — fingerprints the version, maps each CVE to a verdict, and detects CDN/edge proxies (Vercel, Cloudflare, CloudFront, Fastly, Akamai, Netlify, Fly, Heroku).

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `vulnerable` | In affected range **and** the attack path is reachable from outside |
| `likely` | In affected range and path partially confirmed (e.g. h2 reachable, upstream unverifiable) |
| `mitigated` | In affected range but the specific path is disabled (e.g. ALPN negotiated `http/1.1`) |
| `inconclusive` | nginx detected but version unparseable, or requires config review |
| `not_affected` | Not nginx, or predates the affected range, or path absent |
| `patched` | At/above the fixed release in its branch |
| `info` | The SCTP kernel LPE note (not remotely assessable) |

> **Important caveat:** distro backports (Debian/Ubuntu/RHEL) keep the old version string while shipping the fix. Always confirm against the vendor advisory rather than trusting the banner version alone.

---

## Dependencies

**None.** The entire app is Python standard library only (`socket`, `ssl`, `sqlite3`, `http.server`). No `pip install`, no `requirements.txt`, no virtualenv needed.

Requirements:

- **Python 3.8+** (uses `ssl.SSLContext.set_alpn_protocols` and `socket.create_connection`). Tested on 3.11/3.12.
- Outbound network access from the machine running the scanner to the targets you want to probe.

---

## Quickstart (local)

```bash
git clone https://github.com/josueportillo/nginx2root-scanner.git
cd nginx2root-scanner

# Web UI
python3 server.py
# → open http://localhost:8095

# Or CLI (prints JSON to stdout)
python3 scanner.py example.com https://nginx.org
```

The web server binds `0.0.0.0` so it is reachable across your LAN/subnets. Configure the port via the `NGINX2ROOT_PORT` environment variable (default `8095`).

---

## Web API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | The single-page UI |
| `POST` | `/api/scan` | Run a scan. Body: `{"target": "example.com"}`. Returns the full result JSON. |
| `GET` | `/api/history` | List past scans (id, target, overall status, timestamp) |
| `GET` | `/api/scan/{id}` | Fetch a stored scan result by id |

Scan history is persisted in `scans.db` (SQLite) next to `server.py`.

---

## Deployment

### 1. systemd (bare-metal / VM — recommended)

```bash
sudo cp deploy/nginx2root-scanner.service /etc/systemd/system/
sudo mkdir -p /opt/nginx2root-scanner
sudo cp scanner.py server.py /opt/nginx2root-scanner/
sudo cp -r static /opt/nginx2root-scanner/
sudo systemctl daemon-reload
sudo systemctl enable --now nginx2root-scanner
systemctl status nginx2root-scanner
```

Edit the `WorkingDirectory`, `ExecStart`, and `User=` lines in the unit to match your install path and service account.

### 2. Docker

```bash
docker build -t nginx2root-scanner .
docker run -d --name nginx2root-scanner -p 8095:8095 nginx2root-scanner
```

The image runs as a non-root user and binds `0.0.0.0:8095`.

### 3. Docker Compose

```bash
docker compose up -d --build
```

### 4. Kubernetes / k3s

```bash
# build/tag/push the image to your registry first, then update the image: in the manifest
kubectl apply -f deploy/k3s.yaml
```

Ships a `Deployment`, a `ClusterIP` `Service`, and a `networking.k8s.io/v1` `Ingress` (works with Traefik). Edit the ingress `host` to match your DNS.

### 5. Reverse proxy (optional)

The app is plain HTTP. To front it with nginx/Traefik, proxy to `127.0.0.1:8095`. No WebSockets or special headers required.

---

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `NGINX2ROOT_PORT` | `8095` | TCP port the web server binds |

---

## Project structure

```
nginx2root-scanner/
├── scanner.py           # detection engine (stdlib only)
├── server.py            # web server + JSON API + SQLite history
├── static/
│   └── index.html       # self-contained dark UI (inline CSS + JS)
├── Dockerfile
├── docker-compose.yml
├── run.sh               # convenience launcher
├── deploy/
│   ├── nginx2root-scanner.service   # systemd unit
│   └── k3s.yaml                     # Kubernetes manifest
├── CHANGELOG.md
└── LICENSE
```

---

## Security & legal

- This tool performs **detection only**. It makes standard HTTP/TLS/banner probes and compares the results against published version ranges and protocol-negotiation signals.
- **Only scan hosts you own or are explicitly authorized to test.** Probing third-party infrastructure without permission may violate their terms of service or applicable law (e.g. the Computer Fraud and Abuse Act).
- The `Server` header and ALPN/Alt-Svc signals can be spoofed or stripped by a CDN, WAF, or reverse proxy. When a CDN is detected, the scanner flags it and tells you to scan the origin directly.

## Sources

- [nginx2root.com](https://nginx2root.com) — the vulnerability disclosure
- [Xint writeup: nginx2root Remote Code Execution](https://xint.io/blog/nginx2root-remote-code-execution)

## License

[MIT](./LICENSE) © 2026 Josue Portillo
