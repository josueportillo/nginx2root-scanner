# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-19

### Added

- Detection engine (`scanner.py`) covering the five nginx2root CVEs
  (CVE-2026-123007, -123634, -123633, -121810, -113425) and the chained
  Linux SCTP kernel privilege-escalation note.
- Network probes: DNS resolution, HTTP/1.1, HTTPS with ALPN `h2`/`http/1.1`
  negotiation, h2c cleartext upgrade + prior-knowledge, HTTP/3 (`Alt-Svc`),
  and six mail-proxy port banner grabs.
- Branch-aware nginx patching check (stable 1.30.7 vs mainline 1.31.9,
  both fixed 2026-11-18).
- CDN/edge detection hint (Vercel, Cloudflare, CloudFront, Fastly, Akamai,
  Netlify, Fly, Heroku).
- Stdlib-only web server (`server.py`) with a JSON API and SQLite scan history.
- Self-contained dark web UI (`static/index.html`) with per-CVE verdict cards,
  fingerprint table, mail-port breakdown, and scan history.
- Deployment assets: Dockerfile, docker-compose.yml, systemd unit, k3s manifest.
