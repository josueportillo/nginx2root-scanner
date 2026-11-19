#!/usr/bin/env python3
"""
nginx2root vulnerability scanner — detection engine.

Implements the exposure checks from nginx2root.com / the Xint writeup
(https://xint.io/blog/nginx2root-remote-code-execution), Section 2.3.

DETECTION ONLY. No exploit payloads, no memory corruption, no RCE attempts.
This does exactly what testssl.sh / nuclei / nmap do: banner grab, TLS ALPN
negotiation, h2c cleartext upgrade, HTTP/3 advertisement, mail-port banners.

Vulnerabilities covered (nginx2root):
  CVE-2026-123007  HTTP/2 flow-control integer overflow -> RCE  (1.9.5 - 1.31.8)
  CVE-2026-123634  DNS resolver use-after-free (resolver + variable proxy_pass + mirror)
  CVE-2026-123633  HTTP/2 use-after-free with upstream forwarding   (>= 1.19.7)
  CVE-2026-121810  HTTP/3 (QUIC) use-after-free with upstream fwd   (>= 1.25.0)
  CVE-2026-113425  Mail proxy auth_http use-after-free              (>= 0.5.15)
  + Linux kernel SCTP LPE (chained post-exploitation -> root, kernel >= 4.15)
"""

import socket
import ssl
import re
import time
import ipaddress

TIMEOUT = 8.0
USER_AGENT = "nginx2root-scanner/1.0 (detection only)"

MAIL_PORTS = [25, 110, 143, 465, 587, 993, 995]

# ---------------------------------------------------------------------------
# version helpers
# ---------------------------------------------------------------------------

def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _pad(v):
    return tuple(v) + (0,) * (3 - len(v))


def vcmp(a, b):
    a, b = _pad(a), _pad(b)
    return (a > b) - (a < b)


# Fix releases (2026-11-18). nginx ships two release branches: stable (even
# minor, e.g. 1.30.x) and mainline (odd minor, e.g. 1.31.x). Both were patched
# on the same day, so a version is patched only if it is >= the fix in ITS
# own branch.
FIX_STABLE = (1, 30, 7)
FIX_MAINLINE = (1, 31, 9)


def is_patched(version):
    if version is None:
        return False
    minor = version[1] if len(version) > 1 else 0
    fix = FIX_STABLE if minor % 2 == 0 else FIX_MAINLINE
    return vcmp(version, fix) >= 0


# ---------------------------------------------------------------------------
# network probes
# ---------------------------------------------------------------------------

def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for fam, *_ , sa in infos:
            ip = sa[0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except Exception as e:
        return []


def _connect(host, port, timeout=TIMEOUT):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        return s
    except Exception as e:
        return None


def http1_probe(host, port=80, sni=None):
    r = {"port": port, "open": False, "error": None, "status": None,
         "server": None, "headers": {}}
    s = _connect(host, port)
    if s is None:
        r["error"] = "connection failed"
        return r
    r["open"] = True
    try:
        hdr_host = sni or host
        req = ("GET / HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n"
               "User-Agent: {ua}\r\nAccept: */*\r\n\r\n").format(h=hdr_host, ua=USER_AGENT)
        s.sendall(req.encode("latin-1"))
        data = b""
        while len(data) < 65536:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    except Exception as e:
        r["error"] = str(e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    if data:
        text = data.decode("latin-1", "replace")
        lines = text.split("\r\n")
        m = re.match(r"HTTP/\S+\s+(\d+)", lines[0] if lines else "")
        r["status"] = int(m.group(1)) if m else None
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        r["headers"] = hdrs
        r["server"] = hdrs.get("server")
    return r


def https_probe(host, port=443, sni=None):
    r = {"port": port, "open": False, "error": None, "status": None,
         "server": None, "headers": {}, "tls_version": None, "alpn": None,
         "alt_svc": None}
    s = _connect(host, port)
    if s is None:
        r["error"] = "connection failed (TLS port closed or filtered)"
        return r
    r["open"] = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    hdr_host = sni or host
    try:
        with ctx.wrap_socket(s, server_hostname=hdr_host) as ss:
            r["tls_version"] = ss.version() or None
            try:
                r["alpn"] = ss.selected_alpn_protocol()
            except Exception:
                r["alpn"] = None
            req = ("GET / HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n"
                   "User-Agent: {ua}\r\nAccept: */*\r\n\r\n").format(h=hdr_host, ua=USER_AGENT)
            ss.sendall(req.encode("latin-1"))
            data = b""
            while len(data) < 65536:
                try:
                    chunk = ss.recv(4096)
                except (ssl.SSLError, socket.timeout):
                    break
                if not chunk:
                    break
                data += chunk
    except Exception as e:
        r["error"] = "TLS: " + str(e)
        return r
    if data:
        text = data.decode("latin-1", "replace")
        lines = text.split("\r\n")
        m = re.match(r"HTTP/\S+\s+(\d+)", lines[0] if lines else "")
        r["status"] = int(m.group(1)) if m else None
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        r["headers"] = hdrs
        r["server"] = hdrs.get("server")
        r["alt_svc"] = hdrs.get("alt-svc")
    return r


def h2c_probe(host, port=80):
    """Cleartext HTTP/2 detection: Upgrade h2c + prior-knowledge preface."""
    r = {"upgrade": False, "prior_knowledge": False, "error": None}
    # 1) HTTP/1.1 Upgrade: h2c
    try:
        s = _connect(host, port)
        if s is None:
            r["error"] = "connection failed"
            return r
        req = ("GET / HTTP/1.1\r\nHost: {h}\r\n"
               "Connection: Upgrade, HTTP2-Settings\r\n"
               "Upgrade: h2c\r\nHTTP2-Settings: \r\n\r\n").format(h=host)
        s.sendall(req.encode("latin-1"))
        resp = b""
        try:
            while len(resp) < 4096:
                c = s.recv(1024)
                if not c:
                    break
                resp += c
        except socket.timeout:
            pass
        s.close()
        head = resp.split(b"\r\n")[0]
        low = resp.lower()
        if b" 101 " in head and b"upgrade: h2c" in low:
            r["upgrade"] = True
    except Exception as e:
        r["error"] = str(e)
    # 2) HTTP/2 prior knowledge preface
    try:
        s = _connect(host, port)
        if s is None:
            return r
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        resp = b""
        try:
            while len(resp) < 9:
                c = s.recv(9 - len(resp))
                if not c:
                    break
                resp += c
        except socket.timeout:
            pass
        s.close()
        if len(resp) >= 9 and resp[3] == 0x04:  # SETTINGS frame type
            r["prior_knowledge"] = True
    except Exception:
        pass
    return r


def mail_probe(host):
    results = []
    for port in MAIL_PORTS:
        entry = {"port": port, "open": False, "banner": None}
        try:
            s = socket.create_connection((host, port), timeout=4)
            s.settimeout(4)
            try:
                banner = s.recv(512).decode("latin-1", "replace").strip()
            except socket.timeout:
                banner = "(no banner within timeout)"
            entry["open"] = True
            entry["banner"] = banner[:160]
            s.close()
        except Exception:
            pass
        results.append(entry)
    return results


# ---------------------------------------------------------------------------
# CVE knowledge base
# ---------------------------------------------------------------------------

CVES = [
    {
        "id": "CVE-2026-123007",
        "title": "HTTP/2 flow-control integer overflow → remote code execution",
        "first": (1, 9, 5),
        "fix": (1, 31, 9),
        "key": "h2",
        "requires": "HTTP/2 module compiled in + HTTP/2 listener + externally reachable h2 (ALPN)",
        "blocked_by_h2_off": True,
        "desc": "Send-window accounting error lets an unauthenticated attacker corrupt heap "
                "metadata, leak addresses, and overwrite a cleanup-function pointer to run "
                "commands as the nginx worker. The most severe finding.",
    },
    {
        "id": "CVE-2026-123634",
        "title": "DNS resolver use-after-free (variable proxy_pass + mirror)",
        "first": (1, 13, 4),
        "fix": (1, 31, 9),
        "key": "resolver",
        "requires": "resolver directive + request-derived proxy_pass destination + mirror "
                    "(or SSI subrequests) with mirror_request_body off",
        "blocked_by_h2_off": False,
        "desc": "Use-after-free in the resolver waiting-list when a request-derived upstream "
                "name is resolved while a mirror subrequest shares the lookup.",
    },
    {
        "id": "CVE-2026-123633",
        "title": "HTTP/2 use-after-free with upstream forwarding",
        "first": (1, 19, 7),
        "fix": (1, 31, 9),
        "key": "h2_upstream",
        "requires": "HTTP/2 reachable + requests forwarded to an upstream (backend) server",
        "blocked_by_h2_off": True,
        "desc": "A still-active HTTP/2 connection stays in the reusable queue; a drain during an "
                "upstream connect frees the request while upstream code keeps using it.",
    },
    {
        "id": "CVE-2026-121810",
        "title": "HTTP/3 (QUIC) use-after-free with upstream forwarding",
        "first": (1, 25, 0),
        "fix": (1, 31, 9),
        "key": "h3",
        "requires": "HTTP/3 (QUIC) listener + requests forwarded to an upstream (backend) server",
        "blocked_by_h2_off": False,
        "desc": "Closing a QUIC connection while an HTTP/3 request is still running frees the "
                "request's own memory during an upstream connect.",
    },
    {
        "id": "CVE-2026-113425",
        "title": "Mail proxy auth_http use-after-free",
        "first": (0, 5, 15),
        "fix": (1, 31, 9),
        "key": "mail",
        "requires": "mail{} block with 'proxy on' + 'auth_http' (IMAP/POP3/SMTP fronting)",
        "blocked_by_h2_off": False,
        "desc": "Closing the client connection during an auth_http lookup frees the session while "
                "the auth connection still references it.",
    },
]


# ---------------------------------------------------------------------------
# assessment
# ---------------------------------------------------------------------------

def assess(fp):
    """Return per-CVE verdicts given a fingerprint dict."""
    is_nginx = fp.get("is_nginx", False)
    version = fp.get("version")           # parsed tuple or None
    server_raw = (fp.get("server") or "")
    alpn = fp.get("alpn")                  # None / 'h2' / 'http/1.1'
    https_open = fp.get("https_open", False)
    http_open = fp.get("http_open", False)
    h2c = fp.get("h2c", {})
    alt_svc = fp.get("alt_svc") or ""
    mail_open_any = fp.get("mail_open_any", False)
    cdn_hint = fp.get("cdn_hint")

    h2_reachable = (alpn == "h2")
    h2c_present = bool(h2c.get("upgrade") or h2c.get("prior_knowledge"))
    h3_advertised = bool(re.search(r'\bh3\b', alt_svc, re.I))

    out = []

    for c in CVES:
        verdict = _assess_one(c, is_nginx, version, server_raw, h2_reachable,
                              h2c_present, h3_advertised, https_open,
                              mail_open_any)
        out.append(verdict)

    # SCTP kernel note (informational)
    out.append({
        "id": "SCTP-LPE",
        "title": "Linux kernel SCTP use-after-free (privilege escalation)",
        "status": "info",
        "reason": "Cannot be assessed remotely. This is a chained post-exploitation step: it "
                  "requires local code execution first (e.g. via an nginx CVE above). If any nginx "
                  "RCE verdict is vulnerable, assume this is in play on kernels >= 4.15. "
                  "Mitigation: 'install sctp /bin/false' under /etc/modprobe.d/ on hosts that don't need SCTP.",
    })
    return out


def _assess_one(c, is_nginx, version, server_raw, h2_reachable, h2c_present,
                h3_advertised, https_open, mail_open_any):
    cid = c["id"]
    first = c["first"]
    base = {"id": cid, "title": c["title"], "requires": c["requires"], "desc": c["desc"]}

    if not is_nginx:
        base.update(status="not_affected",
                    reason="Target does not identify as nginx (Server: %r). nginx2root only "
                           "applies to nginx." % server_raw)
        return base

    if version is None:
        base.update(status="inconclusive",
                    reason="nginx detected but version could not be parsed from the banner "
                           "(%r). Cannot confirm affected range." % server_raw)
        return base

    # patched / before range / in range
    if is_patched(version):
        base.update(status="patched",
                    reason="nginx %s is >= the fixed release in its branch (1.30.7 stable / "
                           "1.31.9 mainline). Patched against this CVE." %
                           ".".join(map(str, version)))
        return base

    if vcmp(version, first) < 0:
        base.update(status="not_affected",
                    reason="nginx %s predates the first affected release %s." %
                           (".".join(map(str, version)), ".".join(map(str, first))))
        return base

    # in affected range — now depends on the specific feature signal
    vstr = ".".join(map(str, version))
    if cid == "CVE-2026-123007":
        if h2_reachable:
            base.update(status="vulnerable",
                        reason="nginx %s is in the affected range (1.9.5–1.31.8) AND HTTP/2 "
                               "negotiates externally (ALPN h2). All exposure conditions met from "
                               "outside. Treat as exposed unless a vendor backport is confirmed." % vstr)
        elif h2c_present:
            base.update(status="likely",
                        reason="nginx %s is in range and cleartext HTTP/2 (h2c) is present, but "
                               "TLS ALPN did not negotiate h2. HTTP/2 code path exists." % vstr)
        elif https_open:
            base.update(status="mitigated",
                        reason="nginx %s is in range but HTTP/2 is NOT negotiated on the HTTPS "
                               "listener (ALPN negotiated %s). Vulnerable code likely present, "
                               "current attack path disabled." % (vstr, "http/1.1"))
        else:
            base.update(status="inconclusive",
                        reason="nginx %s is in range but the HTTPS listener is unreachable, so "
                               "external HTTP/2 could not be tested." % vstr)
    elif cid == "CVE-2026-123633":
        if h2_reachable:
            base.update(status="likely",
                        reason="nginx %s (>= 1.19.7) with HTTP/2 reachable. Vulnerable IF this "
                               "server forwards requests to an upstream/backend (proxy_pass). "
                               "Upstream forwarding cannot be confirmed from outside." % vstr)
        else:
            base.update(status="not_affected",
                        reason="HTTP/2 is not externally reachable, so this HTTP/2-only path is "
                               "not exposed.")
    elif cid == "CVE-2026-121810":
        if h3_advertised:
            base.update(status="likely",
                        reason="nginx %s (>= 1.25.0) advertises HTTP/3 (Alt-Svc h3). Vulnerable IF "
                               "HTTP/3 requests are forwarded to an upstream. Confirm QUIC listener "
                               "and proxy_pass from config." % vstr)
        else:
            base.update(status="not_affected",
                        reason="No HTTP/3 (h3) advertisement detected, so the QUIC-only path is "
                               "not exposed.")
    elif cid == "CVE-2026-123634":
        base.update(status="inconclusive",
                    reason="nginx %s (>= 1.13.4). Requires resolver + request-derived proxy_pass + "
                           "mirror (or SSI). Not detectable from outside — review the target's "
                           "nginx config for these directives." % vstr)
    elif cid == "CVE-2026-113425":
        if mail_open_any:
            base.update(status="likely",
                        reason="nginx %s (>= 0.5.15) with mail proxy ports listening. Vulnerable IF "
                               "the mail{} block uses 'proxy on' + 'auth_http'. Review mail config." % vstr)
        else:
            base.update(status="not_affected",
                        reason="No nginx mail-proxy ports (25/110/143/465/587/993/995) detected "
                               "as open, so the mail auth_http path is not exposed.")
    else:
        base.update(status="inconclusive", reason="Review required.")
    return base


# ---------------------------------------------------------------------------
# top-level scan
# ---------------------------------------------------------------------------

def normalize_target(target):
    t = (target or "").strip()
    if not t:
        return None
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split("@")[-1]
    t = t.split(":")[0] if t.count(":") == 1 and not t.startswith("[") else t
    t = t.strip("[]")
    return t or None


def run_scan(target):
    host = normalize_target(target)
    started = time.time()
    if not host:
        return {"error": "Could not parse target", "target": target}

    ips = resolve(host)

    # HTTP / HTTPS / h2c / mail in a sensible order
    http = http1_probe(host, 80)
    https = https_probe(host, 443)
    h2c = h2c_probe(host, 80)
    mail = mail_probe(host)

    server_raw = https.get("server") or http.get("server") or ""
    is_nginx = bool(re.search(r"nginx", server_raw, re.I))
    version = parse_version(server_raw) if is_nginx else None

    mail_open_any = any(m["open"] for m in mail)
    mail_open = [m for m in mail if m["open"]]

    # CDN / edge hint
    cdn_hint = None
    low = server_raw.lower()
    for edge in ["vercel", "cloudflare", "cloudfront", "fastly", "akamai", "netlify", "fly", "heroku"]:
        if edge in low:
            cdn_hint = ("Response appears to come from an edge/CDN (%s). The ALPN and Server "
                        "header reflect the edge, not your origin. If your origin runs nginx, "
                        "scan the origin host directly." % server_raw)
            break

    fp = {
        "host": host,
        "resolved_ips": ips,
        "server": server_raw,
        "is_nginx": is_nginx,
        "version": version,
        "version_str": ".".join(map(str, version)) if version else None,
        "http_open": http.get("open", False),
        "http_status": http.get("status"),
        "https_open": https.get("open", False),
        "https_status": https.get("status"),
        "tls_version": https.get("tls_version"),
        "alpn": https.get("alpn"),
        "alt_svc": https.get("alt_svc"),
        "h2c": h2c,
        "mail": mail,
        "mail_open_any": mail_open_any,
        "mail_open": mail_open,
        "cdn_hint": cdn_hint,
        "http_headers": http.get("headers", {}),
        "https_headers": https.get("headers", {}),
        "http_error": http.get("error"),
        "https_error": https.get("error"),
    }

    verdicts = assess(fp)

    # overall risk
    order = {"vulnerable": 4, "likely": 3, "mitigated": 2, "inconclusive": 2,
             "not_affected": 0, "patched": 0, "info": 0}
    top = max((v["status"] for v in verdicts), key=lambda s: order.get(s, 0))
    overall = {
        "vulnerable": "VULNERABLE — immediate action required",
        "likely": "LIKELY VULNERABLE — confirm config, then patch",
        "mitigated": "PATCH PENDING — vulnerable code present but path disabled",
        "inconclusive": "INCONCLUSIVE — further review required",
        "not_affected": "NOT AFFECTED — no nginx2root exposure detected",
        "patched": "PATCHED — no nginx2root exposure detected",
        "info": "NO EXPOSURE DETECTED",
    }[top]

    return {
        "target": target,
        "host": host,
        "started_at": started,
        "finished_at": time.time(),
        "fingerprint": fp,
        "verdicts": verdicts,
        "overall": overall,
        "overall_status": top,
    }


if __name__ == "__main__":
    import json
    for t in __import__("sys").argv[1:]:
        print(json.dumps(run_scan(t), indent=2))
