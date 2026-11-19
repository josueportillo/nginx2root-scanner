#!/usr/bin/env python3
"""nginx2root scanner — stdlib-only web server (no pip dependencies)."""

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import scanner

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "scans.db")
STATIC = os.path.join(BASE, "static")
HOST = "0.0.0.0"
PORT = int(os.environ.get("NGINX2ROOT_PORT", "8095"))


def get_db():
    con = sqlite3.connect(DB, timeout=30)
    con.execute(
        "CREATE TABLE IF NOT EXISTS scans ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "target TEXT, started_at REAL, finished_at REAL, result_json TEXT)"
    )
    con.commit()
    return con


def save_scan(result):
    con = get_db()
    cur = con.execute(
        "INSERT INTO scans (target, started_at, finished_at, result_json) VALUES (?,?,?,?)",
        (result.get("target"), result.get("started_at"),
         result.get("finished_at"), json.dumps(result)),
    )
    con.commit()
    scan_id = cur.lastrowid
    con.close()
    return scan_id


def list_scans():
    con = get_db()
    rows = con.execute(
        "SELECT id, target, started_at, finished_at, result_json FROM scans "
        "ORDER BY id DESC LIMIT 100"
    ).fetchall()
    con.close()
    out = []
    for rid, target, started, finished, blob in rows:
        try:
            r = json.loads(blob)
            overall = r.get("overall_status", "unknown")
        except Exception:
            overall = "unknown"
        out.append({"id": rid, "target": target, "overall_status": overall,
                    "started_at": started})
    return out


def get_scan(scan_id):
    con = get_db()
    row = con.execute("SELECT result_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    return json.loads(row[0]) if row else None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            fp = os.path.join(STATIC, "index.html")
            if os.path.exists(fp):
                with open(fp, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
                return
            self._send(404, "not found", "text/plain")
        elif path == "/api/history":
            self._json(200, {"scans": list_scans()})
        elif path.startswith("/api/scan/"):
            try:
                scan_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                self._json(400, {"error": "bad id"})
                return
            r = get_scan(scan_id)
            self._json(200, r if r else {"error": "not found"})
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/scan":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}
        target = (payload.get("target") or "").strip()
        if not target:
            self._json(400, {"error": "target is required"})
            return
        result = scanner.run_scan(target)
        result["id"] = save_scan(result)
        self._json(200, result)

    def log_message(self, *args):
        pass


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def main():
    srv = ReusableThreadingHTTPServer((HOST, PORT), Handler)
    print("nginx2root scanner listening on http://%s:%d" % (HOST, PORT), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
