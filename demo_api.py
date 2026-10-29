#!/usr/bin/env python3
"""
API-Sentinel demo lab API — LOCAL, LAB-ONLY, deliberately includes two
realistic API security defects so the toolkit has something real to test
against. This is not a product and must never be exposed beyond localhost.

Resources (in-memory, reset on restart):
  GET /me                 -> caller's own profile (correctly scoped)
  GET /orders/<id>         -> an order (DELIBERATELY vulnerable: no ownership
                              check — any valid token can read any order = BOLA)
  GET /admin/stats         -> admin-only stats (DELIBERATELY vulnerable: any
                              valid token is accepted, not just admin = BFLA)

Auth: a fake bearer token in the `Authorization: Bearer <token>` header.
Valid demo tokens: "alice-token" (user), "bob-token" (user), "admin-token" (admin).
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {
    "alice-token": {"user_id": 1, "username": "alice", "role": "user"},
    "bob-token": {"user_id": 2, "username": "bob", "role": "user"},
    "admin-token": {"user_id": 99, "username": "root_admin", "role": "admin"},
}

ORDERS = {
    1: {"order_id": 1, "owner_id": 1, "item": "widget", "total": 19.99},
    2: {"order_id": 2, "owner_id": 2, "item": "gadget", "total": 49.99},
}


def _auth(handler: "Handler") -> dict | None:
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[len("Bearer "):].strip()
    return USERS.get(token)


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # quiet test runs
        pass

    def do_GET(self) -> None:
        user = _auth(self)

        if self.path == "/me":
            if not user:
                self._send_json(401, {"error": "unauthenticated"})
                return
            self._send_json(200, user)
            return

        if self.path.startswith("/orders/"):
            if not user:
                self._send_json(401, {"error": "unauthenticated"})
                return
            try:
                order_id = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                self._send_json(400, {"error": "bad order id"})
                return
            order = ORDERS.get(order_id)
            if not order:
                self._send_json(404, {"error": "not found"})
                return
            # --- VULNERABLE BY DESIGN: no check that order["owner_id"] == user["user_id"] ---
            # A correct implementation would be:
            #   if order["owner_id"] != user["user_id"] and user["role"] != "admin":
            #       self._send_json(403, {"error": "forbidden"}); return
            self._send_json(200, order)
            return

        if self.path == "/admin/stats":
            if not user:
                self._send_json(401, {"error": "unauthenticated"})
                return
            # --- VULNERABLE BY DESIGN: no role check, any authenticated user gets admin data ---
            self._send_json(200, {"total_orders": len(ORDERS), "total_users": len(USERS)})
            return

        self._send_json(404, {"error": "no such route"})


def run(port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return server


if __name__ == "__main__":
    srv = run()
    print(f"[demo_api] LAB-ONLY API listening on http://127.0.0.1:{srv.server_address[1]} — Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
