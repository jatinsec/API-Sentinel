# API Security Assessment — API-Sentinel demo lab API (127.0.0.1:8765)

**Tester:** Jatin Patidar  
**Created:** 2026-10-28T00:00:00Z  
**Test cases recorded:** 4

> This report records only what was actually tested. A check with no recorded test case
> is not covered by this assessment and is not implied to be secure.

| Check | Category | OWASP | Endpoint | Result | Evidence |
|---|---|---|---|---|---|
| AUTH-01 — Endpoint rejects requests with no credentials | Authentication | API2:2023 | `GET /orders/1` | **PASS** | curl -i http://127.0.0.1:8765/orders/1 -> HTTP/1.0 401 |
| BOLA-01 — Requesting another user's object ID returns 403/404, not the object | Broken Object Level Authorization | API1:2023 | `GET /orders/1` | **FAIL** | curl -H 'Authorization: Bearer bob-token' http://127.0.0.1:8765/orders/1 -> HTTP/1.0 200, body includes owner_id=1 while caller is user_id=2 |
| BFLA-01 — Low-privilege account cannot call admin/staff-only endpoints | Broken Function Level Authorization | API5:2023 | `GET /admin/stats` | **FAIL** | curl -H 'Authorization: Bearer bob-token' http://127.0.0.1:8765/admin/stats -> HTTP/1.0 200 |
| MISCONFIG-02 — CORS does not reflect arbitrary Origin with credentials allowed | Security Misconfiguration | API8:2023 | `GET /me` | **NOT_APPLICABLE** | demo_api.py has no CORS handling code path |

## Findings (result = FAIL)

### BOLA-01 — Requesting another user's object ID returns 403/404, not the object
- **Endpoint:** `GET /orders/1`
- **Expected:** 403 Forbidden when Bob's token requests Alice's order (owner_id=1)
- **Actual:** 200 OK, full order body returned: {"order_id":1,"owner_id":1,"item":"widget","total":19.99}
- **Evidence:** curl -H 'Authorization: Bearer bob-token' http://127.0.0.1:8765/orders/1 -> HTTP/1.0 200, body includes owner_id=1 while caller is user_id=2

### BFLA-01 — Low-privilege account cannot call admin/staff-only endpoints
- **Endpoint:** `GET /admin/stats`
- **Expected:** 403 Forbidden for a non-admin token
- **Actual:** 200 OK, admin stats returned to a 'user' role token
- **Evidence:** curl -H 'Authorization: Bearer bob-token' http://127.0.0.1:8765/admin/stats -> HTTP/1.0 200

