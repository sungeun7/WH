from __future__ import annotations

import os
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

load_dotenv()

ENGINE_URL = os.getenv("ENGINE_URL", "http://127.0.0.1:8000").rstrip("/")
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "").rstrip("/")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8080"))

app = FastAPI(title="WH HTTP Gateway")


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def inspect(request: Request, path: str, event_type: str = "request") -> dict[str, Any]:
    payload = {
        "client_ip": client_ip(request),
        "method": request.method,
        "path": "/" + path.lstrip("/"),
        "has_auth": "authorization" in request.headers,
        "user_agent": request.headers.get("user-agent", ""),
        "event_type": event_type,
    }
    if payload["path"] == "/":
        payload["path"] = "/"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.post(f"{ENGINE_URL}/api/v1/gateway/inspect", json=payload)
            res.raise_for_status()
            return res.json()
    except Exception:
        return {"allow": True, "status": 200, "reason": "engine_unavailable"}


def blocked_response(decision: dict[str, Any]) -> JSONResponse:
    status = int(decision.get("status") or 403)
    return JSONResponse(
        {
            "error": "blocked_by_wh",
            "reason": decision.get("reason"),
            "message": "화이트햇 방어 엔진이 이 요청을 차단했습니다.",
        },
        status_code=status,
    )


@app.get("/gateway/health")
def gateway_health() -> dict[str, str]:
    return {"ok": "true", "role": "http-gateway"}


@app.post("/login")
async def login(request: Request) -> JSONResponse:
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    user = str(body.get("user") or "")
    password = str(body.get("password") or "")
    if user == "demo" and password == "demo":
        decision = await inspect(request, "/login", "request")
        if not decision.get("allow", True):
            return blocked_response(decision)
        return JSONResponse({"ok": True, "token": "demo-session"})
    decision = await inspect(request, "/login", "auth_fail")
    if not decision.get("allow", True):
        return blocked_response(decision)
    return JSONResponse({"ok": False, "error": "invalid_credentials"}, status_code=401)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def catch_all(path: str, request: Request):
    decision = await inspect(request, path or "/", "request")
    if not decision.get("allow", True):
        return blocked_response(decision)

    if UPSTREAM_URL:
        url = f"{UPSTREAM_URL}/{path}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream = await client.request(
                request.method,
                url,
                params=request.query_params,
                content=await request.body(),
                headers={k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}},
            )
        return JSONResponse(
            content=upstream.json() if "application/json" in upstream.headers.get("content-type", "") else {"raw": upstream.text},
            status_code=upstream.status_code,
        )

    normalized = "/" + path.lstrip("/")
    if normalized in {"/", ""}:
        return {
            "app": "wh-protected-demo",
            "status": "ok",
            "hint": "이 게이트웨이 뒤의 데모 앱입니다.",
        }
    if normalized == "/health":
        return {"status": "ok"}
    if normalized == "/api/items":
        return {"items": [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}]}
    if normalized.startswith("/admin"):
        if "authorization" not in request.headers:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return {"admin": True, "ok": True}
    return JSONResponse({"error": "not_found"}, status_code=404)


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=GATEWAY_PORT, reload=False)


if __name__ == "__main__":
    run()
