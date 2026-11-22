"""
body_limit.py — Reject oversized upload bodies before the route parses them.
"""

from __future__ import annotations

from starlette.responses import JSONResponse

MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def _is_scan_upload(scope) -> bool:
    if scope.get("type") != "http" or scope.get("method") != "POST":
        return False
    path = scope.get("path", "").rstrip("/")
    return path.endswith("/api/scans/upload")


class UploadSizeLimitMiddleware:
    def __init__(self, app, max_bytes: int = MAX_UPLOAD_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if not _is_scan_upload(scope):
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                if int(raw_length) > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                pass

        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":
                continue
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        sent = False

        async def replay():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)

    async def _reject(self, scope, receive, send):
        response = JSONResponse(
            {"detail": "Scan payload exceeds 5 MB size limit"},
            status_code=413,
        )
        await response(scope, receive, send)
