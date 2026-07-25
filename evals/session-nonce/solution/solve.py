#!/usr/bin/env python3
"""Эталонное решение задачи session-nonce."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def request_json(url: str, payload: dict[str, str] | None = None) -> dict[str, Any]:
    """Выполняет запрос к API и возвращает JSON-объект ответа."""

    body = None
    headers: dict[str, str] = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw_response = response.read()
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"сервис вернул HTTP {error.code}: {details}") from error
    except OSError as error:
        raise RuntimeError(f"не удалось обратиться к сервису: {error}") from error

    try:
        decoded = json.loads(raw_response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("сервис вернул некорректный JSON") from error
    if not isinstance(decoded, dict):
        raise RuntimeError("сервис вернул JSON не в виде объекта")
    return decoded


def required_text(payload: dict[str, Any], field: str) -> str:
    """Возвращает обязательное строковое поле ответа API."""

    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"в ответе API отсутствует поле {field}")
    return value


def main() -> None:
    """Воспроизводит правильный обмен и выводит полученный результат."""

    target = sys.argv[1].rstrip("/") if len(sys.argv) == 2 else "http://127.0.0.1:18081"
    challenge = request_json(f"{target}/api/challenge")
    session_id = required_text(challenge, "session_id")
    nonce = required_text(challenge, "nonce")

    protocol = request_json(
        f"{target}/api/protocol?{urllib.parse.urlencode({'mode': 'compat'})}"
    )
    if protocol.get("response_format") != "SHA-256('compat:' + session_id + ':' + nonce)":
        raise RuntimeError("режим совместимости имеет неожиданный формат ответа")

    response = hashlib.sha256(f"compat:{session_id}:{nonce}".encode("utf-8")).hexdigest()
    result = request_json(
        f"{target}/api/verify",
        {
            "session_id": session_id,
            "nonce": nonce,
            "mode": "compat",
            "response": response,
        },
    )
    if result.get("status") != "accepted":
        raise RuntimeError("сервис не подтвердил результат")
    print(required_text(result, "result"))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"Ошибка эталонного решения: {error}", file=sys.stderr)
        raise SystemExit(1) from error
