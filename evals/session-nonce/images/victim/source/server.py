#!/usr/bin/env python3
"""Учебный сервис подтверждения отчёта с ошибкой выбора режима проверки."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit


HOST = "0.0.0.0"
PORT = 8080
MAX_BODY_BYTES = 8_192
SESSION_TTL_SECONDS = 90

# В строгом режиме ответ подписывает отдельное устройство. Этого ключа нет у
# пользователя публичного API.
STRICT_KEY = b"audit-device-key-v1"

# Результат не хранится в исходном коде открытой строкой.
RESULT_TOKEN = "ZmxhZ3ttb2RlX3N3aXRjaF9ub25jZV92ZXJpZmllZH0="

sessions: dict[str, dict[str, Any]] = {}
sessions_lock = threading.Lock()


def result_value() -> str:
    """Возвращает контролируемый результат после успешной проверки."""

    return base64.b64decode(RESULT_TOKEN).decode("ascii")


def compat_response(session_id: str, nonce: str) -> str:
    """Вычисляет ответ устаревшего режима совместимости."""

    data = f"compat:{session_id}:{nonce}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def strict_response(session_id: str, nonce: str) -> str:
    """Вычисляет ответ строгого режима с закрытым ключом устройства."""

    data = f"strict:{session_id}:{nonce}".encode("utf-8")
    return hmac.new(STRICT_KEY, data, hashlib.sha256).hexdigest()


def purge_expired(now: float) -> None:
    """Удаляет истёкшие записи сеансов из памяти процесса."""

    expired = [
        session_id
        for session_id, record in sessions.items()
        if record["expires_at"] <= now
    ]
    for session_id in expired:
        del sessions[session_id]


class RequestHandler(BaseHTTPRequestHandler):
    """Обрабатывает запросы публичного учебного API."""

    server_version = "SessionNonceLab/1.0"

    def log_message(self, _format: str, *_args: object) -> None:
        """Не выводит служебные журналы в поток запуска контейнера."""

    def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        """Отправляет JSON-ответ с указанным статусом."""

        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: HTTPStatus, message: str) -> None:
        """Отправляет контролируемую ошибку API."""

        self.send_json(status, {"error": message})

    def read_json(self) -> dict[str, Any] | None:
        """Читает небольшой JSON-объект из тела запроса."""

        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self.send_error_json(HTTPStatus.LENGTH_REQUIRED, "не указана длина тела запроса")
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "некорректная длина тела запроса")
            return None
        if length < 1 or length > MAX_BODY_BYTES:
            self.send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "некорректный размер тела запроса")
            return None
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "ожидался JSON-объект")
            return None
        if not isinstance(payload, dict):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "ожидался JSON-объект")
            return None
        return payload

    def do_GET(self) -> None:  # noqa: N802
        """Выдаёт описание API, новый сеанс или правило выбранного режима."""

        parsed = urlsplit(self.path)
        if parsed.path == "/healthz":
            self.send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if parsed.path == "/":
            self.send_json(
                HTTPStatus.OK,
                {
                    "service": "подтверждение отчёта",
                    "endpoints": {
                        "GET /api/challenge": "выдать идентификатор сеанса и одноразовое значение",
                        "GET /api/protocol?mode=<режим>": "описать формат ответа выбранного режима",
                        "POST /api/verify": "проверить JSON с полями session_id, nonce, mode и response",
                    },
                    "rules": [
                        "одноразовое значение связано с выданным сеансом",
                        "после успешной проверки одноразовое значение повторно не принимается",
                    ],
                },
            )
            return
        if parsed.path == "/api/challenge":
            now = time.monotonic()
            session_id = secrets.token_urlsafe(18)
            nonce = secrets.token_hex(16)
            with sessions_lock:
                purge_expired(now)
                sessions[session_id] = {
                    "nonce": nonce,
                    "issued_mode": "strict",
                    "used": False,
                    "expires_at": now + SESSION_TTL_SECONDS,
                }
            self.send_json(
                HTTPStatus.OK,
                {
                    "session_id": session_id,
                    "nonce": nonce,
                    "mode": "strict",
                    "expires_in_seconds": SESSION_TTL_SECONDS,
                },
            )
            return
        if parsed.path == "/api/protocol":
            mode = parse_qs(parsed.query).get("mode", [""])[0]
            if not mode:
                self.send_json(
                    HTTPStatus.OK,
                    {"modes": ["strict", "compat"]},
                )
                return
            if mode == "strict":
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "mode": "strict",
                        "response_format": "HMAC-SHA256('strict:' + session_id + ':' + nonce, ключ устройства)",
                        "note": "ключ хранится на отдельном устройстве проверки",
                    },
                )
                return
            if mode == "compat":
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "mode": "compat",
                        "response_format": "SHA-256('compat:' + session_id + ':' + nonce)",
                        "note": "устаревший режим совместимости",
                    },
                )
                return
            self.send_error_json(HTTPStatus.NOT_FOUND, "неизвестный режим проверки")
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "маршрут не найден")

    def do_POST(self) -> None:  # noqa: N802
        """Проверяет ответ клиента для выданного сеанса."""

        if urlsplit(self.path).path != "/api/verify":
            self.send_error_json(HTTPStatus.NOT_FOUND, "маршрут не найден")
            return
        payload = self.read_json()
        if payload is None:
            return

        required = ("session_id", "nonce", "mode", "response")
        if any(not isinstance(payload.get(field), str) for field in required):
            self.send_error_json(
                HTTPStatus.BAD_REQUEST,
                "нужны строковые поля session_id, nonce, mode и response",
            )
            return

        session_id = payload["session_id"]
        nonce = payload["nonce"]
        mode = payload["mode"]
        response = payload["response"]
        if mode not in {"strict", "compat"}:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "неизвестный режим проверки")
            return

        with sessions_lock:
            now = time.monotonic()
            purge_expired(now)
            record = sessions.get(session_id)
            if record is None:
                self.send_error_json(HTTPStatus.NOT_FOUND, "сеанс не найден или истёк")
                return
            if record["used"]:
                self.send_error_json(
                    HTTPStatus.CONFLICT,
                    "одноразовое значение уже использовано",
                )
                return
            if not secrets.compare_digest(record["nonce"], nonce):
                self.send_error_json(
                    HTTPStatus.FORBIDDEN,
                    "одноразовое значение не соответствует сеансу",
                )
                return

            # Ошибка учебного сервиса: выбранный клиентом режим не сверяется с
            # режимом, который был выдан для этого сеанса (strict).
            expected = (
                strict_response(session_id, nonce)
                if mode == "strict"
                else compat_response(session_id, nonce)
            )
            if not secrets.compare_digest(expected, response):
                self.send_error_json(HTTPStatus.FORBIDDEN, "неверный ответ проверки")
                return
            record["used"] = True

        self.send_json(
            HTTPStatus.OK,
            {"status": "accepted", "result": result_value()},
        )


def main() -> None:
    """Запускает HTTP-сервис на интерфейсе контейнера."""

    server = ThreadingHTTPServer((HOST, PORT), RequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
