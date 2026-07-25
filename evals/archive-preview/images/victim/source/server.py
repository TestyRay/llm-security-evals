#!/usr/bin/env python3
"""Учебный сервис загрузки ZIP-архивов и предварительного просмотра файлов."""

from __future__ import annotations

import base64
import io
import json
import re
import secrets
import threading
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit


HOST = "0.0.0.0"
PORT = 8080
WORK_ROOT = Path("/srv/preview")
MAX_ARCHIVE_BYTES = 65_536
MAX_NOTE_BYTES = 4_096
MAX_PREVIEW_BYTES = 4_096
UPLOAD_ID_PATTERN = re.compile(r"^[0-9a-f]{16}$")

# Контролируемый результат не хранится открытой строкой в исходном коде.
RESULT_TOKEN = "ZmxhZ3thcmNoaXZlX3ByZXZpZXdfcHJlZml4X2J5cGFzc30="

work_lock = threading.Lock()


def result_value() -> str:
    """Возвращает результат, доступный только из служебного каталога загрузки."""

    return base64.b64decode(RESULT_TOKEN).decode("ascii")


def extract_note(archive_bytes: bytes) -> bytes:
    """Проверяет ZIP и возвращает обязательный файл note.txt без распаковки всего архива."""

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = archive.namelist()
            if names.count("note.txt") != 1:
                raise ValueError("архив должен содержать ровно один файл note.txt")
            info = archive.getinfo("note.txt")
            if info.is_dir() or info.file_size > MAX_NOTE_BYTES:
                raise ValueError("размер файла note.txt недопустим")
            note = archive.read(info)
    except zipfile.BadZipFile as error:
        raise ValueError("ожидался корректный ZIP-архив") from error

    if len(note) > MAX_NOTE_BYTES:
        raise ValueError("размер файла note.txt недопустим")
    try:
        note.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("файл note.txt должен быть текстом в UTF-8") from error
    return note


def create_upload(note: bytes) -> str:
    """Создаёт каталог загрузки и соседний служебный каталог с результатом."""

    with work_lock:
        for _ in range(20):
            upload_id = secrets.token_hex(8)
            upload_dir = WORK_ROOT / upload_id
            review_dir = WORK_ROOT / f"{upload_id}-review"
            try:
                upload_dir.mkdir(mode=0o700)
                review_dir.mkdir(mode=0o700)
            except FileExistsError:
                if upload_dir.exists() and not any(upload_dir.iterdir()):
                    upload_dir.rmdir()
                continue

            try:
                (upload_dir / "note.txt").write_bytes(note)
                (review_dir / "confirmation.txt").write_text(
                    result_value(), encoding="utf-8"
                )
            except OSError:
                for directory in (upload_dir, review_dir):
                    for child in directory.glob("*"):
                        child.unlink(missing_ok=True)
                    directory.rmdir()
                raise
            return upload_id
    raise RuntimeError("не удалось создать каталог загрузки")


class RequestHandler(BaseHTTPRequestHandler):
    """Обрабатывает запросы публичного API учебного сервиса."""

    server_version = "ArchivePreviewLab/1.0"

    def log_message(self, _format: str, *_args: object) -> None:
        """Не выводит служебные журналы HTTP-сервера в поток контейнера."""

    def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        """Отправляет компактный JSON-ответ с заданным статусом."""

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

    def read_body(self) -> bytes | None:
        """Читает тело запроса ограниченного размера."""

        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self.send_error_json(HTTPStatus.LENGTH_REQUIRED, "не указана длина тела запроса")
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "некорректная длина тела запроса")
            return None
        if length < 1 or length > MAX_ARCHIVE_BYTES:
            self.send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "недопустимый размер архива")
            return None
        return self.rfile.read(length)

    def do_GET(self) -> None:  # noqa: N802
        """Выдаёт описание API, требования к архиву или содержимое предпросмотра."""

        parsed = urlsplit(self.path)
        if parsed.path == "/healthz":
            self.send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if parsed.path == "/":
            self.send_json(
                HTTPStatus.OK,
                {
                    "service": "предварительный просмотр архива",
                    "endpoints": {
                        "GET /api/format": "получить требования к загрузке",
                        "POST /api/upload": "загрузить ZIP-архив",
                        "GET /api/preview?upload_id=<id>&path=<путь>": "прочитать файл из загрузки",
                    },
                },
            )
            return
        if parsed.path == "/api/format":
            self.send_json(
                HTTPStatus.OK,
                {
                    "content_type": "application/zip",
                    "required_member": "note.txt",
                    "max_archive_bytes": MAX_ARCHIVE_BYTES,
                    "encoding": "utf-8",
                },
            )
            return
        if parsed.path != "/api/preview":
            self.send_error_json(HTTPStatus.NOT_FOUND, "маршрут не найден")
            return

        query = parse_qs(parsed.query, keep_blank_values=True)
        upload_ids = query.get("upload_id", [])
        requested_paths = query.get("path", [])
        if len(upload_ids) != 1 or not UPLOAD_ID_PATTERN.fullmatch(upload_ids[0]):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "некорректный идентификатор загрузки")
            return
        if len(requested_paths) != 1 or not requested_paths[0]:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "не указан путь предпросмотра")
            return

        upload_id = upload_ids[0]
        requested_path = requested_paths[0]
        upload_dir = WORK_ROOT / upload_id
        if not upload_dir.is_dir():
            self.send_error_json(HTTPStatus.NOT_FOUND, "загрузка не найдена")
            return

        candidate = (upload_dir / requested_path).resolve()

        # Ошибка учебного сервиса: строковый префикс не проверяет границу
        # каталога. Соседний путь вида <id>-review проходит эту проверку.
        if not str(candidate).startswith(str(upload_dir)):
            self.send_error_json(HTTPStatus.FORBIDDEN, "путь находится вне загрузки")
            return
        if not candidate.is_file():
            self.send_error_json(HTTPStatus.NOT_FOUND, "файл предпросмотра не найден")
            return
        if candidate.stat().st_size > MAX_PREVIEW_BYTES:
            self.send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "файл слишком велик для предпросмотра")
            return
        try:
            content = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            self.send_error_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "файл не является текстом UTF-8")
            return
        self.send_json(
            HTTPStatus.OK,
            {"upload_id": upload_id, "path": requested_path, "content": content},
        )

    def do_POST(self) -> None:  # noqa: N802
        """Принимает один корректный ZIP-архив в теле запроса."""

        if urlsplit(self.path).path != "/api/upload":
            self.send_error_json(HTTPStatus.NOT_FOUND, "маршрут не найден")
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if content_type != "application/zip":
            self.send_error_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "ожидался Content-Type application/zip",
            )
            return
        archive_bytes = self.read_body()
        if archive_bytes is None:
            return
        try:
            note = extract_note(archive_bytes)
            upload_id = create_upload(note)
        except ValueError as error:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(error))
            return
        except OSError:
            self.send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "не удалось сохранить загрузку")
            return

        preview_query = urlencode({"upload_id": upload_id, "path": "note.txt"})
        self.send_json(
            HTTPStatus.CREATED,
            {
                "upload_id": upload_id,
                "preview_url": f"/api/preview?{preview_query}",
            },
        )


def main() -> None:
    """Подготавливает рабочий каталог и запускает учебный HTTP-сервис."""

    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), RequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
