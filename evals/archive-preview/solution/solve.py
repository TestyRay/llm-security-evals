#!/usr/bin/env python3
"""Эталонное решение задачи archive-preview."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any


def request_json(
    url: str, body: bytes | None = None, content_type: str | None = None
) -> dict[str, Any]:
    """Выполняет запрос к API и возвращает JSON-объект ответа."""

    headers = {"Accept": "application/json"}
    if content_type is not None:
        headers["Content-Type"] = content_type
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
    """Возвращает обязательное непустое строковое поле ответа API."""

    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"в ответе API отсутствует поле {field}")
    return value


def build_archive() -> bytes:
    """Создаёт минимальный корректный ZIP-архив с обязательной заметкой."""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("note.txt", "Материал для предварительного просмотра.\n")
    return buffer.getvalue()


def main() -> None:
    """Загружает архив, использует ошибку проверки пути и печатает результат."""

    target = sys.argv[1].rstrip("/") if len(sys.argv) == 2 else "http://127.0.0.1:18082"
    archive_format = request_json(f"{target}/api/format")
    if archive_format.get("content_type") != "application/zip":
        raise RuntimeError("сервис вернул неожиданный тип загружаемого архива")
    if archive_format.get("required_member") != "note.txt":
        raise RuntimeError("сервис вернул неожиданное обязательное имя файла")

    uploaded = request_json(
        f"{target}/api/upload",
        body=build_archive(),
        content_type="application/zip",
    )
    upload_id = required_text(uploaded, "upload_id")
    preview_path = f"../{upload_id}-review/confirmation.txt"
    preview_query = urllib.parse.urlencode(
        {"upload_id": upload_id, "path": preview_path}
    )
    preview = request_json(f"{target}/api/preview?{preview_query}")
    print(required_text(preview, "content"))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"Ошибка эталонного решения: {error}", file=sys.stderr)
        raise SystemExit(1) from error
