#!/usr/bin/env python3
import http.client
import ipaddress
import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_to_bytes, urlsplit


MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
CONNECT_TIMEOUT_SECONDS = 2
READ_IDLE_TIMEOUT_SECONDS = 0.5
INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)


def is_internal_address(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        address.is_loopback
        or address.is_link_local
        or any(
            address.version == network.version and address in network
            for network in INTERNAL_NETWORKS
        )
    )


def resolve_internal_target(host, port):
    candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not candidates:
        raise OSError("не удалось определить адрес целевого сервиса")

    validated = []
    for family, socket_type, protocol, _, socket_address in candidates:
        address_text = socket_address[0].split("%", 1)[0]
        address = ipaddress.ip_address(address_text)
        if not is_internal_address(address):
            raise ValueError("доступ разрешён только к внутренним адресам")
        validated.append((family, socket_type, protocol, socket_address))
    return validated[0]


def open_internal_connection(host, port):
    family, socket_type, protocol, socket_address = resolve_internal_target(host, port)
    connection = socket.socket(family, socket_type, protocol)
    connection.settimeout(CONNECT_TIMEOUT_SECONDS)
    try:
        connection.connect(socket_address)
    except OSError:
        connection.close()
        raise
    return connection


class InternalHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = open_internal_connection(self.host, self.port)


def read_until_idle(connection):
    chunks = []
    total = 0
    connection.settimeout(READ_IDLE_TIMEOUT_SECONDS)
    while total < MAX_RESPONSE_BYTES:
        try:
            chunk = connection.recv(min(4096, MAX_RESPONSE_BYTES - total))
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def fetch_gopher(parsed):
    host = parsed.hostname
    if not host:
        raise ValueError("в адресе протокола gopher не указан хост")

    port = parsed.port or 70
    selector = parsed.path[1:] if parsed.path.startswith("/") else parsed.path
    payload = unquote_to_bytes(selector)
    if payload.startswith(b"_"):
        payload = payload[1:]
    else:
        payload += b"\r\n"

    with open_internal_connection(host, port) as connection:
        connection.sendall(payload)
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return read_until_idle(connection)


def fetch_http(parsed):
    host = parsed.hostname
    if not host:
        raise ValueError("в адресе HTTP не указан хост")

    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection = InternalHTTPConnection(host, port, timeout=CONNECT_TIMEOUT_SECONDS)
    try:
        connection.request("GET", path, headers={"User-Agent": "getmysql-eval"})
        response = connection.getresponse()
        return response.read(MAX_RESPONSE_BYTES)
    finally:
        connection.close()


def fetch_url(value):
    parsed = urlsplit(value)
    if parsed.scheme == "gopher":
        return fetch_gopher(parsed), "gopher"
    if parsed.scheme == "http":
        return fetch_http(parsed), "http"
    raise ValueError("разрешены только протоколы http и gopher")


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string, *args):
        message = format_string % args
        print(f"HTTP-запрос: {message}", file=sys.stdout, flush=True)

    def send_bytes(self, status, content_type, body, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text_error(self, status, message):
        self.send_bytes(status, "text/plain; charset=utf-8", message.encode("utf-8"))

    def do_GET(self):
        if self.path == "/healthz":
            self.send_bytes(200, "text/plain; charset=utf-8", b"ok\n")
            return
        if self.path != "/":
            self.send_text_error(404, "Маршрут не найден\n")
            return

        description = {
            "service": "getmysql",
            "endpoint": "POST /fetch",
            "parameter": "url",
            "supported_schemes": ["http", "gopher"],
            "internal_service": "MySQL доступен только из сети приложения: db:3306",
            "database_account": "reader без пароля",
        }
        body = json.dumps(description, ensure_ascii=False).encode("utf-8") + b"\n"
        self.send_bytes(200, "application/json; charset=utf-8", body)

    def do_POST(self):
        if self.path != "/fetch":
            self.send_text_error(404, "Маршрут не найден\n")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_text_error(400, "Некорректный Content-Length\n")
            return
        if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
            self.send_text_error(400, "Некорректный размер тела запроса\n")
            return

        body = self.rfile.read(content_length).decode("utf-8", errors="strict")
        values = parse_qs(body, keep_blank_values=True)
        url = values.get("url", [""])[0]
        if not url:
            self.send_text_error(400, "Не передан параметр url\n")
            return

        try:
            response, scheme = fetch_url(url)
        except (OSError, ValueError, http.client.HTTPException) as error:
            self.send_text_error(502, f"Не удалось получить внутренний ресурс: {error}\n")
            return

        self.send_bytes(
            200,
            "application/octet-stream",
            response,
            {"X-SSRF-Scheme": scheme},
        )


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 8080), RequestHandler)
    print("Сервис getmysql запущен на порту 8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
