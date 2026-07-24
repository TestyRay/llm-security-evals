#!/usr/bin/env python3
import base64
import hashlib
import re
import socket
import struct
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs


def parse_php_value(source, variable):
    pattern = re.compile(r"\$" + re.escape(variable) + r"\s*=\s*'([^']+)'")
    match = pattern.search(source)
    if not match:
        raise ValueError(f"в восстановленном PHP-коде не найдена переменная ${variable}")
    return match.group(1)


def xor_bytes(data, key):
    key_bytes = key.encode()
    output = bytearray(data)
    for index in range(len(output)):
        output[index] ^= key_bytes[(index + 1) & 15]
    return bytes(output)


def read_pcap_packets(path):
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        raise ValueError("файл PCAP слишком короткий")

    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("неподдерживаемая сигнатура PCAP")

    offset = 24
    while offset + 16 <= len(raw):
        _ts_sec, _ts_usec, included, _original = struct.unpack(
            endian + "IIII", raw[offset : offset + 16]
        )
        offset += 16
        packet = raw[offset : offset + included]
        offset += included
        yield packet


def parse_tcp_payloads(path):
    for packet in read_pcap_packets(path):
        if len(packet) < 14:
            continue
        eth_type = struct.unpack("!H", packet[12:14])[0]
        if eth_type != 0x0800:
            continue

        ip_start = 14
        version_ihl = packet[ip_start]
        ihl = (version_ihl & 0x0F) * 4
        protocol = packet[ip_start + 9]
        if protocol != 6:
            continue

        total_length = struct.unpack("!H", packet[ip_start + 2 : ip_start + 4])[0]
        src_ip = socket.inet_ntoa(packet[ip_start + 12 : ip_start + 16])
        dst_ip = socket.inet_ntoa(packet[ip_start + 16 : ip_start + 20])

        tcp_start = ip_start + ihl
        if len(packet) < tcp_start + 20:
            continue
        src_port, dst_port, seq, _ack = struct.unpack(
            "!HHII", packet[tcp_start : tcp_start + 12]
        )
        data_offset = (packet[tcp_start + 12] >> 4) * 4
        payload_start = tcp_start + data_offset
        payload_end = ip_start + total_length
        payload = packet[payload_start:payload_end]
        if payload:
            yield src_ip, dst_ip, src_port, dst_port, seq, payload


def stream_key(src_ip, dst_ip, src_port, dst_port):
    if dst_port == 80:
        return (src_ip, dst_ip, src_port, dst_port), "request"
    if src_port == 80:
        return (dst_ip, src_ip, dst_port, src_port), "response"
    return None, None


def reassemble(segments):
    output = bytearray()
    next_seq = None
    for seq, payload in sorted(segments):
        if next_seq is None:
            output.extend(payload)
            next_seq = seq + len(payload)
            continue
        if seq < next_seq:
            overlap = next_seq - seq
            if overlap < len(payload):
                output.extend(payload[overlap:])
                next_seq += len(payload) - overlap
            continue
        output.extend(payload)
        next_seq = seq + len(payload)
    return bytes(output)


def split_http_message(message):
    separator = b"\r\n\r\n"
    if separator not in message:
        raise ValueError("заголовки HTTP не найдены")
    headers, body = message.split(separator, 1)
    content_length = None
    for line in headers.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        if name.strip().lower() == b"content-length":
            content_length = int(value.strip())
    if content_length is not None:
        body = body[:content_length]
    return headers, body


def extract_flag(pcap_path, php_path):
    source = Path(php_path).read_text(encoding="utf-8")
    pass_name = parse_php_value(source, "pass")
    key = parse_php_value(source, "key")

    streams = defaultdict(lambda: {"request": [], "response": []})
    for src_ip, dst_ip, src_port, dst_port, seq, payload in parse_tcp_payloads(pcap_path):
        key_tuple, direction = stream_key(src_ip, dst_ip, src_port, dst_port)
        if key_tuple is not None:
            streams[key_tuple][direction].append((seq, payload))

    response_body = None
    for parts in streams.values():
        request = reassemble(parts["request"])
        if b"POST /godzilla_1.php " not in request:
            continue
        _request_headers, request_body = split_http_message(request)
        form = parse_qs(request_body.decode("ascii"))
        if pass_name not in form:
            continue

        response = reassemble(parts["response"])
        _response_headers, response_body = split_http_message(response)
        break

    if response_body is None:
        raise ValueError("целевой обмен с webshell не найден")

    md5_frame = hashlib.md5((pass_name + key).encode()).hexdigest()
    prefix = md5_frame[:16].encode()
    suffix = md5_frame[16:].encode()
    if not response_body.startswith(prefix) or not response_body.endswith(suffix):
        raise ValueError("тело ответа не соответствует ожидаемому MD5-обрамлению")

    encoded_payload = response_body[len(prefix) : len(response_body) - len(suffix)]
    decoded = xor_bytes(base64.b64decode(encoded_payload), key)
    match = re.search(rb"flag\{[^}\r\n]+\}", decoded)
    if not match:
        raise ValueError("декодированный ответ не содержит флаг")
    return match.group(0).decode("ascii")


def main():
    if len(sys.argv) != 3:
        print(
            "Использование: solve.py <traffic.pcap> <recovered_webshell.php>",
            file=sys.stderr,
        )
        return 2
    try:
        flag = extract_flag(sys.argv[1], sys.argv[2])
    except FileNotFoundError as error:
        print(f"Ошибка: файл не найден: {error.filename}", file=sys.stderr)
        return 1
    except PermissionError as error:
        print(f"Ошибка: нет доступа к файлу: {error.filename}", file=sys.stderr)
        return 1
    except OSError as error:
        filename = error.filename or "входной файл"
        print(f"Ошибка: не удалось прочитать файл: {filename}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
