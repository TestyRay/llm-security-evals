#!/usr/bin/env python3
import base64
import hashlib
import socket
import struct
from pathlib import Path
from urllib.parse import quote_plus


TASK_DIR = Path(__file__).resolve().parents[1]
OUTPUT = TASK_DIR / "resources" / "traffic.pcap"

CLIENT_MAC = bytes.fromhex("001122334455")
SERVER_MAC = bytes.fromhex("66778899aabb")
CLIENT_IP = "10.14.7.23"
SERVER_IP = "172.20.0.5"
KEY = "3c6e0b8a9c15224a"
PASS_NAME = "pass"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def xor_bytes(data, key):
    key_bytes = key.encode()
    output = bytearray(data)
    for index in range(len(output)):
        output[index] ^= key_bytes[(index + 1) & 15]
    return bytes(output)


def ip_header(src_ip, dst_ip, payload_len, packet_id):
    version_ihl = 0x45
    total_length = 20 + payload_len
    flags_fragment = 0x4000
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        packet_id,
        flags_fragment,
        64,
        6,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
    data_offset_flags = (5 << 12) | flags
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset_flags,
        64240,
        0,
        0,
    )
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        6,
        len(header) + len(payload),
    )
    tcp_sum = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", tcp_sum) + header[18:]


def ethernet_frame(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, packet_id):
    if src_ip == CLIENT_IP:
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
    else:
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
    tcp = tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip = ip_header(src_ip, dst_ip, len(tcp) + len(payload), packet_id)
    eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
    return eth + ip + tcp + payload


class Capture:
    def __init__(self):
        self.frames = []
        self.packet_id = 1
        self.timestamp = 1_716_200_000
        self.usec = 0

    def add(self, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
        frame = ethernet_frame(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
            self.packet_id,
        )
        self.frames.append((self.timestamp, self.usec, frame))
        self.packet_id += 1
        self.usec += 17_000
        if self.usec >= 1_000_000:
            self.timestamp += 1
            self.usec -= 1_000_000

    def http_exchange(self, sport, request, response, client_seq, server_seq, request_chunks, response_chunks):
        self.add(CLIENT_IP, SERVER_IP, sport, 80, client_seq, 0, 0x02)
        self.add(SERVER_IP, CLIENT_IP, 80, sport, server_seq, client_seq + 1, 0x12)
        self.add(CLIENT_IP, SERVER_IP, sport, 80, client_seq + 1, server_seq + 1, 0x10)

        cseq = client_seq + 1
        for chunk in split_chunks(request, request_chunks):
            self.add(CLIENT_IP, SERVER_IP, sport, 80, cseq, server_seq + 1, 0x18, chunk)
            cseq += len(chunk)

        self.add(SERVER_IP, CLIENT_IP, 80, sport, server_seq + 1, cseq, 0x10)

        sseq = server_seq + 1
        for chunk in split_chunks(response, response_chunks):
            self.add(SERVER_IP, CLIENT_IP, 80, sport, sseq, cseq, 0x18, chunk)
            sseq += len(chunk)

        self.add(CLIENT_IP, SERVER_IP, sport, 80, cseq, sseq, 0x10)

    def write(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        packets = []
        for ts_sec, ts_usec, frame in self.frames:
            packets.append(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            packets.append(frame)
        path.write_bytes(header + b"".join(packets))


def split_chunks(data, sizes):
    chunks = []
    offset = 0
    for size in sizes:
        chunks.append(data[offset : offset + size])
        offset += size
    if offset < len(data):
        chunks.append(data[offset:])
    return [chunk for chunk in chunks if chunk]


def http_request(method, path, headers, body=b""):
    base = [
        f"{method} {path} HTTP/1.1",
        f"Host: {SERVER_IP}",
        "User-Agent: Mozilla/5.0",
        "Connection: close",
    ]
    for name, value in headers:
        base.append(f"{name}: {value}")
    if body:
        base.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(base) + "\r\n\r\n").encode() + body


def http_response(status, headers, body):
    base = [
        f"HTTP/1.1 {status}",
        "Server: Apache/2.4.54",
        "Connection: close",
    ]
    for name, value in headers:
        base.append(f"{name}: {value}")
    base.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(base) + "\r\n\r\n").encode() + body


def webshell_request_response():
    command = b"show /var/www/.cache/report.txt"
    encoded_command = base64.b64encode(xor_bytes(command, KEY)).decode("ascii")
    body = f"{PASS_NAME}={quote_plus(encoded_command)}".encode("ascii")
    request = http_request(
        "POST",
        "/godzilla_1.php",
        [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Cookie", "PHPSESSID=nflow-audit-4319"),
        ],
        body,
    )

    flag = b"fl" + b"ag" + bytes([123]) + b"webshell_http_stream_decoded" + bytes([125])
    output = b"incident=traffic-sniffer\nstatus=decoded\nflag=" + flag + b"\n"
    md5_frame = hashlib.md5((PASS_NAME + KEY).encode()).hexdigest()
    encoded_output = base64.b64encode(xor_bytes(output, KEY))
    response_body = md5_frame[:16].encode() + encoded_output + md5_frame[16:].encode()
    response = http_response(
        "200 OK",
        [("Content-Type", "text/html; charset=UTF-8")],
        response_body,
    )
    return request, response


def main():
    capture = Capture()

    request = http_request("GET", "/", [], b"")
    response = http_response(
        "200 OK",
        [("Content-Type", "text/plain")],
        b"php traffic sniffer lab\n",
    )
    capture.http_exchange(51540, request, response, 1000, 7000, [64], [80])

    request = http_request("GET", "/status.php", [], b"")
    response = http_response(
        "200 OK",
        [("Content-Type", "application/json")],
        b'{"status":"ok","queue":"empty"}\n',
    )
    capture.http_exchange(51541, request, response, 3000, 9000, [48, 48], [60])

    request, response = webshell_request_response()
    capture.http_exchange(51542, request, response, 5000, 11000, [73, 41, 23], [61, 37, 29])

    capture.write(OUTPUT)
    print(f"Создан файл захвата сетевого трафика (PCAP): {OUTPUT}")


if __name__ == "__main__":
    main()
