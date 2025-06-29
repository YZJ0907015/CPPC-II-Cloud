import socket
import struct

# 发送带 4 字节大端长度前缀的消息
def send(conn: socket.socket, data: bytes):
    length_prefix = struct.pack('>I', len(data))
    conn.sendall(length_prefix + data)
    
# 接收带长度前缀的消息，循环 recv 直到拿满
def recv(conn: socket.socket) -> bytes:
    # 1. 先读 4 字节前缀
    prefix = b''
    while len(prefix) < 4:
        chunk = conn.recv(4 - len(prefix))
        if not chunk:
            raise ConnectionError("Failed to read length prefix")
        prefix += chunk

    length = struct.unpack('>I', prefix)[0]
    # 2. 循环读 body
    data = bytearray()
    to_read = length
    while to_read > 0:
        # 每次读不超过 4 KB，或剩余字节
        chunk = conn.recv(min(4096, to_read))
        if not chunk:
            raise ConnectionError(f"Incomplete data received, expected {length} bytes, got {len(data)} bytes")
        data.extend(chunk)
        to_read -= len(chunk)

    return bytes(data)