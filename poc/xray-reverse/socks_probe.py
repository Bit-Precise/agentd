import socket
import sys
import time


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise RuntimeError(f"closed while reading {n} bytes")
        data += part
    return data


def main():
    proxy_port = int(sys.argv[1]) if len(sys.argv) > 1 else 19287
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 19081
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 no-auth negotiation failed")
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
    header = recv_exact(sock, 4)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 CONNECT failed: {header[1]}")
    if header[3] == 1:
        recv_exact(sock, 4)
    elif header[3] == 3:
        recv_exact(sock, recv_exact(sock, 1)[0])
    elif header[3] == 4:
        recv_exact(sock, 16)
    recv_exact(sock, 2)
    sock.settimeout(10)
    print(sock.recv(1024).decode(), end="", flush=True)
    sock.sendall(b"ping\n")
    print(sock.recv(1024).decode(), end="", flush=True)
    print("connected", flush=True)
    while True:
        sock.sendall(b"ping\n")
        print(sock.recv(1024).decode(), end="", flush=True)
        time.sleep(1)


if __name__ == "__main__":
    main()
