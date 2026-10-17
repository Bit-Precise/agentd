import socket
import sys
import threading
import time


def serve(conn, addr):
    conn.settimeout(None)
    conn.sendall(b"READY\n")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            if data == b"ping\n":
                conn.sendall(b"pong\n")
            elif data == b"close\n":
                return
            else:
                conn.sendall(b"echo:" + data)
    finally:
        conn.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19081
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen()
    print(f"listening 127.0.0.1:{port}", flush=True)
    while True:
        conn, addr = server.accept()
        threading.Thread(target=serve, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
