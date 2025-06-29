import logging
import threading
import socket
import mtlsp

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def server(host: str = "0.0.0.0", port: int = 1653):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen()

    logging.info(f"Server listening on {host}:{port}")

    try:
        while True:
            conn, addr = server_sock.accept()
            logging.info(f"Accepted connection from {addr}")
            t = threading.Thread(target=mtlsp.handshake, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        logging.info("Shutting down server")
    finally:
        server_sock.close()


if __name__ == "__main__":
    server()
