"""Copy one local OpenCode exchange to the fixture's private Unix socket."""

from contextlib import suppress
from pathlib import Path
import select
import socket
import time


PORT = 8401
IDLE = 15
TOTAL = 60
LIMITS = (80 * 1024, 256 * 1024)


def exchange(client, proof):
    deadline = time.monotonic() + TOTAL
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
        broker.settimeout(IDLE)
        broker.connect("/fixture/provider.sock")
        broker.sendall(proof)
        left = list(LIMITS)
        readers = [client, broker]
        while broker in readers:
            remaining = min(IDLE, deadline - time.monotonic())
            if remaining <= 0:
                return
            ready, _, _ = select.select(readers, [], [], remaining)
            if not ready:
                return
            for peer in ready:
                index = 0 if peer is client else 1
                target = broker if index == 0 else client
                data = peer.recv(min(8192, left[index] + 1))
                if not data:
                    readers.remove(peer)
                    with suppress(OSError):
                        target.shutdown(socket.SHUT_WR)
                    continue
                left[index] -= len(data)
                if left[index] < 0:
                    return
                target.settimeout(max(0.001, min(IDLE, deadline - time.monotonic())))
                target.sendall(data)


def main():
    proof = Path("/fixture/proof").read_bytes()
    if len(proof) != 32:
        raise SystemExit(2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", PORT))
        listener.listen(2)
        while True:
            client, _ = listener.accept()
            with client, suppress(OSError):
                client.settimeout(IDLE)
                exchange(client, proof)


if __name__ == "__main__":
    main()
