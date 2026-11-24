"""Hand accepted loopback TCP clients to the host canary broker via SCM_RIGHTS."""

from array import array
from contextlib import suppress
from pathlib import Path
import socket
import time


PORT = 8401
IDLE = 15
LIFETIME = 90


def handoff(client, address, proof):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
        broker.settimeout(IDLE)
        broker.connect(str(address))
        broker.sendall(proof)
        rights = (socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [client.fileno()]))
        if broker.sendmsg([b"F"], [rights]) != 1:
            raise OSError("incomplete socket handoff")


def main():
    root = Path("/fixture")
    proof = (root / "proof").read_bytes()
    if len(proof) != 32:
        raise SystemExit(2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", PORT))
        listener.listen(4)
        deadline = time.monotonic() + LIFETIME
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            listener.settimeout(remaining)
            try:
                client, _ = listener.accept()
            except TimeoutError:
                return
            with client, suppress(OSError):
                handoff(client, root / "provider.sock", proof)


if __name__ == "__main__":
    main()
