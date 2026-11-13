"""A fake mail server for tests/cli.sh (DIVE-8347): greets each connection with
the given line ("silent" = accept and never greet), records every byte the
client sends, then closes. Writes its port to argv[2] once listening."""
import socket
import sys
import threading

greeting, port_file, log_file = sys.argv[1], sys.argv[2], sys.argv[3]
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(8)
with open(port_file, "w") as f:
    f.write(str(srv.getsockname()[1]))


def serve(c):
    try:
        c.settimeout(3)
        if greeting != "silent":
            c.sendall((greeting + "\r\n").encode())
        got = b""
        try:
            while True:
                b = c.recv(4096)
                if not b:
                    break
                got += b
                if b"QUIT" in got:
                    c.sendall(b"221 bye\r\n")
                    break
        except OSError:
            pass
        with open(log_file, "ab") as f:
            f.write(got)
    finally:
        c.close()


while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
