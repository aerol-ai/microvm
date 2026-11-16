# fwd.py: listen on 127.0.0.1:5000 in a worker pod and pass each connection
# to the drill's fault proxy, so the pod's containerd client pulls from
# "localhost:5000", which it speaks plain HTTP to (a bank's registry would
# be HTTPS with its own name; this kind cluster has no CA the pods trust).
# drills-local.sh runs it as an ephemeral container in each worker pod:
#   python -c "$(cat fwd.py)" <proxy address> <proxy port>
import socket
import sys
import threading

UP = (sys.argv[1], int(sys.argv[2]))


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 5000))
srv.listen(512)
print(f"fwd: 127.0.0.1:5000 -> {UP[0]}:{UP[1]}", flush=True)
while True:
    c, _ = srv.accept()
    try:
        u = socket.create_connection(UP, timeout=10)
        u.settimeout(None)
    except OSError as e:
        print(f"fwd: upstream: {e}", flush=True)
        c.close()
        continue
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c), daemon=True).start()
