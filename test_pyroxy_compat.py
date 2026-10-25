#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kiểm tra nhanh PyRoxy mới (Elite-PhoenixA/PyRoxy) + quét nhanh toàn bộ methods."""

import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")

import start  # noqa: E402
from start import (HttpFlood, Layer4, Methods, ToolsConsole,
                   REQUESTS_SENT, BYTES_SEND, CONNECTIONS_SENT,
                   handleProxyList, _read_proxies, con)
from PyRoxy import Proxy, ProxyType, ProxyUtiles
from yarl import URL

HTTP_PORT = 18080
L4_PORT = 18081
PROXY_PORT = 18082
HOST = "127.0.0.1"
results = []


# ================= local servers =================
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):
        pass


def start_proxy_server():
    """HTTP proxy forwarding tối giản: CONNECT (tunnel) + GET absolute-URI."""
    import socket as sk

    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except Exception:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except Exception:
                    pass

    def worker():
        ls = sk.socket()
        ls.setsockopt(sk.SOL_SOCKET, sk.SO_REUSEADDR, 1)
        ls.bind((HOST, PROXY_PORT))
        ls.listen(256)
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    def handle(c):
        try:
            c.settimeout(10)
            head = b""
            while b"\r\n\r\n" not in head:
                d = c.recv(4096)
                if not d:
                    return
                head += d
            line = head.split(b"\r\n", 1)[0].decode()
            if line.upper().startswith("CONNECT"):
                host, port = line.split()[1].rsplit(":", 1)
                up = sk.create_connection((host, int(port)), timeout=10)
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                threading.Thread(target=pipe, args=(c, up), daemon=True).start()
                pipe(up, c)
            else:
                # absolute-URI GET -> forward
                url = line.split()[1]
                from urllib.parse import urlparse
                u = urlparse(url)
                up = sk.create_connection((u.hostname, u.port or 80), timeout=10)
                req = head.replace(url.encode(), (u.path or "/").encode(), 1)
                up.sendall(req)
                threading.Thread(target=pipe, args=(c, up), daemon=True).start()
                pipe(up, c)
        except Exception:
            try:
                c.close()
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()


def start_tcp_udp():
    import socket as sk

    def tcp():
        s = sk.socket()
        s.setsockopt(sk.SOL_SOCKET, sk.SO_REUSEADDR, 1)
        s.bind((HOST, L4_PORT))
        s.listen(512)
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=lambda cc: [cc.recv(4096) for _ in iter(int, 1)],
                              args=(c,), daemon=True).start()

    def udp():
        s = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
        s.bind((HOST, L4_PORT))
        while True:
            try:
                s.recvfrom(65535)
            except OSError:
                return

    threading.Thread(target=tcp, daemon=True).start()
    threading.Thread(target=udp, daemon=True).start()


# ================= PyRoxy-specific tests =================
def test_pyroxy_api():
    print("\n=== 1. PyRoxy API ===")
    try:
        p = Proxy(HOST, PROXY_PORT, ProxyType.HTTP)
        assert str(p) == f"http://{HOST}:{PROXY_PORT}", str(p)
        assert p.asRequest()["http"] == f"http://{HOST}:{PROXY_PORT}"
        assert ProxyType.stringToProxyType("socks5") == ProxyType.SOCKS5
        assert ProxyType.stringToProxyType("http") == ProxyType.HTTP
        print("  PASS  Proxy / ProxyType / stringToProxyType / asRequest")
    except Exception as e:
        print(f"  FAIL  {e!r}")


def test_readFromFile():
    print("\n=== 2. ProxyUtiles.readFromFile ===")
    from pathlib import Path
    f = Path("files/proxies/test_pyroxy_local.txt")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(f"http://{HOST}:{PROXY_PORT}\n")
    try:
        proxies = _read_proxies(f, ProxyType.HTTP)
        assert len(proxies) == 1, proxies
        p = next(iter(proxies))
        assert p.host == HOST and p.port == PROXY_PORT and p.type == ProxyType.HTTP
        print(f"  PASS  parse được {len(proxies)} proxy từ file")
    except Exception as e:
        print(f"  FAIL  {e!r}")
    finally:
        f.unlink(missing_ok=True)


def test_open_socket_via_proxy():
    print("\n=== 3. Proxy.open_socket (flood QUA proxy thật) ===")
    prox = {Proxy(HOST, PROXY_PORT, ProxyType.HTTP)}
    for method in ("GET", "POST", "OVH"):
        REQUESTS_SENT.set(0)
        url = URL(f"http://{HOST}:{HTTP_PORT}/")
        ev = threading.Event()
        ev.set()
        floods = [HttpFlood(i, url, HOST, method, 2, ev, None, None, prox)
                  for i in range(10)]
        for t in floods:
            t.start()
        time.sleep(2)
        ev.clear()
        for t in floods:
            t.join(timeout=5)
        n = int(REQUESTS_SENT)
        results.append((method, n))
        print(f"  {'PASS' if n > 0 else 'FAIL'}  HttpFlood {method} qua proxy: {n} req")


def test_layer4_via_proxy():
    print("\n=== 4. Layer4 qua proxy (TCP) ===")
    prox = {Proxy(HOST, PROXY_PORT, ProxyType.HTTP)}
    ev = threading.Event()
    ev.set()
    floods = [Layer4((HOST, L4_PORT), None, "TCP", ev, prox, 47) for _ in range(5)]
    for t in floods:
        t.start()
    time.sleep(2)
    ev.clear()
    for t in floods:
        t.join(timeout=5)
    n = int(CONNECTIONS_SENT)
    print(f"  {'PASS' if n > 0 else 'FAIL'}  Layer4 TCP qua proxy: {n} kết nối")


def test_proxy_checker():
    print("\n=== 5. ProxyChecker.checkAll ===")
    from PyRoxy import ProxyChecker
    prox = [Proxy(HOST, PROXY_PORT, ProxyType.HTTP)]
    try:
        alive = ProxyChecker.checkAll(prox, timeout=5, threads=10,
                                      url=f"http://{HOST}:{HTTP_PORT}/")
        print(f"  {'PASS' if alive else 'FAIL'}  checkAll: {len(alive)}/{len(prox)} sống")
    except Exception as e:
        print(f"  FAIL  {e!r}")


def test_handleProxyList():
    print("\n=== 6. handleProxyList (luồng CLI) ===")
    from pathlib import Path
    f = Path("files/proxies/test_hpl.txt")
    f.write_text(f"http://{HOST}:{PROXY_PORT}\n")
    try:
        proxies = handleProxyList(con, f, 1, check_threads=10)
        ok = proxies and len(proxies) == 1
        print(f"  {'PASS' if ok else 'FAIL'}  handleProxyList trả về {len(proxies or [])} proxy")
    except Exception as e:
        print(f"  FAIL  {e!r}")
    finally:
        f.unlink(missing_ok=True)


# ================= quick sweep toàn bộ methods =================
def sweep():
    print("\n=== 7. Quét nhanh toàn bộ methods (không proxy, 1.5s mỗi method) ===")
    l7 = sorted(Methods.LAYER7_METHODS)
    for m in l7:
        REQUESTS_SENT.set(0)
        BYTES_SEND.set(0)
        url = URL(f"http://{HOST}:{HTTP_PORT}/")
        ev = threading.Event()
        ev.set()
        dur = 7.0 if m == "CFBUAM" else 1.5
        floods = [HttpFlood(i, url, HOST, m, 2, ev, None, None, None)
                  for i in range(10)]
        for t in floods:
            t.start()
        time.sleep(dur)
        ev.clear()
        for t in floods:
            t.join(timeout=5)
        n = max(int(REQUESTS_SENT), int(BYTES_SEND) // 10)
        results.append((m, n))

    l4_tcp = ["TCP", "CPS", "CONNECTION", "MINECRAFT", "MCBOT"]
    l4_udp = ["UDP", "VSE", "TS3", "MCPE", "FIVEM", "FIVEM-TOKEN"]
    for m in l4_tcp + l4_udp:
        REQUESTS_SENT.set(0)
        CONNECTIONS_SENT.set(0)
        ev = threading.Event()
        ev.set()
        floods = [Layer4((HOST, L4_PORT), [HOST], m, ev, None, 47)
                  for _ in range(10)]
        for t in floods:
            t.start()
        time.sleep(1.5)
        ev.clear()
        for t in floods:
            t.join(timeout=5)
        n = int(REQUESTS_SENT) + int(CONNECTIONS_SENT)
        results.append((m, n))

    raw_ok = ToolsConsole.checkRawSocket()
    raw = ["SYN", "ICMP", "OVH-UDP"] + sorted(Methods.LAYER4_AMP)
    for m in raw:
        if not raw_ok:
            results.append((m, -1))  # skip
            continue
        REQUESTS_SENT.set(0)
        ev = threading.Event()
        ev.set()
        floods = [Layer4((HOST, L4_PORT), [HOST], m, ev, None, 47)
                  for _ in range(10)]
        for t in floods:
            t.start()
        time.sleep(1.5)
        ev.clear()
        for t in floods:
            t.join(timeout=5)
        results.append((m, int(REQUESTS_SENT)))


def main():
    print("Khởi động server local (HTTP/TCP/UDP/proxy)...")
    QuietServer((HOST, HTTP_PORT), H).serve_in_background = None
    srv = QuietServer((HOST, HTTP_PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    start_proxy_server()
    start_tcp_udp()
    time.sleep(0.5)

    import PyRoxy
    print(f"PyRoxy version: {getattr(PyRoxy, '__version__', '?')} "
          f"tại {PyRoxy.__file__}")

    test_pyroxy_api()
    test_readFromFile()
    test_open_socket_via_proxy()
    test_layer4_via_proxy()
    test_proxy_checker()
    test_handleProxyList()
    sweep()

    print("\n" + "=" * 60)
    print("KẾT QUẢ SWEEP (số lượng đếm được, -1 = skip cần Admin):")
    fails = []
    for m, n in results:
        status = "SKIP" if n == -1 else ("PASS" if n > 0 else "FAIL")
        if status == "FAIL":
            fails.append(m)
        print(f"  {m:<14} {status}  ({n})")
    print("=" * 60)
    if fails:
        print(f"FAIL: {fails}")
    else:
        print("Không có method nào FAIL.")


if __name__ == "__main__":
    main()
