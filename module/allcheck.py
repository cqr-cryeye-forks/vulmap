#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import platform
import socket
from urllib.parse import urlparse

from module import globals
from thirdparty import requests


def os_check():
    if platform.system().lower() == 'windows':
        return "windows"
    elif platform.system().lower() == 'linux':
        return "linux"
    else:
        return "other"


def url_check(url):
    try:
        if r"http://" not in url and r"https://" not in url:
            url = f"https://{url}" if r"443" in url else f"http://{url}"
        return url
    except AttributeError:
        return url


def survival_check(url) -> bool | None:
    if globals.get_value("CHECK") != "on":
        return

    def _socket_conn():
        try:
            getipport = urlparse(url)
            hostname = getipport.hostname
            port = getipport.port
            if port is None and r"https://" in url:
                port = 443
            elif port is None and r"http://" in url:
                port = 80
            else:
                port = 80
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        except:
            return False

    def _http_conn():
        try:
            timeout = globals.get_value("TIMEOUT")  # 获取全局变量TIMEOUT
            headers = globals.get_value("HEADERS")
            target = url_check(url)
            requests.get(target, timeout=timeout, headers=headers, verify=False)
            return True
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.InvalidURL):
            return False

    return bool(_socket_conn() or _http_conn())
