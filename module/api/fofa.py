#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from thirdparty import requests
import base64
from module.color import color
from module.time import now
from module import globals


def fofa(fofa_data, size):
    timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
    headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
    email = globals.get_value("fofa_email")
    key = globals.get_value("fofa_key")
    fofa_target = []
    keyword = base64.b64encode(str.encode(fofa_data))
    qbase = keyword.decode('ascii')
    api_url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&size={size}&qbase64={qbase}"
    print(now.timed(de=0) + color.yel_info() + color.yellow(f" Fofa api: {api_url}"))

    try:
        res = requests.get(api_url, headers=headers, timeout=timeout, verify=False)
        if res.status_code != 200:
            print(now.timed(de=0) + color.red_warn() + color.red(f" {res.text}"))
            r = json.loads(res.text)
            fofa_target.extend(i[0] for i in r['results'])
        return fofa_target
    except requests.exceptions.Timeout:
        print(now.timed(de=0) + color.red_warn() + color.red(" Fofa API connection failed because of timeout "))
    except requests.exceptions.ConnectionError:
        print(now.timed(de=0) + color.red_warn() + color.red(" Fofa API connection failed because the connection failed "))
    except Exception as e:
        print(now.timed(de=0) + color.red_warn() + color.red(f" Fofa API connection failed because unknown error : {e}"))
    return fofa_target
