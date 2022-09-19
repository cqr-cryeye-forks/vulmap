#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os.path
import re
import time
from urllib.parse import urlparse

from module import globals
from module.color import color
from module.time import now


def output(types, item):
    try:
        o_text = globals.get_value("O_TEXT")
        o_json = globals.get_value("O_JSON")
        if o_text and types == "text":
            output_text(o_text, item)
        if o_json and types == "json":
            output_json(o_json, item)
    except Exception as error:
        print(now.timed(de=0) + color.red(f"[ERROR] {error} " + error.__traceback__.tb_frame.f_globals['__file__']
                                          + " " + str(error.__traceback__.tb_lineno)))


def output_text(filename, item):
    with open(filename, 'a') as output_file:
        output_file.write("%s\n" % item)


def output_json(filename, data):
    try:
        vul_data = data["vul_data"]
    except KeyError:
        write_json([], file_name=filename)
        return
    json_results = []
    vul_path, vul_requ, vul_resp = parse_data(vul_data)
    try:
        if vul_data:
            vul_urls = data["vul_urls"]
            host_port = urlparse(vul_urls)
            vul_host = host_port.hostname
            vul_port = host_port.port
            # vul_u = vul_host + ":" + str(vul_port)
            if vul_port is None:
                if r"https://" in vul_urls:
                    vul_port = 443
                elif r"http://" in vul_urls:
                    vul_port = 80
            if r"https://" in vul_urls and vul_port is not None:
                vul_u = f"https://{vul_host}:{str(vul_port)}/{vul_path}"
            elif r"https://" in vul_urls:
                vul_u = f"https://{vul_host}/{vul_path}"
            elif r"http://" in vul_urls and vul_port is not None:
                vul_u = f"http://{vul_host}:{str(vul_port)}/{vul_path}"
            else:
                vul_u = f"http://{vul_host}/{vul_path}"
            prt_name = data["prt_name"]
            vul_payd = data["vul_payd"]
            vul_type = data["vul_type"]
            vul_desc = data["vul_name"]
            vul_date = int(round(time.time() * 1000))
            json_data = {
                "create_time": vul_date,
                "detail": {
                    "description": vul_desc,
                    "host": vul_host,
                    "param": {},
                    "payload": vul_payd,
                    "port": vul_port,
                    "request": vul_requ,
                    "response": vul_resp,
                    "url": vul_u
                },
                "plugin": prt_name,
                "target": {
                    "url": vul_urls
                },
                "vuln_class": vul_type
            }
            json_results.append(json_data)
        write_json(json_results, file_name=filename)
    except Exception as error:
        print(now.timed(de=0) + color.red(f"[ERROR] {error} " + error.__traceback__.tb_frame.f_globals['__file__']
                                          + " " + str(error.__traceback__.tb_lineno)))


def write_json(obj, file_name):
    item_list = []
    try:
        if os.path.isfile(file_name):  # keep data from result file.
            with open(file_name, 'r') as f:
                try:
                    load_dict = json.load(f)
                except ValueError:
                    load_dict = {}
                for i in range(len(load_dict)):
                    create_time = load_dict[i]['create_time']
                    description = load_dict[i]['detail']['description']
                    host = load_dict[i]['detail']['host']
                    param = load_dict[i]['detail']['param']
                    payload = load_dict[i]['detail']['payload']
                    port = load_dict[i]['detail']['port']
                    request = load_dict[i]['detail']['request']
                    response = load_dict[i]['detail']['response']
                    url_1 = load_dict[i]['detail']['url']
                    plugin = load_dict[i]['plugin']
                    url_2 = load_dict[i]['target']['url']
                    vuln_class = load_dict[i]['vuln_class']
                    json_dict = {
                        "create_time": create_time,
                        "detail": {
                            "description": description,
                            "host": host,
                            "param": param,
                            "payload": payload,
                            "port": port,
                            "request": request,
                            "response": response,
                            "url": url_1
                        },
                        "plugin": plugin,
                        "target": {
                            "url": url_2
                        },
                        "vuln_class": vuln_class
                    }
                    item_list.append(json_dict)
        if len(obj):
            item_list.append(*obj)
        with open(file_name, 'w', encoding='utf-8') as f2:
            json.dump(item_list, f2, indent=4, ensure_ascii=False)
    except Exception as error:
        print(now.timed(de=0) + color.red(f"[ERROR] {error} " + error.__traceback__.tb_frame.f_globals['__file__']
                                          + " " + str(error.__traceback__.tb_lineno)))


def parse_data(vul_data) -> (str, str, str):
    if not vul_data or vul_data == 'null':
        return '', '', ''
    vul_path = ""
    request = ""
    response = ""
    try:
        if r">_<" in vul_data:
            request = vul_data
            response = vul_data
        else:
            request = re.findall(r'([\s\S]*)\r\n> HTTP/', vul_data)[0]
            request = request.replace("< ", "")
            response = re.findall(r'\r\n> HTTP/([\s\S]*)', vul_data)[0]
            response = f'HTTP/{response.replace("> ", "")}'
            vul_path = re.findall(r' /(.*) HTTP', vul_data)[0]
    except Exception as error:
        print(now.timed(de=0) + color.red(f"[ERROR] {error} " + error.__traceback__.tb_frame.f_globals['__file__']
                                          + " " + str(error.__traceback__.tb_lineno)))

    return vul_path, request, response
