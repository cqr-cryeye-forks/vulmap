#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# import shodan
from module import globals
from module.color import color
from module.time import now
from thirdparty import shodan


def shodan_api(shodan_keyword):
    try:
        shodan_key = globals.get_value("shodan_key")
        api = shodan.Shodan(shodan_key)
        res = api.search(shodan_keyword)
        return [f"{result['ip_str']}:{result['port']}" for result in res['matches']]
    except shodan.APIError as e:
        print(now.timed(de=0) + color.red_warn() + color.red(f" Shodan api: {str(e)}"))
    return []
