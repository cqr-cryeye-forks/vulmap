#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

from gevent import joinall

from core.scan import scan
from identify.identify import Identify
from module import globals
from module.allcheck import url_check, survival_check
from module.api.dns import dns_request
from module.api.fofa import fofa
from module.api.shodan import shodan_api
from module.color import color
from module.dismap import dismap, dismap_getwebapps
from module.output import output
from module.proxy import proxy_set
from module.time import now


class Core(object):

    def __init__(self, args, mode: str = "poc", ):
        self.mode = mode

        if self.mode == "poc":
            self.web_app = args.app
            if self.web_app is None:  # 判断是否扫描扫描全部webapps
                globals.set_value("RUNALLPOC", True)  # 扫描单个URL并且所有webapps时RUNALLPOC=True

        self.delay = globals.get_value("DELAY")  # 获取全局变量延时时间DELAY
        self.thread_num = 10
        self.target_url = args.url
        self.target_file = args.file

        if self.target_url and self.target_file:
            raise AttributeError('Too many targets. Select one')

        # fofa
        self.fofa_target = args.fofa
        self.target_shodan = args.shodan

        self.fofa_size = args.size
        if args.socks:
            proxy_set(args.socks, "socks")  # proxy support socks5 http https
        elif args.http:
            proxy_set(args.http, "http")  # proxy support socks5 http https

        if args.thread_num != 10:  # 判断是否为默认线程
            print(now.timed(de=0) + color.yel_info() + color.yellow(f" Custom thread number: {str(args.thread_num)}"))
            self.thread_num = args.thread_num
        if args.debug is False:  # 判断是否开启--debug功能
            print(now.timed(de=self.delay) + color.yel_info() + color.yellow(
                " Using debug mode to echo debug information"))
            globals.set_value("DEBUG", "debug")  # 设置全局变量DEBUG
        self.file_text = args.O_TEXT
        self.file_json = args.O_JSON

        # Check output file
        if self.target_file and os.path.isfile(self.target_file):
            print(now.timed(de=0) + color.red_warn() + color.red(f" Not found target file: {self.target_file}. Skipping"))
            self.target_file = None

        if self.file_json and os.path.isfile(self.file_json):
            print(now.timed(de=self.delay) + color.red_warn() + color.red(
                f" The json file: [{self.file_json}] already exists"))
            self.target_file = None

    def control_options(self):  # 选项控制，用于处理所有选项
        now_warn = now.timed(de=self.delay) + color.red_warn()
        # ceye_api()  # 测试ceye连接性
        if not dns_request():
            print(now_warn + color.red(" Dnslog platform (hyuga.co dnslog.cn ceye.io) is not available"))

        if self.mode == "poc":  # 判断是否进入poc模式
            if self.target_url:  # 判断是否为仅-u扫描单个URL
                self.target_url = url_check(self.target_url)  # 处理url格式
                if survival_check(self.target_url):  # 检查目标存活状态
                    print(now.timed(de=0) + color.red_warn() + color.red(f" Survival check failed: {self.target_url}"))
                    output('json', {})
                else:
                    print(now.timed(de=0) + color.yel_info() + color.cyan(f" Start scanning target: {self.target_url}"))
                    self.control_webapps("url", self.target_url, self.web_app)
            if self.target_file:  # 判断是否为仅-f批量扫描文件
                print(now.timed(de=0) + color.yel_info() + color.cyan(f" Start batch scanning target: {self.target_file}"))
                if self.web_app is None:  # 判断是否扫描扫描全部webapps
                    globals.set_value("RUNALLPOC", "FILE")  # 批量扫描URL并且所有webapps时RUNALLPOC="FILE"
                self.control_webapps("file", self.target_file, self.web_app)
            if self.fofa_target:  # 调用fofa api
                self.scan_fofa()
            if self.target_shodan:  # 调用fofa api 或者 shodan api
                self.scan_shodan()

        else:
            print(now_warn + color.red(" Options error"))

    def save_result(self, result):
        if self.file_text:
            print(now.timed(de=self.delay) + color.yel_info() + color.cyan(
                f" Scan result text saved to: {self.file_text}"))
        if self.file_json:
            print(now.timed(de=self.delay) + color.yel_info() + color.cyan(
                f" Scan result json saved to: {self.file_json}"))

    def control_webapps(self, target_type, target, webapps):
        thread_pool = ThreadPoolExecutor(self.thread_num)  # 多线程池数量t_num由选项控制，默认10线程
        webapps_identify = []  # 定义目标类型字典，用于目标类型识别并记录，为跑所有poc时进行类型识别
        thread_poc = []  # 多线程字典，用于添加线程任务
        gevent_pool = []  # 协程字段，用于添加协程任务
        if self.mode == "poc":  # poc漏洞扫描模式
            match target_type:
                case 'url':  # 第一种扫描仅扫描单个URL
                    output("text", f"[*] {target}")
                    if webapps is None:  # 判断是否进行指纹识别
                        Identify.start(target, webapps_identify)  # 第一种情况需要进行指纹识别
                    elif r"all" in webapps:  # 判断是否扫描所有类型poc
                        print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify to scan all vulnerabilities"))
                        webapps_identify.append("all")  # 指定扫描所有时，需要将指纹全部指定为all
                    else:
                        webapps_identify = webapps  # 指定但不是all，也可以指定多个类型，比如-a solr struts2
                        print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify scan vulnerabilities for: "),
                              end='')
                        for count, w_i in enumerate(webapps_identify, start=1):
                            print(color.cyan(w_i), end=' ')
                            if count % len(webapps_identify) == 0:
                                print(end='\n')
                    self.scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, target)  # 调用scan开始扫描
                    joinall(gevent_pool)  # 运行协程池
                    wait(thread_poc, return_when=ALL_COMPLETED)  # 等待所有多线程任务运行完
                    print(now.timed(de=0) + color.yel_info() + color.yellow(
                        " Scan completed and ended"))
                case "file":  # 第二种扫描情况，批量扫描文件不指定webapps时需要做指纹识别
                    count_line = -1  # 用于判断行数
                    count_null = 0
                    for line in open(target):
                        line = line.strip()  # 读取目标时过滤杂质
                        if line == "":
                            count_null += 1
                    for count_line, line in enumerate(open(target, 'rU')):  # 判断文件的行数
                        pass
                    count_line += 1  # 行数加1
                    target_num = count_line - count_null
                    now_num = 0  # 当前数量
                    target_list = []  # 批量扫描需要读取的字典
                    with open(target, 'r') as _:  # 打开目标文件
                        for line in _:  # 用for循环读取文件
                            line = line.strip()  # 过滤杂质
                            get_line = dismap(line)
                            if get_line == "######":
                                target_num = target_num - 1
                                continue
                            if globals.get_value("DISMAP") == "true":
                                dismap_webapps = dismap_getwebapps(line)
                            if get_line:  # 判断是否结束
                                if globals.get_value("DISMAP") == "true":
                                    if dismap_webapps is None:
                                        continue
                                    else:
                                        print(now.timed(de=0) + color.yel_info() +
                                              " The result of dismap identifying is " + color.yellow(dismap_webapps))
                                target_list.append(get_line)  # 读取到的目标加入字典准备扫描
                                now_num += 1  # 读取到之后当前数量+1
                                furl = get_line
                                furl = url_check(furl)  # url格式检测
                                output("text", f"[*] {furl}")
                                if survival_check(furl):  # 如果存活检测失败就跳过
                                    print(now.timed(de=0) + color.red_warn() + color.red(
                                        f" Current:[{now_num}] Total:[{str(target_num)}] Survival check failed: {furl}"))

                                    continue
                                else:  # 存活不失败就正常显示
                                    print(now.timed(de=0) + color.yel_info() + color.yellow(
                                        f" Current:[{now_num}] Total:[{str(target_num)}] Scanning target: {furl}"))

                                if globals.get_value("DISMAP") == "true" and webapps is None:
                                    webapps_identify.append(dismap_getwebapps(line))
                                elif webapps is None:  # 判断是否要进行指纹识别
                                    webapps_identify.clear()  # 可能跟单个url冲突需要清理字典
                                    Identify.start(furl, webapps_identify)  # 识别指纹
                                    # print(webapps_identify)
                                elif r"all" in webapps:  # 不识别指纹运行所有
                                    print(now.timed(de=0) + color.yel_info() + color.yellow(
                                        " Specify to scan all vulnerabilities"))
                                    webapps_identify.append("all")
                                else:
                                    webapps_identify = webapps
                                    print(now.timed(de=0) + color.yel_info() + color.yellow(
                                        " Specify scan vulnerabilities for: "),
                                          end='')
                                    for count, w_i in enumerate(webapps_identify, start=1):
                                        print(color.cyan(w_i), end=' ')
                                        if count % len(webapps_identify) == 0:
                                            print(end='\n')
                                self.scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, furl)  # 开扫
                                joinall(gevent_pool)  # 运行协程池
                                wait(thread_poc, return_when=ALL_COMPLETED)  # 等待所有多线程任务运行完
                                if globals.get_value("DISMAP") == "true" and webapps is None:
                                    webapps_identify.clear()
                        print(now.timed(de=0) + color.yel_info() + color.yellow(
                            " Scan completed and ended"))
                case ["fofa", "shodan"]:  # 第三种调用fofa api
                    total = len(target)  # fofa api的总数，不出意外100个
                    if webapps is not None:
                        if r"all" in webapps:  # 不识别直接扫描所有类型
                            print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify to scan all vulnerabilities"))
                            webapps_identify.append("all")
                        else:
                            webapps_identify = webapps  # 扫描指定的类型
                            print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify scan vulnerabilities for: "),
                                  end='')
                            for count, w_i in enumerate(webapps_identify, start=1):
                                print(color.cyan(w_i), end=' ')
                                if count % len(webapps_identify) == 0:
                                    print(end='\n')
                    now_num = 0  # 当前第几个
                    for f_target in target:
                        fofa_target = url_check(f_target)
                        output("text", f"[*] {fofa_target}")
                        now_num += 1
                        if survival_check(fofa_target):
                            print(now.timed(de=0) + color.red_warn() + color.red(
                                f" Current:[{now_num}] Total:[{total}] Survival check failed: {fofa_target}"))

                            continue
                        else:
                            print(now.timed(de=0) + color.yel_info() + color.yellow(
                                f" Current:[{now_num}] Total:[{total}] Scanning target: {fofa_target}"))

                        if webapps is None:  # 需要指纹识别
                            webapps_identify.clear()
                            Identify.start(fofa_target, webapps_identify)  # 是否需要进行指纹识别
                        self.scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, fofa_target)
                        joinall(gevent_pool)  # 运行协程池
                        wait(thread_poc, return_when=ALL_COMPLETED)  # 等待所有多线程任务运行完
                    print(now.timed(de=0) + color.yel_info() + color.yellow(
                        " Scan completed and ended"))
                case _:
                    pass

    @staticmethod
    def scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, target):
        # 自动处理大小写的webapps类型: https://github.com/zhzyker/vulmap/commit/5e1ee00b0598b5dd5b9898a01fabcc4b84dc4e8c
        webapps_identify = [x.lower() for x in webapps_identify]
        if globals.get_value("DISMAP") == "true":
            webapps_identify = ','.join(webapps_identify)
        if r"weblogic" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.oracle_weblogic(target, gevent_pool)))
        if r"shiro" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_shiro(target, gevent_pool)))
        if r"activemq" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_activemq(target, gevent_pool)))
        if r"flink" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_flink(target, gevent_pool)))
        if r"fastjson" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.fastjson(target, gevent_pool)))
        if r"spring" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.spring(target, gevent_pool)))
        if r"solr" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_solr(target, gevent_pool)))
        if r"tomcat" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_tomcat(target, gevent_pool)))
        if r"elasticsearch" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.elasticsearch(target, gevent_pool)))
        if r"jenkins" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.jenkins(target, gevent_pool)))
        if r"nexus" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.nexus(target, gevent_pool)))
        if r"jboss" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.redhat_jboss(target, gevent_pool)))
        if r"unomi" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_unomi(target, gevent_pool)))
        if r"thinkphp" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.thinkphp(target, gevent_pool)))
        if r"drupal" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.drupal(target, gevent_pool)))
        if r"struts2" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_strtus2(target, gevent_pool)))
        if r"druid" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_druid(target, gevent_pool)))
        if r"laravel" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.laravel(target, gevent_pool)))
        if r"vmware" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.vmware(target, gevent_pool)))
        if r"saltstack" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.saltstack(target, gevent_pool)))
        if r"nodejs" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.nodejs(target, gevent_pool)))
        if r"exchange" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.exchange(target, gevent_pool)))
        if r"bigip" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.big_ip(target, gevent_pool)))
        if r"ofbiz" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_ofbiz(target, gevent_pool)))
        if r"qianxin" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.qiaixin(target, gevent_pool)))
        if r"ruijie" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.ruijie(target, gevent_pool)))
        if r"eyou" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.eyou(target, gevent_pool)))
        if r"coremail" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.coremail(target, gevent_pool)))
        if r"ecology" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.ecology(target, gevent_pool)))

    def scan_fofa(self):
        print(now.timed(de=0) + color.yel_info() + color.yellow(
            f" Use fofa api to search [{self.fofa_target}] and start scanning"))

        if globals.get_value("fofa_key"):  # 使用fofa api之前判断fofa信息是否正确
            print(now.timed(de=0) + color.red_warn() + color.red(
                " Check fofa email. Please replace key and email"))
            print(now.timed(de=0) + color.red_warn() + color.red(
                " Go to https://fofa.so/user/users/info find key and email"))
            print(now.timed(de=0) + color.red_warn() + color.red(
                " How to use key and email reference https://github.com/zhzyker/vulmap"))
            return []
        else:
            print(now.timed(de=0) + color.yel_info() + color.yellow(
                " Fofa email: " + globals.get_value("fofa_email")))
            print(now.timed(de=0) + color.yel_info() + color.yellow(
                " Fofa key: " + globals.get_value("fofa_key")))
        fofa_list = fofa(self.fofa_target, self.fofa_size)  # 调用fofa api拿到目标数组默认100个
        self.control_webapps("fofa", fofa_list, self.web_app)

    def scan_shodan(self):
        print(now.timed(de=0) + color.yel_info() + color.yellow(
            f" Use shodan api to search [{self.target_shodan}] and start scanning"))

        if globals.get_value("shodan_key"):  # 使用shodan api之前判断shodan信息是否正确
            print(now.timed(de=0) + color.red_warn() + color.red(
                " Check shodan key. Please replace key"))
            print(now.timed(de=0) + color.red_warn() + color.red(" Go to https://account.shodan.io/ find key"))
            print(now.timed(de=0) + color.red_warn() + color.red(
                " How to use key reference https://github.com/zhzyker/vulmap"))
            return
        else:
            print(now.timed(de=0) + color.yel_info() + color.yellow(
                " Shodan key: " + globals.get_value("shodan_key")))
        shodan_list = shodan_api(self.target_shodan)  # 调用shodan api拿到目标数组默认100个
        self.control_webapps("shodan", shodan_list, self.web_app)
