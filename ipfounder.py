#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Ip Founder (python2.7.*)
~~~~~~~~~~~~~~~~~~

各地节点（大部分国内 + 少部分国外）ping方式获取域名的所有节点ip，支持多域名查询。

包含内容：
1、ipfounder.py      主程序）
2、requirements.txt（依赖库）

usage:

    python ipfounder.py --help


Author:

    amm907

"""

import re
import os
import sys
import time
import requests
import websocket
from json import loads, dumps
from optparse import OptionParser


class Ipfounder(object):
    def __init__(self):
        self.parser = OptionParser()
        self.parser.add_option(
            '-p', '--ping-only',
            action='store_true',
            dest='ping',
            default=False,
            help='仅用ping扫描。（默认模式）'
        )
        self.parser.add_option(
            '-g', '--get-only',
            action='store_true',
            dest='get',
            default=False,
            help='仅用get请求扫描'
        )
        self.parser.add_option(
            '-v', '--level',
            action='store',
            dest='lv',
            default='1',
            help='扫描等级,1-3,默认1'
        )
        self.parser.add_option(
            '-f', '--file',
            action='store',
            dest='filename',
            help='扫描的域名列表文件'
        )
        (self.opt, self.args) = self.parser.parse_args()

    def discover(self):
        res = []
        res_str = ''
        filename = self._get_file_name()
        with open(filename, 'rb') as f:
            domain_list = [i.split(' ')[0].strip() for i in f.readlines()]
            print domain_list
            print('[+] domains number: %d' % len(domain_list))
            print('[+] Starting now...')

        # 17ce
        p = 'code=d6966976efe5bffff1daf6c3d4388cfe&ut=1563874136'
        if self.opt.lv == '1':
            for d in domain_list:
                ips = _scan_17ce(d, p)
                if ips == 0:
                    print('[-] SCAN CANCELED !')
                    break
                dict_temp1 = {d: ips}
                res.append(dict_temp1)
                res_str += '%s\t%s\n' % (d.ljust(35), ', '.join(ips))

        # chinaz
        if self.opt.lv == '2':
            count = 1
            for d in domain_list:
                dict_temp2 = {d: _scan_chinaz(d, count)}
                res.append(dict_temp2)
                count += 1

        # aizhan
        if self.opt.lv == '3':
            pass

        print('\r[+] =================================================')
        print('[+] ALL DONE! Outputting results...')
        print('%s' % res)
        print('%s' % res_str)

        return res

    def _get_file_name(self):
        if not os.path.exists(self.opt.filename):
            print('[ERROR] File not found: %s' % self.opt.filename)
            exit(-1)
        return self.opt.filename


def _scan_17ce(domain, params):
    ip_list = []
    res_last = 'start'
    domain = 'http://' + domain
    # code = '704d19676de490f9c3237a4adccfb46f'
    # ut = '1563870584'
    sock = websocket.create_connection('wss://wsapi.17ce.com:8001/socket/?user=yiqice@qq.com&%s' % params)#code={code}&ut={ut}'.format(code=code, ut=ut))
    data = '{"txnid":1,"nodetype":1,"num":1,"Url":"%s","TestType":"HTTP","Host":"","TimeOut":10,"Request":"GET",' \
           '"NoCache":false,"Speed":0,"Cookie":"","Trace":false,"Referer":"","UserAgent":"","FollowLocation":3,' \
           '"GetMD5":true,"GetResponseHeader":true,"MaxDown":1048576,"AutoDecompress":true,"type":1,"isps":[0,1,2,6,7,8,' \
           '17,18,19,3,4],"pro_ids":[12,49,79,80,180,183,184,188,189,190,192,193,194,195,196,221,227,235,236,238,241,243,' \
           '250,346,349,350,351,353,354,355,356,357,239,352,3,5,8,18,27,42,43,46,47,51,56,85],"areas":[0,1,2,3],' \
           '"SnapShot":true,"postfield":"","PingCount":10,"PingSize":32,"SrcIP":""}' % domain
    sock.send(data)

    # print "##" + sock.recv()
    while True:
        res = loads(sock.recv())
        if res['rt'] != 1:
            print '[ERROR] Error returned: %s' % res
            print '[-] Last recv: %s' % res_last
            return 0
        if 'TotalCount' in res.get('data', ''):
            print '[+] SCAN COMPLETED !'
            break
        res_last = res
        if 'srcip' in res_last.get('data', ''):
            ip_list.append(res_last['data']['srcip']['srcip'])
    sock.close()
    res_list = list(set(ip_list))

    return res_list


def _scan_chinaz(domain, num):
    count = 0
    ip_list = []
    _set = ['\\', '|', '/', '-']
    with open('chuid.txt', 'rb') as f:
        uid_list = [uid[:-2] for uid in f.readlines()]
    url = 'http://ping.chinaz.com/iframe.ashx?t=ping&callback=jQuery1113010265421639967198_%s' % \
          str(int(round(time.time() * 1000)))
    for uid in uid_list:
        params = {
            'guid': uid,
            'host': domain,
            'ishost': '0',
            'encode': 'fpZGPApnKYR7PkPnijDBQRGFw7rZkcKL',
            'checktype': '0'
        }
        resp = requests.post(url, data=params)
        content = loads(re.match(".*?({.*}).*", resp.content).group(1).replace('state', '"state"')
                        .replace('msg', '"msg"').replace('result', '"result"').replace('ip:', '"ip":')
                        .replace('ipaddress', '"ipaddress"').replace('responsetime', '"responsetime"')
                        .replace('ttl', '"ttl"').replace('bytes', '"bytes"').replace("'", '"'))
        try:
            ip_list.append(content['result']['ip'])
        except:
            pass
        count += 1
        msg = '[%s] Processing, please wait... %d domains finished!' % (_set[count % 4], num)
        _msg(msg)

    res_list = list(set(ip_list))

    return res_list


def _scan_aizhan():
    ip_list = set()

    url = 'https://ping.aizhan.com/api/ping?callback=flightHandler'
    headers = {
        'Cookie': 'Hm_lvt_b37205f3f69d03924c5447d020c09192=1563430565; Hm_lpvt_b37205f3f69d03924c5447d020c09192=1563430626; _csrf=ba88576d8a1fdcde1fa66873df64a7fefbdf58145974ba2d4830a04a8afe1ab7a%3A2%3A%7Bi%3A0%3Bs%3A5%3A%22_csrf%22%3Bi%3A1%3Bs%3A32%3A%22U0su7Xzu3zTItubiSzsomlM1y1AJNUiW%22%3B%7D; allSites=amm907.com%2C0'
    }
    params = {
        "type": "ping",
        "domain": "amm907.com",
        "_csrf": "c2djR2lFWXQmVxAyXh0jAUAdNw4dMDsdIB0QKAQpFEUKViINJxAwIw=="
    }
    resp = requests.post(url, data=params, headers=headers)
    content = loads(resp.content[16:][:-1])
    for i in content.keys():
        ip_list.add(content[i]['ip'])

    return list(ip_list)


def _msg(msg=None, left_align=True, line_feed=False):
    if left_align:
        sys.stdout.write('\r' + msg)
    if line_feed:
        sys.stdout.write('\n')
    sys.stdout.flush()


def main():
    ipfounder = Ipfounder()
    ipfounder.discover()
    # print ipfounder.scan_aizhan()


if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding('utf8')
    main()
