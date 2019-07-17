# coding: utf-8
#!/usr/bin/env python

import requests
import logging
from logging.config import fileConfig
from datetime import datetime, date, time, timedelta
import configparser
from anytree import AnyNode
import re

fileConfig('logging.conf')
logger = logging.getLogger()

config = configparser.ConfigParser()
config.read('config.ini')

regex_email = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

def vt_ip_to_file(parent):
    """
    Files downloaded from the IP address

    Output is a list of file nodes with sha256 value

    Example: 192.99.142.235

    https://developers.virustotal.com/v3.0/reference#domains-relationships

    """

    result = []

    if parent.type != 'ip_address':
        return result

    ip_address = parent.id

    headers = {'x-apikey': config.get('VirusTotal','api_key')}
    params = {'limit': int(config.get('VirusTotal', 'limit'))}
    re_url = config.get('VirusTotal', 'ip_downloaded_files').replace('{ip}', ip_address)

    try:
        logger.debug('[Processing] Relationship query - VT: IP to downloaded files - %s', ip_address)
        r = requests.get(re_url, headers=headers, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - VT: IP to downloaded files - %s', ip_address)
        return result

    logger.debug('[Done] Relationship query - VT: IP to downloaded files - %s', ip_address)

    if r.status_code == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:

            if 'attributes' in i:
                child_node = AnyNode(id=i['attributes']['sha256'],
                                     type='file',
                                     relation='VT: IP to downloaded file',
                                     parent=parent)

                result.append(child_node)

    return result

def vt_domain_to_file(parent):
    """
    Files downloaded from the domain

    Output is a list of file nodes with sha256 value

    Example: xnz.freetzi.com

    https://developers.virustotal.com/v3.0/reference#domains-relationships

    """

    result = []

    if parent.type != 'domain':
        return result

    domain = parent.id

    headers = {'x-apikey': config.get('VirusTotal','api_key')}
    params = {'limit': int(config.get('VirusTotal', 'limit'))}
    re_url = config.get('VirusTotal', 'domain_downloaded_files').replace('{domain}', domain)

    try:
        logger.debug('[Processing] Relationship query - VT: domain to downloaded files - %s', domain)
        r = requests.get(re_url, headers=headers, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - VT: domain to downloaded files - %s', domain)
        return result

    logger.debug('[Done] Relationship query - VT: domain to downloaded files - %s', domain)

    if r.status_code == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:

            if 'attributes' in i:
                child_node = AnyNode(id=i['attributes']['sha256'],
                                     type='file',
                                     relation='VT: domain to downloaded file',
                                     parent=parent)

                result.append(child_node)

    return result


def vt_domain_to_ip(parent):
    """
    DNS resolutions for the domain

    Output is a list of IP address nodes

    Example: xnz.freetzi.com

    https://developers.virustotal.com/v3.0/reference#domains-relationships

    """

    result = []

    if parent.type != 'domain':
        return result

    domain = parent.id

    headers = {'x-apikey': config.get('VirusTotal','api_key')}
    params = {'limit': int(config.get('VirusTotal', 'limit'))}
    re_url = config.get('VirusTotal', 'domain_resolutions').replace('{domain}', domain)

    try:
        logger.debug('[Processing] Relationship query - VT: domain to resolution ip - %s', domain)
        r = requests.get(re_url, headers=headers, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - VT: domain to resolution ip - %s', domain)
        return result

    logger.debug('[Done] Relationship query - VT: domain to resolution ip - %s', domain)

    if r.status_code == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:

            if 'attributes' in i:
                child_node = AnyNode(id=i['attributes']['ip_address'],
                                     type='ip_address',
                                     relation='VT: domain to resolution ip',
                                     parent=parent)

                result.append(child_node)

    return result


def vt_file_to_ip(parent):
    """
    IP addresses contacted by the file

    Output is a list of IP address nodes

    Example: c3f5add704f2c540f3dd345f853e2d84

    https://developers.virustotal.com/v3.0/reference#domains-relationships

    """

    result = []

    if parent.type != 'file':
        return result


    file_hash = parent.id

    headers = {'x-apikey': config.get('VirusTotal','api_key')}
    params = {'limit': int(config.get('VirusTotal', 'limit'))}
    re_url = config.get('VirusTotal', 'file_contacted_ips').replace('{file}', file_hash)

    try:
        logger.debug('[Processing] Relationship query - VT: file to contacted ip - %s', file_hash)
        r = requests.get(re_url, headers=headers, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - VT: file to contacted ip - %s', file_hash)
        return result

    logger.debug('[Done] Relationship query - VT: file to contacted ip - %s', file_hash)

    if r.status_code == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:

            child_node = AnyNode(id=i['id'],
                                type='ip_address',
                                relation='VT: file to contacted ip',
                                parent=parent)

            result.append(child_node)

    return result


def vt_file_to_domain(parent):
    """
    Domains contacted by the file.

    Output is a list of domains

    Example: c3f5add704f2c540f3dd345f853e2d84

    https://developers.virustotal.com/v3.0/reference#domains-relationships

    """

    result = []

    if parent.type != 'file':
        return result


    file_hash = parent.id

    headers = {'x-apikey': config.get('VirusTotal','api_key')}
    params = {'limit': int(config.get('VirusTotal', 'limit'))}
    re_url = config.get('VirusTotal', 'file_contacted_domains').replace('{file}', file_hash)

    try:
        logger.debug('[Processing] Relationship query - VT: file to contacted domains - %s', file_hash)
        r = requests.get(re_url, headers=headers, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - VT: file to contacted domains - %s', file_hash)
        return result

    logger.debug('[Done] Relationship query - VT: file to contacted domains - %s', file_hash)

    if r.status_code == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:

            child_node = AnyNode(id=i['id'],
                                type='domain',
                                relation='VT: file to contacted domain',
                                parent=parent)

            result.append(child_node)

    return result


def vt_file_to_file(parent):
    """
    Files that executed the file.

    Output is a list of file hashes

    Example: c0531f812a1ec5e825f7250f7b52db7621ecf93d973f0e3ba1aa0372e0f559f2

    https://developers.virustotal.com/v3.0/reference#domains-relationships

    """

    result = []

    if parent.type != 'file':
        return result


    file_hash = parent.id

    headers = {'x-apikey': config.get('VirusTotal','api_key')}
    params = {'limit': int(config.get('VirusTotal', 'limit'))}
    re_url = config.get('VirusTotal', 'file_execution_parents').replace('{file}', file_hash)

    try:
        logger.debug('[Processing] Relationship query - VT: file to execution parents - %s', file_hash)
        r = requests.get(re_url, headers=headers, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - VT: file to execution parents - %s', file_hash)
        return result

    logger.debug('[Done] Relationship query - VT: file to execution parents - %s', file_hash)

    if r.status_code == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:

            if 'attributes' in i:
                child_node = AnyNode(id=i['attributes']['sha256'],
                                     type='file',
                                     relation='VT: file to execution parent',
                                     parent=parent)

                result.append(child_node)

    return result


def qax_domain_to_ip(parent):
    """
    Private data source of QiAnXin

    DNS resolutions (A record) for the domain

    Output is a list of IP addresses

    Example: xnz.freetzi.com

    https://wiki.qianxin-inc.cn/display/360JSYJ/flint

    """

    result = []

    if parent.type != 'domain':
        return result


    domain = parent.id

    params = {'limit': int(config.get('QiAnXin_PDNS', 'limit')),
              'start': int(config.get('QiAnXin_PDNS', 'start')),
              'end': int(config.get('QiAnXin_PDNS', 'end')),
              'mode': int(config.get('QiAnXin_PDNS', 'mode')),
              'rtype': int(config.get('QiAnXin_PDNS', 'rtype'))}

    re_url = config.get('QiAnXin_PDNS', 'flint').replace('{domain}', domain)

    try:
        logger.debug('[Processing] Relationship query - QAX: domain to resolution ip - %s', domain)
        r = requests.get(re_url, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - QAX: domain to resolution ip - %s', domain)
        return result

    logger.debug('[Done] Relationship query - QAX: domain to resolution ip - %s', domain)

    if r.status_code == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:

            for j in i['rdata'].split(';'):
                if j != '':
                    child_node = AnyNode(id=j,
                                         type='ip_address',
                                         relation='QAX: domain to resolution ip',
                                         parent=parent)

                    result.append(child_node)

    return result

def qax_domain_to_email(parent):
    """
    Private data source of QiAnXin

    Registrant email for the domain in Whois record

    Output is a list of emails

    Example: freetzi.com

    https://wiki.qianxin-inc.cn/display/360JSYJ/detail

    """

    result = []

    if parent.type != 'domain':
        return result

    domain = parent.id

    re_url = config.get('QiAnXin_Whoisdb', 'registrant_email').replace('{domain}', domain)

    try:
        logger.debug('[Processing] Relationship query - QAX: domain to whois email - %s', domain)
        r = requests.get(re_url, timeout=5)

    except:
        logger.debug('[Error] Relationship query - QAX:  domain to whois email - %s', domain)
        return result

    logger.debug('[Done] Relationship query - QAX: domain to registrant email - %s', domain)

    if r.json()['code'] == 200 and 'registrantEmail' in r.json()['data']:

        email = r.json()['data']['registrantEmail'][0]
        if re.search(regex_email, email):
            child_node = AnyNode(id=email,
                                 type='email',
                                 relation='QAX: domain to whois email',
                                 parent=parent)

            result.append(child_node)

    return result

def qax_email_to_domain(parent):
    """
    Private data source of QiAnXin

    Domain names registered in the same email

    Output is a list of domains

    Example: 373192510@qq.com

    https://wiki.qianxin-inc.cn/display/360JSYJ/reverse

    """

    result = []

    if parent.type != 'email':
        return result

    email = parent.id

    params = {'limit': int(config.get('QiAnXin_Whoisdb', 'reverse_email_limit'))}
    re_url = config.get('QiAnXin_Whoisdb', 'reverse_email').replace('{email}', email)

    try:
        logger.debug('[Processing] Relationship query - QAX: Whois email to domains - %s', email)
        r = requests.get(re_url, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - QAX: Whois email to domains - %s', email)
        return result

    logger.debug('[Done] Relationship query - QAX: Whois email to domains - %s', email)

    if r.json()['code'] == 200 and len(r.json()['data']) > 0:
        for i in r.json()['data']:
            child_node = AnyNode(id=i,
                                 type='domain',
                                 relation='QAX: Whois email to domain',
                                 parent=parent)

            result.append(child_node)

    return result


def qax_file_to_ip(parent):
    """
    Private data source of QiAnXin

    IP addresses contacted by the file

    Output is a list of IP addresses

    Example: e889544aff85ffaf8b0d0da705105dee7c97fe26

    https://wiki.qianxin-inc.cn/display/360JSYJ/reverse

    """

    result = []

    if parent.type != 'file':
        return result

    file_hash = parent.id

    params = {'apikey': config.get('QiAnXin_TI', 'api_key'),
              'param':file_hash}
    re_url = config.get('QiAnXin_TI', 'file_reputation')

    try:
        logger.debug('[Processing] Relationship query - QAX: file to contacted IPs - %s', file_hash)
        r = requests.get(re_url, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - QAX: file to contacted IPs - %s', file_hash)
        return result

    logger.debug('[Done] Relationship query - QAX: file to contacted IPs - %s', file_hash)

    if r.json()['status'] == 10000 and len(r.json()['data']) > 0:
        for i in r.json()['data']:
            if 'network' in i and 'ip' in i['network']:
                for j in i['network']['ip']:
                    child_node = AnyNode(id=j,
                                         type='ip_address',
                                         relation='QAX: file to contacted ip',
                                         parent=parent)

                    result.append(child_node)

    return result

def qax_file_to_domain(parent):
    """
    Private data source of QiAnXin

    Domains contacted by the file

    Output is a list of domains

    Example: 46173adc26721fb54f6e1a1091a892d4

    https://wiki.qianxin-inc.cn/display/360JSYJ/reverse

    """

    result = []

    if parent.type != 'file':
        return result

    file_hash = parent.id

    params = {'apikey': config.get('QiAnXin_TI', 'api_key'),
              'param':file_hash}
    re_url = config.get('QiAnXin_TI', 'file_reputation')

    try:
        logger.debug('[Processing] Relationship query - QAX: file to contacted domains - %s', file_hash)
        r = requests.get(re_url, params=params, timeout=5)

    except:
        logger.debug('[Error] Relationship query - QAX: file to contacted domains - %s', file_hash)
        return result

    logger.debug('[Done] Relationship query - QAX: file to contacted domains - %s', file_hash)

    if r.json()['status'] == 10000 and len(r.json()['data']) > 0:
        for i in r.json()['data']:
            if 'network' in i and 'domain' in i['network']:
                for j in i['network']['domain']:
                    child_node = AnyNode(id=j,
                                         type='domain',
                                         relation='QAX: file to contacted domain',
                                         parent=parent)

                    result.append(child_node)


    return result

