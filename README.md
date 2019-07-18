# IOC Explorer - Explore IOCs in iterative way

![illustration](pics/illustration.png)

## Introduction

threat hunting

problem

multiple sources: community sources or paid sources

repeat input

random choose

major advantage

## Quick Start

1. Open config.ini file, and type in your API Key of VirusTotal or QiAnXin_TI section
2. Open ioc.csv file, and type in your query IOC (eg., 'domain, xnz.freetzi.com')
3. Run the tool in command line
```
$python explorer.py
```
4. Go to './results' directory to check your query result

## Usage in Details

### Initial Configuration

There are some settings to configure before first run. Basiclly, all settings stored in 'config.ini' file can be splitted into two categories: query behavior setting and threat intelligence setting.

'depth' setting in 'general' section is an important query behavior setting. It defines the times of iterative queries, which will query intelligence sources based on IOCs returned on previous queries. Default setting is 'depth=3'. If user increases the value, the tool carries additional queries on previous returned IOCs. 

Each threat intelligence has its own but different settings. However, API key is the most common setting for intelligence sources, which is also required.

### Input IOC

Currently, 4 IOC types are supported, namely as followings,

- email address
- file hash(MD5/SHA1/SHA256)
- ip address
- domain name

CSV file (by default, ./ioc.csv) is the place to input IOC for query. The CSV file has following format for data,

```
IOC_type, IOC Value
```

For example,

```
domain, xnz.freetzi.com
file, c0531f812a1ec5e825f7250f7b52db7621ecf93d973f0e3ba1aa0372e0f559f2
email, 373192510@qq.com
ip_address, 192.99.142.235
```

### Output Result



Format: TXT and JSON

```
AnyNode(id='373192510@qq.com', type='email')
├── AnyNode(id='qq758.com', relation='QAX: Whois email to domain', type='domain')
│   ├── AnyNode(id='5292086@qq.com', relation='QAX: domain to whois email', type='email')
│   │   ├── AnyNode(id='ltcp3.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='lzskqc.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='df796.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='mir900.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='888hl.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='jiemianpaomo.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='qx969.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='c888c.com', relation='QAX: Whois email to domain', type='domain')
│   │   ├── AnyNode(id='982307.com', relation='QAX: Whois email to domain', type='domain')
│   │   └── AnyNode(id='ac0028.com', relation='QAX: Whois email to domain', type='domain')
│   ├── AnyNode(id='47.91.202.66', relation='VT: domain to resolution ip', type='ip_address')
│   │   ├── AnyNode(id='4bf7e7e6c78c1a69def4beef216ad52dbabae1f831f49067e3b29f8a7a62d71e', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='e682dfcdde010f6e15bae0d843696f6ae8d5a85e75441660b782789ee747f075', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='88f089e2e069ca698fa498fb5ba5f46fd95d3c8ee5b4c5c6587eae8d2db43fe7', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='39a75a83af8d38202ab05de7ac9beae6e00d21501867601cc2a86094c79d6f16', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='1630ab0121c4df64230045ef86ee54e5ee05bd371c2b3c26bcdb0ef3a0d2360f', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='7d04f7431bbfa41a04bcc7e6b98b9de0d919756c4c671c5785c99fff45f16402', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='9b342ae7f25d65bdb817d8c995f3211ac398e41575fc5d149d994c1dcb008f0a', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='39d6bba9f294f11f84933e48483aff12a9efc5c7d6eb4f57a8d36ef8bd71823e', relation='VT: IP to downloaded file', type='file')
│   │   ├── AnyNode(id='d37608c9b93ae18c5ed5d376e32449f95358f708a35cd8b06431ca2be733f87e', relation='VT: IP to downloaded file', type='file')
│   │   └── AnyNode(id='fb7595b2d6f1cc89cca75ec06186c228274e95fb6c3e233e8de2e804284ab8c1', relation='VT: IP to downloaded file', type='file')
```

Sample
There are some sample results in './samples' directory for reference.

## Threat Intelligence Sources

VirusTotal

QiAnXin

Add your own data source

## Future Plan

Challenges

Add tags

Known Bad, Known White, 

Your ideas or suggestions are appreciated
lion.gu@gmail.com
