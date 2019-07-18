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

Sample

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
