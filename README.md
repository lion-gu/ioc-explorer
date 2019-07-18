# IOC Explorer - Explore IOCs in iterative way

[todo] insert picture

## Introduction

threat hunting

problem

multiple sources: community sources or paid sources

repeat input

random choose

major advantage

## Quick Start

1.

## Usage in Details

### Configuration

ini file

depth

API key

### Input IOC

Currently, 4 IOC types are supported, namely as followings,
email
file hash(MD5/SHA1/SHA256)
ip address
domain names

CSV file (by default, ./ioc.csv) is the place to input IOC for query. The CSV file has following format for data,

IOC_type, IOC Value

For example,

domain, xnz.freetzi.com
file, c0531f812a1ec5e825f7250f7b52db7621ecf93d973f0e3ba1aa0372e0f559f2
email, 373192510@qq.com
ip_address, 192.99.142.235

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
