# coding: utf-8
#!/usr/bin/env python

import requests
import logging
from logging.config import fileConfig
import configparser
from anytree import AnyNode, RenderTree
from anytree.exporter import DotExporter, JsonExporter
import csv
import relationship
import argparse
from datetime import datetime

fileConfig('logging.conf')
logger = logging.getLogger()

config = configparser.ConfigParser()
config.read('config.ini')

def build_ioc_relation(root):
    """

    """
    ioc_list = [root]
    query_queue = [root]
    ioc_value_list = [root.id]

    relation_list = [
                     relationship.qax_domain_to_ip,
                     relationship.qax_domain_to_email,
                     relationship.qax_email_to_domain,
                     relationship.qax_file_to_ip,
                     relationship.qax_file_to_domain,
                     relationship.vt_ip_to_file,
                     relationship.vt_domain_to_file,
                     relationship.vt_domain_to_ip,
                     relationship.vt_file_to_ip,
                     relationship.vt_file_to_domain,
                     relationship.vt_file_to_file
    ]

    query_depth = int(config.get('general','depth'))

    for seed in range(query_depth):

        queue_temp = []

        for ioc in query_queue:

            for relation in relation_list:
                result_list = relation(ioc)

                for r in result_list:
                    if r.id not in ioc_value_list:
                        ioc_value_list.append(r.id)
                        ioc_list.append(r)
                        queue_temp.append(r)

        query_queue = queue_temp

    return ioc_list


def main(ioc_file, output_dir):

    with open(ioc_file) as csvfile:
        iocreader = csv.reader(csvfile, delimiter=',')
        for row in iocreader:
            root = AnyNode(id=row[1], type=row[0])

            logger.info('=========Start to explore IOC: %s', root.id)

            ioc_list = build_ioc_relation(root)

            timestamp = datetime.now().strftime('%Y%m%d%H%M')
            query_depth = config.get('general','depth')

            txtfile = output_dir + root.id + '_depth_'+ query_depth + '_'+timestamp + '.txt'
            file = open(txtfile, "w")
            file.write(str(RenderTree(root)))
            file.close()

            logger.info('Export IOCs to TXT file: %s', txtfile)

            jsonfile = output_dir + root.id + '_depth_'+ query_depth + '_'+timestamp + '.json'
            file = open(jsonfile, "w")
            exporter = JsonExporter(indent=2, sort_keys=False)
            exporter.write(root, file)
            file.close()

            logger.info('Export IOCs to JSON file: %s', jsonfile)

            logger.info('=========Done exploration for IOC: %s', root.id)

    return

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='ioc_explorer',
                                     description='Explorer IOCs across multiple sources in iterative way')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-i', dest='ioc_file', default='./ioc.csv',
                        help="""input csv file. Default file: ./ioc.csv. 
                        Format of csv file: ioc type, ioc value. For example: domain, google.com""")
    parser.add_argument('-o', dest='out_dir', default='./results/',
                        help='output directory. Default directory: ./results')
    args = parser.parse_args()

    main(args.ioc_file, args.out_dir)

