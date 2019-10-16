#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import math
import optparse
import time
import random
import shodan
import string
import sys
import logging


proxies = {'http': 'socks5://127.0.0.1:1080',
           'https': 'socks5://127.0.0.1:1080'}


class SearchShodan(object):
    """docstring for ClassName"""

    def __init__(self, query, destfile):
        SHODAN_API_KEY = "yK0AfFxENdV4bzGQtQZOPE0ExNJ1jS2y"
        api = shodan.Shodan(SHODAN_API_KEY)
        self.api = api
        self.query = query
        if destfile:
            self.file = destfile
        else:
            self.file = self.file_name_set()

    def results_page_num(self):
        count = self.api.count(self.query)
        logging.info('Number of results obtained from count '
                     'api: {}'.format(count['total']))
        # Show the results
        logging.info('Results found: {}'.format(count['total']))
        page = int(math.ceil(count['total'] / 100.0) + 1)
        logging.info('Page: {}'.format(page - 1))
        return page

    def search(self, page=1):
        # Wrap the request in a try/ except block to catch errors
        try:
            # Search Shodan
            logging.info('Current page: %d', page)
            results = self.api.search(self.query, page)
            if self.file:
                self.save_results(results)
        except shodan.APIError as e:
            logging.error('Error: {}'.format(e))

    def file_name_set(self):
        pre_file_name = self.query[:5]
        time_str = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        file_name = '_'.join([pre_file_name, time_str]) + '.txt'
        return file_name

    def random_string(self, stringLength):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(stringLength))

    def save_results(self, results):
        with open(self.file, 'a+') as res_file:
            for result in results['matches']:
                # 将结果拼接成协议://ip:port模式
                schema = str(result['_shodan']['module'])
                if schema in 'http-simple-new':
                    schema = 'http'
                elif schema in 'https-simple-new':
                    schema = 'https'
                ip = str(result['ip_str'])
                port = str(result['port'])
                URI = schema + '://' + ip + ':' + port
                res_file.write(URI + '\n')

    def get_all_results(self):
        page = self.results_page_num()
        for num in range(1, page):
            self.search(num)
            time.sleep(10)


def get_parser():
    shodan_mxd_description = (
        'This tool is created for security research. '
        'It cannot be used in illegal ways, '
        'the user should be resposible for the usage of it.')
    shodan_usage = 'usage: %prog [options] arg1 arg2'
    parser = optparse.OptionParser(usage=shodan_usage,
                                   description=shodan_mxd_description)
    parser.add_option('-q', '--query', action='store', dest='query',
                      help='The condition to be query.')
    parser.add_option('-f', '--file', action='store', dest='destfile',
                      help='The results to be save.')
    return parser


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s",
                        # 注意月份和天数，这里的格式化符与time模块相同
                        datefmt='%Y-%m-%d  %H:%M:%S %a')
    parser = get_parser()
    (options, args) = parser.parse_args()
    if not options.query:
        print('No condition is specified.')
        parser.print_help()
        sys.exit()
    search_shodan = SearchShodan(options.query, options.destfile)
    search_shodan.get_all_results()

