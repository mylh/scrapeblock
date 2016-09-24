from collections import defaultdict
import datetime as dt
import re
import socket
import os
import sys

from logbook import Logger
import dateutil.parser

from .conf import settings

log = Logger(__name__)


def analyze_log(input_file, start):
    counts = count_ips(input_file, start)
    threshold = settings.get('analyze.threshold')
    scrapers = {}
    for ip, count in counts.items():
        if count > threshold:
            scrapers[ip] = {
                'count': count
                }
    del counts
    log.debug('Scrapers count: %d' % len(scrapers))
    resolve_ips(scrapers)
    with open(os.path.expanduser(
                  settings.get('analyze.analyze_file')), 'wt') as out:
        for ip, data in scrapers.items():
            out.write(
                '%s, %s, %s\n' %
                (ip, data['host'], data['count']))


def resolve_ips(data):
    """Get hostname for IP"""
    for ip in data:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            log.debug('Resolved %s to %s' % (ip, hostname))
        except Exception as e:
            hostname = ip
            log.debug('Resolving %s failed: %s' % (ip, e))
        data[ip]['host'] = hostname


def count_ips(input_file, start):
    """Count number of requests per ip."""
    log.info('Reading log, counting records after %s' % start)
    res = defaultdict(lambda: 0)

    re_ip = re.compile(settings.get('analyze.logformat.host'))
    re_time = re.compile(settings.get('analyze.logformat.time'))
    total_lines = 0
    for line in input_file:
        total_lines += 1
        ip_match = re_ip.search(line)
        time_match = re_time.search(line)
        if not ip_match or not time_match:
            continue
        ip = ip_match.group(1)
        time = dateutil.parser.parse(
            time_match.group(1),
            fuzzy=True,
            ignoretz=True)

        if total_lines % 100 == 0:
            sys.stdout.write(
                "\rLines processed: %d time: %s" % (total_lines, time))
            sys.stdout.flush()

        if time < start:
            continue
        res[ip] += 1

    print('\n')
    log.info('Total lines read: %d' % total_lines)
    return res
