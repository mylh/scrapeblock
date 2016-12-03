import datetime as dt
import sys
import os

import click
from logbook import Logger, StreamHandler, RotatingFileHandler, lookup_level
import dateutil

from .conf import settings
from .analyze import analyze_log
from .block import process, block_cloudflare, block_iptables

log = None


def setup_logging(log_level):
    if log_level == 'debug':
        StreamHandler(sys.stdout, bubble=True).push_application()
    level_name = log_level or settings.get("log.level")
    level = lookup_level(level_name.upper())
    if settings.get('log.screen') and log_level != 'debug':
        StreamHandler(sys.stdout, level=level, bubble=True).push_application()
    RotatingFileHandler(
        os.path.expanduser(settings.log['path']),
        backup_count=settings.log['rotate'],
        level=level, bubble=True
        ).push_application()


@click.group()
@click.option('--config', type=click.Path(),
              help='Path to config file', default='~/.scrapeblock/config.yml')
@click.option('--debug', default=False, is_flag=True,
              help='Override log level from config file')
def cli(config, debug=False):
    global log
    if config is not None:
        setattr(settings, 'load_path', config)
    log_level = None
    if debug:
        log_level = 'debug'
    setup_logging(log_level)
    log = Logger(__name__)


@cli.command()
@click.option('--logfile', type=click.Path(exists=True),
              help='Specify log file path instead of settings', )
@click.option('--start',
              help='Start date to parse, default -1 day from current time', )
def analyze(logfile=None, start=None):
    """Analyze logfile for scrapers"""
    if logfile is None:
        logfiles = settings.get('analyze.logfile', [])
        if isinstance(logfiles, str):
            logfiles = [logfiles]
    else:
        logfiles = [logfile]
    if start is None:
        start = dt.datetime.now() - dt.timedelta(days=1)
    else:
        start = dateutil.parser.parse(start, fuzzy=True, ignoretz=True)
    for logfile in logfiles:
        log.info('Processing log: %s' % logfile)
        try:
            with open(logfile, 'rt') as inp:
                analyze_log(inp, start)
        except IOError as e:
            log.error('Error processing file: %s - %s' % (logfile, str(e)))


def write_blocked_results(blocked):
    with open(os.path.expanduser(
            settings.get('block.blocked_file')), 'w') as out:
        for ip in blocked:
            out.write('{ip}\n'.format(ip=ip))


def read_previously_blocked():
    blocked = []
    try:
        with open(os.path.expanduser(
                 settings.get('block.blocked_file')), 'rt') as inp:
            for line in inp:
                blocked.append(line.strip())
    except IOError:
        pass
    return set(blocked)


@cli.command()
def block():
    """Block IPs based on analyze results"""
    data = {}
    # get analyze results
    with open(os.path.expanduser(
            settings.get('analyze.analyze_file')), 'rt') as inp:
        for line in inp:
            ip, host, count = line.split(',')
            data[ip] = {'count': int(count), 'host': host}

    # process IPs to get what to block and what to notify
    blocklist, notifylist = process(data)

    # log notify results
    for ip, dat in notifylist.items():
        log.notice(
            'Suspicios host: %s, %s, %d\n' % (ip, dat['host'], dat['count']))

    # fetching previously blocked IPs to check new IPs against it
    blocked = read_previously_blocked()

    to_block = {}
    cl_blocked = {}
    ipt_blocked = {}
    for ip in blocklist:
        if ip not in blocked:
            to_block[ip] = blocklist[ip]

    if settings.get('cloudflare.enabled'):
        log.info('Blocking %d IPs on cloudflare' % len(to_block))
        cl_blocked = block_cloudflare(to_block)

    if settings.get('iptables.enabled'):
        log.info('Blocking %d IPs on iptables' % len(to_block))
        ipt_blocked = block_iptables(to_block)

    # set operations
    blocked = blocked | (set(cl_blocked.keys()) | set(ipt_blocked.keys()))
    write_blocked_results(blocked)


if __name__ == '__main__':
    cli()
