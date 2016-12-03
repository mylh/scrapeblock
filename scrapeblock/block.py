import datetime as dt

from logbook import Logger
import requests

from .conf import settings

log = Logger(__name__)


def one_in(value, items):
    for i in items:
        if i in value:
            return True
    return False


def process(data):
    """Process data to identify what IP to block

    Checks whitelist and blacklist. Hosts that does not match threshold and not
    appears in blacklist are logged in notify_file for manual descision.
    """
    blacklist = settings.get('block.blacklist', [])
    whitelist = settings.get('block.whitelist', [])
    threshold = settings.get('block.threshold')

    block = {}
    notify = {}
    for ip, dat in data.items():
        if one_in(dat['host'], blacklist):
            block[ip] = dat
            continue
        if one_in(dat['host'], whitelist):
            continue
        if dat['count'] > threshold:
            block[ip] = dat
        else:
            notify[ip] = dat
    return block, notify


def call_cloudflare(method, data=None, delete=False):
    endpoint = 'https://api.cloudflare.com/client/v4/'
    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Key':  settings.get('cloudflare.api_key'),
        'X-Auth-Email': settings.get('cloudflare.auth_email'),
        }
    log.debug('Headers: %s' % headers)
    url = endpoint + method
    log.debug('Requesting %s with %s' % (url, data or ''))
    if delete:
        res = requests.delete(url, timeout=10, headers=headers)
    elif data is None:
        res = requests.get(url, timeout=10, headers=headers)
    else:
        res = requests.post(url, json=data, headers=headers)
    if res.status_code != 200:
        log.warning(
            'Cloudflare call %s status: %d' % (method, res.status_code))
        return None

    data = res.json()
    log.debug('Cloudflare response: %s' % data)
    if data['success']:
        return data
    else:
        log.warning(
            'Cloudflare call %s error: %d' % (method, data['errors']))


def get_zone(name):
    zones = call_cloudflare('zones')['result']
    for z in zones:
        if z['name'] == name:
            return z


def block_cloudflare(blocklist):
    zone = get_zone(settings.get('cloudflare.zone_name'))
    if not zone:
        log.error('Cloudflare zone not found')
        return

    method = 'zones/%s/firewall/access_rules/rules' % zone['id']
    params = {
        'mode': settings.get('cloudflare.mode', 'challenge'),
        }

    blocked = {}
    for ip, dat in blocklist.items():
        params['configuration'] = {
            'target': 'ip',
            'value': ip,
            }
        params['notes'] = 'Scrapeblock: Count: %d, host: %s, date: %s' % (
            dat['count'], dat['host'], dt.datetime.now())
        log.notice('Cloudflare ' + params['notes'])
        try:
            result = call_cloudflare(method, params)
            if result:
                blocked[ip] = dat
        except Exception as e:
            log.warning('Request error: %s' % str(e))
    return blocked


def block_iptables(blocklist):
    # TODO
    blocked = {}
    return blocked


def cleanup_cloudflare(days):
    cutoff_date = dt.datetime.now() - dt.timedelta(days=days)
    log.info('Cleaning rules older than %s' % cutoff_date)
    zone = get_zone(settings.get('cloudflare.zone_name'))
    if not zone:
        log.error('Cloudflare zone not found')
        return

    method = 'zones/%s/firewall/access_rules/rules' % zone['id']

    page = 1
    while True:
        call_url = method + '?per_page=100&page=%d' % page
        result = call_cloudflare(call_url)
        if not result:
            break
        data = result['result']
        for rule in data:
            # check rule date and delete
            rule_date = dt.datetime.strptime(
                rule['created_on'],
                "%Y-%m-%dT%H:%M:%S.%fZ"
                )
            if rule_date <= cutoff_date:
                log.info(
                    'Deleting rule %s: %s' % (
                        rule['id'],
                        rule['notes']))
                delete_url = method + '/%s' % rule['id']
                res = call_cloudflare(delete_url, delete=True)
                if not res or not res['success']:
                    log.error('Error deleting rule: %s' % rule['id'])
        res_info = result['result_info']
        if res_info['total_count'] <= page * 100:
            break
        page += 1
