Scrapeblock
===========

Block website scrapers by analyzing web server access log file. IP is blocked on Cloudflare or local server iptables depending on what is configured in config file. Config file default location is `~/.scrapeblock/config.yml`. Workflow consists of two stages (command line commands):
 - analyze
 - block

During "analyze" stage it counts number of accesses per IP, resolves IP address into hostname and writes results into `analyze.analyze_file`. An IP is logged If number of requests from it is greater than `analyze.threshold` (see config.yml)

During "block" stage it reads previously blocked IPs from `block.blocked_file`, reads analyze results and decide wether to block or pass for each IP depending on `block` config. If IP or host is in whitelist it is passed, if in blacklist it is blocked, if IP is not in black or white lists but request count is greater than `block.threshold` it is blocked. All IPs that are left are logged as notices intho the logfile for manual evaluation.

See example `config.yml` for available options and settings.
