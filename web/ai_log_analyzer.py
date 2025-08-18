#!/usr/bin/env python3
"""
AI Log Analyzer (single-file MVP)
- Parses Nginx/Apache access logs (Common or Combined format)
- Scores suspicious IPs using multiple signals
- Suggests ufw/iptables rules
- Produces a Markdown report and PNG charts

Usage:
  python3 ai_log_analyzer.py --log path/to/access.log --out out_dir [--top 20]

No external services. Fully offline.
"""

import argparse
import collections
import datetime as dt
import ipaddress
import math
import os
import re
import statistics
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt

LOG_PATTERNS = [
    # Combined Log Format (Apache/Nginx):
    re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+)\s(?P<path>[^"]*?)\s(?P<proto>[^"]*?)" '
        r'(?P<status>\d{3}) (?P<size>\S+)(?: '
        r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
    ),
    # Common Log Format (no referrer/agent)
    re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+)\s(?P<path>[^"]*?)\s(?P<proto>[^"]*?)" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
    ),
]

# Typical suspicious indicators
SUS_PATH_PATTERNS = [
    r'\.\./', r'/wp-admin', r'/wp-login', r'/xmlrpc\.php', r'/\.git', r'/\.env',
    r'/admin', r'/phpmyadmin', r'/cgi-bin', r'/vendor/', r'/composer\.(json|lock)',
    r'/id_rsa', r'/\.DS_Store', r'\.php(?:\?|$)', r'\.bak$', r'\.old$', r'/\.well-known'
]
sus_path_regex = re.compile("|".join(SUS_PATH_PATTERNS), re.IGNORECASE)

SUS_AGENTS = [
    'sqlmap', 'curl', 'wget', 'nikto', 'nmap', 'dirbuster', 'gobuster', 'acunetix', 'nessus'
]
sus_agent_regex = re.compile("|".join(re.escape(a) for a in SUS_AGENTS), re.IGNORECASE)

def parse_time(ts: str) -> dt.datetime:
    # Example: 10/Oct/2000:13:55:36 -0700
    return dt.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")

def parse_line(line: str):
    for pat in LOG_PATTERNS:
        m = pat.match(line)
        if m:
            d = m.groupdict()
            try:
                when = parse_time(d['time'])
            except Exception:
                continue
            return {
                'ip': d['ip'],
                'time': when,
                'method': d.get('method', '-'),
                'path': d.get('path', '-'),
                'proto': d.get('proto', '-'),
                'status': int(d.get('status', 0)),
                'size': int(d['size']) if d['size'].isdigit() else 0,
                'referrer': d.get('referrer') or '-',
                'agent': d.get('agent') or '-',
            }
    return None

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def score_entry(entry) -> float:
    score = 0.0
    status = entry['status']
    path = entry['path'] or ''
    agent = entry['agent'] or ''

    # Elevated score for auth/forbidden errors
    if status in (401, 403, 429):
        score += 2.0
    elif status in (404, 500, 502, 503):
        score += 0.8

    # Suspicious path patterns
    if sus_path_regex.search(path):
        score += 2.5

    # Suspicious agents
    if sus_agent_regex.search(agent):
        score += 2.0

    # Large request size can be probing (heuristic)
    if entry['size'] > 500_000:
        score += 0.5

    # Methods other than GET/HEAD
    if entry['method'] not in ('GET', 'HEAD'):
        score += 0.4

    return score

def aggregate(entries: List[dict]):
    per_ip = collections.defaultdict(lambda: {
        'count': 0,
        'score': 0.0,
        'first_seen': None,
        'last_seen': None,
        'statuses': collections.Counter(),
        'paths': collections.Counter(),
        'agents': collections.Counter(),
        'bytes': 0,
        'timeline': collections.Counter(),  # minute buckets
    })

    for e in entries:
        ip = e['ip']
        ipd = per_ip[ip]
        ipd['count'] += 1
        ipd['score'] += score_entry(e)
        ipd['first_seen'] = min(ipd['first_seen'], e['time']) if ipd['first_seen'] else e['time']
        ipd['last_seen'] = max(ipd['last_seen'], e['time']) if ipd['last_seen'] else e['time']
        ipd['statuses'][e['status']] += 1
        if e['path']:
            ipd['paths'][e['path']] += 1
        if e['agent']:
            ipd['agents'][e['agent']] += 1
        ipd['bytes'] += e['size']
        minute_bucket = e['time'].astimezone(dt.timezone.utc).replace(second=0, microsecond=0, tzinfo=None)
        ipd['timeline'][minute_bucket] += 1

    return per_ip

def zscore(values: List[int]) -> float:
    if len(values) < 3:
        return 0.0
    mean = statistics.mean(values)
    stdev = statistics.pstdev(values) or 1e-9
    latest = values[-1]
    return (latest - mean) / stdev

def anomaly_boost(per_ip: Dict[str, dict]) -> Dict[str, float]:
    # For each IP, compute a burstiness score using z-score on minute buckets
    boost = {}
    for ip, d in per_ip.items():
        series = [cnt for _, cnt in sorted(d['timeline'].items())]
        z = zscore(series)
        boost[ip] = max(0.0, z)  # only positive spikes boost
    return boost

def suggest_firewall(ip: str, use_ufw=True) -> List[str]:
    cmds = []
    if use_ufw:
        cmds.append(f"sudo ufw deny from {ip}")
    else:
        cmds.append(f"sudo iptables -A INPUT -s {ip} -j DROP")
        cmds.append("sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null")
    return cmds

def summarize(per_ip: Dict[str, dict], top=20) -> List[Tuple[str, dict]]:
    # Compute final threat score = base score + burst boost + 0.5*log(count)
    boosts = anomaly_boost(per_ip)
    ranked = []
    for ip, d in per_ip.items():
        base = d['score']
        burst = boosts.get(ip, 0.0)
        count_factor = 0.5 * math.log(d['count'] + 1, 2)
        final = base + burst + count_factor
        d['final_score'] = round(final, 3)
        d['burst_z'] = round(burst, 3)
        ranked.append((ip, d))
    ranked.sort(key=lambda x: x[1]['final_score'], reverse=True)
    return ranked[:top]

def plot_activity(per_ip: Dict[str, dict], outdir: str, top_ips: List[str]):
    os.makedirs(outdir, exist_ok=True)
    # Combined per-minute total
    from collections import Counter
    total = Counter()
    for d in per_ip.values():
        total.update(d['timeline'])
    xs = sorted(total.keys())
    ys = [total[x] for x in xs]
    if xs:
        plt.figure(figsize=(10,4))
        plt.plot(xs, ys)
        plt.title("Overall Requests per Minute")
        plt.xlabel("Time (UTC, minute)")
        plt.ylabel("Requests")
        plt.tight_layout()
        plt.savefig(os.path.join(outdir, "overall_requests_per_minute.png"))
        plt.close()

    # Top IPs activity
    for ip in top_ips[:5]:
        d = per_ip[ip]
        xs = sorted(d['timeline'].keys())
        ys = [d['timeline'][x] for x in xs]
        if xs:
            plt.figure(figsize=(10,4))
            plt.plot(xs, ys)
            plt.title(f"Requests per Minute - {ip}")
            plt.xlabel("Time (UTC, minute)")
            plt.ylabel("Requests")
            plt.tight_layout()
            safe_ip = ip.replace(":", "_")
            plt.savefig(os.path.join(outdir, f"ip_{safe_ip}_requests.png"))
            plt.close()

def write_report(per_ip: Dict[str, dict], ranked: List[Tuple[str, dict]], outdir: str, use_ufw=True):
    os.makedirs(outdir, exist_ok=True)
    report_path = os.path.join(outdir, "report.md")
    lines = []
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"# AI Log Analyzer Report\n\nGenerated: **{now}**\n")
    lines.append(f"Analyzed unique IPs: **{len(per_ip)}**\n")
    if not ranked:
        lines.append("> No entries ranked. Check your log file.\n")
    else:
        lines.append("## Top Suspicious IPs\n")
        lines.append("| Rank | IP | Final Score | Requests | 401/403 | 404 | Burst z | First Seen | Last Seen | Private |\n")
        lines.append("|---:|---|---:|---:|---:|---:|---:|---|---|---|\n")
        for i, (ip, d) in enumerate(ranked, 1):
            s401_403 = d['statuses'].get(401,0) + d['statuses'].get(403,0)
            s404 = d['statuses'].get(404,0)
            private = "Yes" if is_private_ip(ip) else "No"
            lines.append(f"| {i} | {ip} | {d['final_score']:.2f} | {d['count']} | {s401_403} | {s404} | {d['burst_z']:.2f} | {d['first_seen']} | {d['last_seen']} | {private} |\n")

        lines.append("\n### Suggested Firewall Rules\n")
        for ip, d in ranked[:10]:
            cmds = suggest_firewall(ip, use_ufw=use_ufw)
            for c in cmds:
                lines.append(f"- `{c}`\n")

        lines.append("\n### Notes\n")
        lines.append("- Final score = base(anomalies from paths/agents/status) + burst_z + 0.5*log(request_count+1)\n")
        lines.append("- Private IPs are listed; block carefully to avoid self-DOS in internal networks.\n")
        lines.append("- Charts saved next to this report.\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report_path

def main():
    ap = argparse.ArgumentParser(description="AI Log Analyzer (offline)")
    ap.add_argument("--log", required=True, help="Path to access log file (Apache/Nginx)")
    ap.add_argument("--out", required=True, help="Output directory for report and charts")
    ap.add_argument("--top", type=int, default=20, help="How many IPs to include (default: 20)")
    ap.add_argument("--iptables", action="store_true", help="Suggest iptables instead of ufw")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    entries = []
    with open(args.log, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            e = parse_line(line)
            if e:
                entries.append(e)

    if not entries:
        print("No valid log lines parsed. Check file format.")
        return

    per_ip = aggregate(entries)
    ranked = summarize(per_ip, top=args.top)

    top_ips = [ip for ip, _ in ranked]
    plot_activity(per_ip, args.out, top_ips)

    report = write_report(per_ip, ranked, args.out, use_ufw=not args.iptables)

    print(f"Done. Report: {report}")
    print("Tip: open the Markdown in a viewer, or convert to PDF if selling to non-technical users.")

if __name__ == "__main__":
    main()
