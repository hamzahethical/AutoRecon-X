#!/usr/bin/env python3
"""
AutoRecon-X — Automated Bug Bounty Reconnaissance Framework
Author : Md Hamzah (@hamzahethical)
GitHub : https://github.com/hamzahethical/AutoRecon-X
"""

import sys
import os
import json
import socket
import ssl
import datetime
import argparse
import urllib.request
import urllib.error
import threading
import concurrent.futures
import time
import hashlib

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich.live import Live
    from rich import box
    RICH = True
except ImportError:
    RICH = False
    print("[!] Install rich for better output: pip install rich")

console = Console() if RICH else None

BANNER = r"""
     _         _        ____                      __  __
    / \  _   _| |_ ___ |  _ \ ___  ___ ___  _ __ \ \/ /
   / _ \| | | | __/ _ \| |_) / _ \/ __/ _ \| '_ \ \  / 
  / ___ \ |_| | || (_) |  _ <  __/ (_| (_) | | | |/  \ 
 /_/   \_\__,_|\__\___/|_| \_\___|\___\___/|_| |_/_/\_\

  Automated Bug Bounty Reconnaissance Framework
  Author: Md Hamzah (@hamzahethical)
"""

DEFAULT_PORTS = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443,8888,9200,27017]

TECH_SIGNATURES = {
    "WordPress":        ["wp-content", "wp-includes", "WordPress"],
    "Laravel":          ["laravel_session", "X-Laravel"],
    "Django":           ["csrftoken", "Django"],
    "React":            ["__REACT_", "_reactroot_"],
    "Angular":          ["ng-version", "ng-app"],
    "Vue.js":           ["__vue__", "data-v-"],
    "Bootstrap":        ["bootstrap.min.css", "bootstrap.bundle"],
    "jQuery":           ["jquery.min.js", "jQuery"],
    "Apache":           ["Apache", "apache"],
    "Nginx":            ["nginx"],
    "IIS":              ["Microsoft-IIS"],
    "Cloudflare":       ["cloudflare", "__cf_bm"],
    "AWS S3":           ["AmazonS3", "s3.amazonaws.com"],
    "Shopify":          ["cdn.shopify.com", "Shopify"],
    "Drupal":           ["Drupal", "drupal"],
    "Joomla":           ["Joomla", "joomla"],
    "PHP":              ["PHP/", "X-PHP"],
    "ASP.NET":          ["ASP.NET", "X-AspNet"],
    "Node.js":          ["X-Powered-By: Express"],
}

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
DNS_WORDLIST = [
    "www","mail","ftp","admin","api","dev","test","staging","vpn","portal",
    "app","cdn","cloud","remote","secure","m","mobile","login","auth","beta",
    "dashboard","support","help","blog","shop","store","img","images","static",
    "assets","media","files","download","upload","smtp","pop","imap","ns1","ns2",
    "mx","mx1","mx2","webmail","autodiscover","sip","meet","video","stream",
    "monitor","metrics","grafana","jenkins","gitlab","git","jira","confluence",
    "demo","sandbox","qa","uat","prod","production","internal","intranet",
    "vpn2","fw","firewall","proxy","gateway","router","switch","ap","wifi",
    "backup","db","database","sql","mysql","redis","mongo","elastic","kibana",
    "docs","documentation","wiki","status","health","ping","api2","api-v2",
    "v2","v3","new","old","legacy","stage","preprod","connect","oauth","sso"
]


# ─── Utilities ────────────────────────────────────────────────────────────────

def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def log(msg, level="INFO", c=None):
    colors = {"INFO": "cyan", "OK": "green", "WARN": "yellow", "ERROR": "red", "FIND": "bright_green"}
    if RICH and c:
        c.print(f"[dim]{ts()}[/dim]  [{colors.get(level,'white')}][{level}][/{colors.get(level,'white')}]  {msg}")
    else:
        print(f"{ts()}  [{level}]  {msg}")

def req(url, timeout=8, follow=True):
    try:
        rq = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (AutoRecon-X Security Scanner)",
            "Accept": "text/html,application/xhtml+xml,*/*"
        })
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(rq, timeout=timeout, context=ctx) as r:
            body = r.read(65536).decode("utf-8", errors="ignore")
            return {"status": r.status, "headers": dict(r.headers), "body": body, "url": r.url}
    except urllib.error.HTTPError as e:
        body = e.read(16384).decode("utf-8", errors="ignore")
        return {"status": e.code, "headers": dict(e.headers), "body": body, "url": url}
    except Exception:
        return None


# ─── Module 1: Subdomain Enum ─────────────────────────────────────────────────

def crtsh_subdomains(domain):
    found = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        rq = urllib.request.Request(url, headers={"User-Agent": "AutoRecon-X"})
        with urllib.request.urlopen(rq, timeout=15) as r:
            data = json.loads(r.read().decode())
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.").lower()
                if domain in name and name.endswith(domain):
                    found.add(name)
    except Exception:
        pass
    return found

def dns_brute(domain, wordlist=None):
    if wordlist is None:
        wordlist = DNS_WORDLIST
    found = set()
    lock = threading.Lock()

    def probe(sub):
        fqdn = f"{sub}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            with lock:
                found.add(fqdn)
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(probe, wordlist)
    return found

def enum_subdomains(domain, c=None):
    log(f"Fetching subdomains from certificate transparency logs (crt.sh)...", "INFO", c)
    crt = crtsh_subdomains(domain)
    log(f"crt.sh: {len(crt)} subdomains found", "OK", c)

    log(f"DNS brute-force with {len(DNS_WORDLIST)} wordlist...", "INFO", c)
    brute = dns_brute(domain)
    log(f"DNS brute: {len(brute)} resolved hosts", "OK", c)

    all_subs = crt | brute
    # Always include apex domain
    all_subs.add(domain)
    log(f"Total unique subdomains: [bold]{len(all_subs)}[/bold]", "FIND", c)
    return sorted(all_subs)


# ─── Module 2: DNS Resolution ─────────────────────────────────────────────────

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def resolve_all(hosts, c=None):
    log(f"Resolving {len(hosts)} hosts...", "INFO", c)
    result = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        futures = {ex.submit(resolve_host, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futures):
            host = futures[f]
            ip = f.result()
            if ip:
                result[host] = ip
    log(f"Resolved: [bold]{len(result)}[/bold] live hosts", "OK", c)
    return result


# ─── Module 3: HTTP Probe ──────────────────────────────────────────────────────

def probe_http(host):
    result = {"host": host, "alive": False, "url": None, "status": None,
              "title": None, "redirect": None, "headers": {}, "tech": [], "body": ""}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        r = req(url)
        if r:
            result["alive"] = True
            result["url"] = r["url"]
            result["status"] = r["status"]
            result["headers"] = r["headers"]
            result["body"] = r["body"]
            # Extract title
            body = r["body"]
            ti = body.find("<title")
            if ti != -1:
                ts2 = body.find(">", ti) + 1
                te = body.find("</title>", ts2)
                if te != -1:
                    result["title"] = body[ts2:te].strip()[:120]
            if r["url"] != url:
                result["redirect"] = r["url"]
            # Tech detection
            combined = body + " ".join(f"{k}: {v}" for k, v in r["headers"].items())
            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in combined.lower():
                        if tech not in result["tech"]:
                            result["tech"].append(tech)
                        break
            break
    return result

def probe_all(hosts, c=None):
    log(f"HTTP/HTTPS probing {len(hosts)} resolved hosts...", "INFO", c)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(probe_http, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r["alive"]:
                results.append(r)
    alive = [r for r in results if r["alive"]]
    log(f"Live web hosts: [bold]{len(alive)}[/bold]", "OK", c)
    return results


# ─── Module 4: Port Scan ──────────────────────────────────────────────────────

PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP",
    110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB", 3306:"MySQL",
    3389:"RDP", 5432:"PostgreSQL", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    8888:"Jupyter", 9200:"Elasticsearch", 27017:"MongoDB"
}

def scan_port(host, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, port)) == 0:
            s.close()
            return port
        s.close()
    except Exception:
        pass
    return None

def scan_host_ports(host, ports=None):
    if ports is None:
        ports = DEFAULT_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            p = f.result()
            if p:
                open_ports.append(p)
    return sorted(open_ports)

def port_scan_all(resolved, c=None, max_hosts=10):
    log(f"Port scanning top {len(DEFAULT_PORTS)} ports on up to {max_hosts} hosts...", "INFO", c)
    results = {}
    targets = list(resolved.keys())[:max_hosts]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(scan_host_ports, ip): host for host, ip in list(resolved.items())[:max_hosts]}
        for f in concurrent.futures.as_completed(futures):
            host = futures[f]
            open_p = f.result()
            results[host] = open_p
            if open_p:
                svc_str = ", ".join(f"{p}/{PORT_SERVICES.get(p,'?')}" for p in open_p)
                log(f"{host}  →  [green]{svc_str}[/green]", "FIND", c)
    return results


# ─── Module 5: HTML Report ────────────────────────────────────────────────────

def html_report(domain, subdomains, resolved, http_results, port_results, outfile):
    alive_http = [r for r in http_results if r["alive"]]
    total_subs = len(subdomains)
    total_live = len(resolved)
    total_web  = len(alive_http)
    gen_time   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_subs = ""
    for sub in subdomains:
        ip = resolved.get(sub, "<em>unresolved</em>")
        rows_subs += f"<tr><td>{sub}</td><td>{ip}</td></tr>"

    rows_http = ""
    for r in alive_http:
        tech_badges = " ".join(f'<span class="badge">{t}</span>' for t in r["tech"])
        redir = f'<br/><small class="redir">→ {r["redirect"]}</small>' if r.get("redirect") else ""
        rows_http += f"""<tr>
          <td><a href="{r['url']}" target="_blank">{r['host']}</a>{redir}</td>
          <td><span class="status s{str(r['status'])[0]}xx">{r['status']}</span></td>
          <td>{r.get('title') or ''}</td>
          <td>{tech_badges}</td>
        </tr>"""

    rows_ports = ""
    for host, ports in port_results.items():
        if ports:
            port_tags = " ".join(f'<span class="port-badge">{p}<small>/{PORT_SERVICES.get(p,"?")}</small></span>' for p in ports)
            rows_ports += f"<tr><td>{host}</td><td>{port_tags}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AutoRecon-X Report — {domain}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;padding:0 0 60px}}
  .header{{background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);border-bottom:1px solid #21262d;padding:40px 60px}}
  .header h1{{font-size:2rem;color:#58a6ff;letter-spacing:2px}}
  .header h1 span{{color:#3fb950}}
  .header p{{margin-top:8px;color:#8b949e;font-size:.9rem}}
  .meta{{display:flex;gap:30px;margin-top:20px;flex-wrap:wrap}}
  .meta-card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px 20px;min-width:140px}}
  .meta-card .num{{font-size:2rem;font-weight:700;color:#58a6ff}}
  .meta-card .label{{font-size:.8rem;color:#8b949e;text-transform:uppercase;letter-spacing:1px}}
  .container{{padding:40px 60px}}
  h2{{font-size:1.3rem;color:#58a6ff;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d}}
  .section{{margin-bottom:50px}}
  table{{width:100%;border-collapse:collapse;font-size:.87rem}}
  th{{background:#161b22;color:#8b949e;font-weight:600;padding:10px 14px;text-align:left;border-bottom:2px solid #21262d;letter-spacing:.5px;text-transform:uppercase;font-size:.75rem}}
  td{{padding:10px 14px;border-bottom:1px solid #21262d;vertical-align:middle}}
  tr:hover td{{background:#161b22}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .badge{{display:inline-block;background:#1f3a6e;color:#79c0ff;border-radius:4px;padding:2px 8px;font-size:.75rem;margin:2px}}
  .port-badge{{display:inline-block;background:#1a3a2a;color:#3fb950;border-radius:4px;padding:2px 7px;font-size:.75rem;margin:2px}}
  .port-badge small{{color:#8b949e;margin-left:1px}}
  .status{{display:inline-block;border-radius:4px;padding:2px 8px;font-weight:600;font-size:.8rem}}
  .s2xx{{background:#1a3a2a;color:#3fb950}}
  .s3xx{{background:#1f3a6e;color:#79c0ff}}
  .s4xx{{background:#3a1f1f;color:#f85149}}
  .s5xx{{background:#3a2a1f;color:#e3b341}}
  .redir{{color:#8b949e}}
  .footer{{text-align:center;color:#484f58;font-size:.8rem;margin-top:60px}}
  ::-webkit-scrollbar{{width:6px;height:6px}}
  ::-webkit-scrollbar-track{{background:#0d1117}}
  ::-webkit-scrollbar-thumb{{background:#21262d;border-radius:3px}}
</style>
</head>
<body>
<div class="header">
  <h1>AutoRecon-X &mdash; <span>{domain}</span></h1>
  <p>Automated Bug Bounty Reconnaissance Report &nbsp;|&nbsp; Generated: {gen_time}</p>
  <div class="meta">
    <div class="meta-card"><div class="num">{total_subs}</div><div class="label">Subdomains</div></div>
    <div class="meta-card"><div class="num">{total_live}</div><div class="label">Live Hosts</div></div>
    <div class="meta-card"><div class="num">{total_web}</div><div class="label">Web Services</div></div>
    <div class="meta-card"><div class="num">{sum(len(v) for v in port_results.values())}</div><div class="label">Open Ports</div></div>
  </div>
</div>

<div class="container">

  <div class="section">
    <h2>🌐 Subdomain Enumeration ({total_subs})</h2>
    <table>
      <thead><tr><th>Subdomain / Host</th><th>Resolved IP</th></tr></thead>
      <tbody>{rows_subs}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>🕸️ Live Web Services ({total_web})</h2>
    <table>
      <thead><tr><th>URL</th><th>Status</th><th>Page Title</th><th>Detected Technologies</th></tr></thead>
      <tbody>{rows_http}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>🔌 Open Ports</h2>
    <table>
      <thead><tr><th>Host</th><th>Open Ports</th></tr></thead>
      <tbody>{rows_ports if rows_ports else "<tr><td colspan='2' style='color:#8b949e'>No significant open ports found on scanned hosts.</td></tr>"}</tbody>
    </table>
  </div>

</div>
<div class="footer">
  Generated by <strong>AutoRecon-X</strong> &mdash; Md Hamzah (@hamzahethical) &mdash; For authorized security testing only.
</div>
</body>
</html>"""

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AutoRecon-X — Automated Bug Bounty Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python autorecon.py -d example.com
  python autorecon.py -d example.com -o report.html
  python autorecon.py -d example.com --no-ports
  python autorecon.py -d example.com --max-port-hosts 20
        """
    )
    parser.add_argument("-d", "--domain",         required=True, help="Target root domain (e.g. example.com)")
    parser.add_argument("-o", "--output",          default=None,  help="HTML report output file (default: <domain>_report.html)")
    parser.add_argument("--no-ports",              action="store_true", help="Skip port scanning")
    parser.add_argument("--max-port-hosts",        type=int, default=10, help="Max hosts to port-scan (default: 10)")
    parser.add_argument("--wordlist",              help="Path to custom DNS wordlist file (one per line)")
    args = parser.parse_args()

    domain = args.domain.strip().lstrip("https://").lstrip("http://").rstrip("/")
    outfile = args.output or f"{domain.replace('.','_')}_autorecon_report.html"

    if RICH:
        console.print(Panel(Text(BANNER, style="bold cyan"), border_style="cyan"))
        console.print(f"[bold white]Target:[/bold white] [green]{domain}[/green]
")
    else:
        print(BANNER)
        print(f"Target: {domain}")

    start = time.time()

    # Custom wordlist
    wordlist = None
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]

    # 1. Subdomain Enumeration
    if RICH: console.rule("[bold cyan]Phase 1: Subdomain Enumeration[/bold cyan]")
    subdomains = enum_subdomains(domain, console)

    # 2. DNS Resolution
    if RICH: console.rule("[bold cyan]Phase 2: DNS Resolution[/bold cyan]")
    resolved = resolve_all(subdomains, console)

    # 3. HTTP Probe
    if RICH: console.rule("[bold cyan]Phase 3: HTTP/HTTPS Probing[/bold cyan]")
    http_results = probe_all(list(resolved.keys()), console)

    # 4. Port Scan
    port_results = {}
    if not args.no_ports:
        if RICH: console.rule("[bold cyan]Phase 4: Port Scanning[/bold cyan]")
        port_results = port_scan_all(resolved, console, args.max_port_hosts)

    # 5. Report
    if RICH: console.rule("[bold cyan]Phase 5: Generating Report[/bold cyan]")
    html_report(domain, subdomains, resolved, http_results, port_results, outfile)
    elapsed = round(time.time() - start, 1)

    if RICH:
        alive_http = [r for r in http_results if r["alive"]]
        t = Table(box=box.ROUNDED, border_style="green", title="[bold green]✓ Scan Complete[/bold green]")
        t.add_column("Metric", style="bold cyan")
        t.add_column("Count",  style="bold white", justify="right")
        t.add_row("Subdomains Found",  str(len(subdomains)))
        t.add_row("Live DNS Hosts",    str(len(resolved)))
        t.add_row("Live Web Services", str(len(alive_http)))
        t.add_row("Total Open Ports",  str(sum(len(v) for v in port_results.values())))
        t.add_row("Time Elapsed",      f"{elapsed}s")
        t.add_row("Report Saved To",   outfile)
        console.print(t)
    else:
        print(f"\nDone in {elapsed}s. Report saved: {outfile}")


if __name__ == "__main__":
    main()
