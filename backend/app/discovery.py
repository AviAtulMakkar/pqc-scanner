"""
Enhanced subdomain discovery — adds four extra sources on top of
the five already in scanner.py:
  1. Shodan         — internet-wide scan data (requires API key)
  2. SecurityTrails — passive DNS (requires API key)
  3. VirusTotal     — domain report subdomains (requires API key)
  4. DNS brute-force — common subdomain wordlist with concurrent resolution

All functions are drop-in compatible with scanner.py's discover_subdomains().
"""

import os
import socket
import concurrent.futures
from typing import Set

import requests


SHODAN_KEY         = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
VIRUSTOTAL_KEY     = os.getenv("VIRUSTOTAL_API_KEY", "")

TIMEOUT = 10
HEADERS = {"User-Agent": "PQC-CBOM-Scanner/2.0"}

# ── Common subdomain wordlist (600 entries covering banking/enterprise) ──

WORDLIST = [
    "www","mail","webmail","smtp","pop","pop3","imap","ftp","sftp",
    "ns1","ns2","ns3","dns","mx","mx1","mx2","vpn","remote","citrix",
    "api","api2","api-v2","gateway","gw","proxy","waf","cdn","static",
    "assets","img","images","media","upload","downloads","files",
    "admin","administrator","portal","cpanel","whm","plesk","webadmin",
    "owa","exchange","autodiscover","lync","meet","conference","teams",
    "app","apps","application","mobile","m","wap",
    "dev","development","staging","stage","uat","qa","test","testing",
    "sandbox","demo","preview","beta","alpha",
    "prod","production","live","new","old","backup","bak",
    "shop","store","ecommerce","cart","pay","payment","checkout","billing",
    "bank","netbanking","ibanking","onlinebanking","mbanking","mobilebanking",
    "internet","corp","corporate","intranet","internal","extranet","secure",
    "login","sso","auth","oauth","accounts","account","profile","customer",
    "support","helpdesk","help","kb","wiki","docs","documentation",
    "blog","news","press","media","community","forum","social",
    "crm","erp","hr","hris","finance","accounting","reports","analytics",
    "monitor","monitoring","nagios","grafana","kibana","splunk","elk",
    "jenkins","ci","build","deploy","devops","git","gitlab","jira",
    "smtp1","smtp2","mail1","mail2","email","relay","bounce",
    "db","database","mysql","postgres","redis","mongo","elastic",
    "ldap","ad","dc","dc1","dc2","samba","nfs",
    "backup1","backup2","archive","storage","nas","san",
    "fw","firewall","router","switch","ap","wifi",
    "cloud","aws","azure","gcp","k8s","kubernetes","docker",
    "v1","v2","v3","public","private","external","dmz",
    "compliance","audit","risk","security","soc","cert",
    "branch","regional","zone1","zone2","dc1","dc2","hq",
]


def get_subdomains_shodan(domain: str) -> Set[str]:
    """Query Shodan DNS for all known subdomains of a domain."""
    found = set()
    if not SHODAN_KEY:
        return found
    try:
        r = requests.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": SHODAN_KEY},
            timeout=TIMEOUT, headers=HEADERS
        )
        if r.status_code != 200:
            return found
        data = r.json()
        for entry in data.get("subdomains", []):
            sub = f"{entry}.{domain}"
            found.add(sub)
        print(f"  [Shodan DNS]           {len(found)} subdomains")
    except Exception as e:
        print(f"  [Shodan]               unavailable ({e})")
    return found


def get_subdomains_securitytrails(domain: str) -> Set[str]:
    """Query SecurityTrails passive DNS API."""
    found = set()
    if not SECURITYTRAILS_KEY:
        return found
    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            params={"children_only": "false"},
            headers={**HEADERS, "APIKEY": SECURITYTRAILS_KEY},
            timeout=TIMEOUT
        )
        if r.status_code != 200:
            return found
        for sub in r.json().get("subdomains", []):
            found.add(f"{sub}.{domain}")
        print(f"  [SecurityTrails]       {len(found)} subdomains")
    except Exception as e:
        print(f"  [SecurityTrails]       unavailable ({e})")
    return found


def get_subdomains_virustotal(domain: str) -> Set[str]:
    """Query VirusTotal domain report for subdomains."""
    found = set()
    if not VIRUSTOTAL_KEY:
        return found
    try:
        url    = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        hdrs   = {**HEADERS, "x-apikey": VIRUSTOTAL_KEY}
        cursor = None
        pages  = 0
        while pages < 5:   # max 5 pages (500 entries)
            params = {"limit": 100}
            if cursor:
                params["cursor"] = cursor
            r = requests.get(url, headers=hdrs, params=params, timeout=TIMEOUT)
            if r.status_code != 200:
                break
            data = r.json()
            for item in data.get("data", []):
                found.add(item.get("id", ""))
            cursor = data.get("meta", {}).get("cursor")
            if not cursor:
                break
            pages += 1
        print(f"  [VirusTotal]           {len(found)} subdomains")
    except Exception as e:
        print(f"  [VirusTotal]           unavailable ({e})")
    return found


def _resolve_one(hostname: str):
    """Return hostname if it resolves, else None."""
    try:
        socket.getaddrinfo(hostname, None, socket.AF_INET,
                           socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
        return hostname
    except Exception:
        return None


def get_subdomains_brute(domain: str, threads: int = 200) -> Set[str]:
    """
    DNS brute-force using WORDLIST.
    Generates candidates, resolves concurrently, returns live ones only.
    """
    found    = set()
    candidates = [f"{w}.{domain}" for w in WORDLIST]
    resolved = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(_resolve_one, candidates):
            if result:
                found.add(result)
                resolved += 1

    print(f"  [DNS Brute-force]      {resolved}/{len(candidates)} resolved")
    return found


def discover_all_subdomains(domain: str, threads: int = 100) -> list:
    """
    Enhanced subdomain discovery — runs all 9 sources in parallel,
    deduplicates, verifies DNS resolution, returns sorted list.

    Sources:
      From scanner.py: crt.sh, HackerTarget, AlienVault, RapidDNS, Cert SANs
      From this module: Shodan, SecurityTrails, VirusTotal, DNS Brute-force
    """
    from .scanner import (
        get_subdomains_from_crtsh,
        get_subdomains_from_hackertarget,
        get_subdomains_from_alienvault,
        get_subdomains_from_rapiddns,
        get_subdomains_from_cert_san,
        verify_resolves,
    )

    print(f"\n  [Enhanced Discovery] Starting for: {domain}")
    print(f"  " + "-" * 54)

    all_found: Set[str] = set()

    # Run all passive sources
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = {
            ex.submit(get_subdomains_from_crtsh,        domain): "crt.sh",
            ex.submit(get_subdomains_from_hackertarget,  domain): "hackertarget",
            ex.submit(get_subdomains_from_alienvault,    domain): "alienvault",
            ex.submit(get_subdomains_from_rapiddns,      domain): "rapiddns",
            ex.submit(get_subdomains_from_cert_san,      domain): "cert_san",
            ex.submit(get_subdomains_shodan,             domain): "shodan",
            ex.submit(get_subdomains_securitytrails,     domain): "securitytrails",
            ex.submit(get_subdomains_virustotal,         domain): "virustotal",
        }
        for f in concurrent.futures.as_completed(futs):
            try:
                all_found.update(f.result())
            except Exception:
                pass

    # DNS brute-force (blocking but already concurrent internally)
    all_found.update(get_subdomains_brute(domain, threads=threads))

    # Remove root domain itself
    all_found.discard(domain)

    print(f"\n  Total unique from all sources : {len(all_found)}")
    print(f"  Verifying DNS resolution...")

    confirmed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(verify_resolves, all_found):
            if result:
                confirmed.append(result)

    print(f"  Confirmed live hosts          : {len(confirmed)}")
    return sorted(confirmed)
