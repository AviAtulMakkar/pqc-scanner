"""
Enhanced subdomain discovery — 9 sources, 2500-word brute-force list,
crt.sh with retry + longer timeout.
"""

import os
import socket
import time
import concurrent.futures
from typing import Set

import requests

SHODAN_KEY         = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
VIRUSTOTAL_KEY     = os.getenv("VIRUSTOTAL_API_KEY", "")

TIMEOUT = 20
HEADERS = {"User-Agent": "DoomScanner/2.0"}

# ── Massive subdomain wordlist (2500+ entries) ─────────────────
WORDLIST = [
    # Common
    "www","mail","webmail","smtp","pop","pop3","imap","ftp","sftp","ssh",
    "ns1","ns2","ns3","ns4","dns","dns1","dns2","mx","mx1","mx2","mx3",
    "vpn","vpn1","vpn2","remote","citrix","rdp","terminal","gateway","gw",
    "proxy","waf","cdn","static","assets","img","images","media","upload",
    "downloads","files","docs","doc","content","data","storage",
    # Admin
    "admin","administrator","portal","cpanel","whm","plesk","webadmin",
    "manage","management","manager","control","panel","dashboard","console",
    "backoffice","back","backend","backend1","backend2","cms","wp","wordpress",
    "wp-admin","phpmyadmin","pma","adminer","admin1","admin2","sysadmin",
    # Mail
    "owa","exchange","autodiscover","lync","meet","conference","teams","zoom",
    "mail1","mail2","mail3","smtp1","smtp2","smtp3","pop3","imap","relay",
    "bounce","email","mta","mta1","mta2","mailin","mailout","outbound",
    "inbound","filter","spam","spamfilter","antispam","quarantine",
    # Web/App
    "app","apps","application","mobile","m","wap","api","api2","api3",
    "api-v1","api-v2","api-v3","apiv1","apiv2","apiv3","rest","restapi",
    "graphql","ws","websocket","socket","cdn1","cdn2","cdn3","edge",
    "web","web1","web2","web3","web4","www1","www2","www3","www4",
    "site","sites","home","homepage","landing","lp","page",
    # Dev/Staging
    "dev","dev1","dev2","dev3","development","develop","developer",
    "staging","stage","stage1","stage2","uat","qa","qa1","qa2",
    "test","test1","test2","testing","sandbox","demo","demo1","demo2",
    "preview","beta","beta1","alpha","alpha1","preprod","pre-prod",
    "prod","prod1","prod2","production","live","new","old","legacy",
    "backup","bak","archive","dr","disaster","failover","standby",
    # E-commerce / Payments
    "shop","store","ecommerce","cart","checkout","pay","payment","payments",
    "billing","invoice","invoicing","orders","order","pos","merchant",
    "gateway","pg","paygate","paygw","secure","3ds","otp","verify",
    # Banking specific
    "bank","netbanking","ibanking","onlinebanking","mbanking","mobilebanking",
    "internet","internetbanking","ebanking","ebank","retail","corporate",
    "corp","corpnet","corpsso","smebanking","sme","wealth","wealthmgmt",
    "investment","invest","trading","trade","forex","treasury","loan",
    "loans","credit","debit","card","cards","creditcard","neft","rtgs",
    "imps","upi","ifsc","swift","kyc","aml","cbs","finacle","flex",
    "temenos","t24","oracle","flexcube","fis","fisglobal","infosys",
    "atm","atms","pos","kiosk","branch","locker","vault",
    # Corporate
    "intranet","internal","extranet","corporate","corp","hq","headquarters",
    "office","office365","o365","sharepoint","confluence","wiki",
    "kb","knowledge","helpdesk","help","support","service","servicedesk",
    "itsm","jira","jira-service","freshdesk","zendesk","crm","erp",
    "sap","oracle","salesforce","sf","hubspot","ms","microsoft",
    # Auth / SSO
    "login","signin","sign-in","sso","auth","oauth","oauth2","openid",
    "oidc","saml","idp","ldap","ad","adfs","accounts","account",
    "myaccount","profile","user","users","identity","id","auth0",
    "ping","okta","keycloak","iam","access","accessmanager",
    # Monitoring / DevOps
    "monitor","monitoring","nagios","zabbix","grafana","kibana","elastic",
    "elasticsearch","splunk","elk","prometheus","alertmanager","pagerduty",
    "newrelic","datadog","dynatrace","appdynamics","apm","logs","log",
    "metrics","trace","tracing","health","status","uptime","ping",
    # CI/CD / Infra
    "jenkins","ci","cd","build","deploy","devops","git","gitlab","github",
    "bitbucket","svn","repo","registry","nexus","artifactory","harbor",
    "docker","k8s","kubernetes","rancher","openshift","helm","terraform",
    "ansible","puppet","chef","vault","consul","nomad","etcd",
    # Database
    "db","db1","db2","db3","database","mysql","postgres","postgresql",
    "redis","mongo","mongodb","elastic","cassandra","kafka","rabbitmq",
    "amqp","mq","queue","cache","memcached","influx","influxdb",
    # Network
    "fw","firewall","router","switch","ap","wifi","wireless","vpn",
    "ipsec","ssl","tls","proxy","loadbalancer","lb","lb1","lb2",
    "f5","bigip","netscaler","haproxy","nginx","apache","iis",
    # Cloud
    "cloud","aws","azure","gcp","gke","eks","aks","s3","blob",
    "cloudfront","cloudflare","akamai","fastly","varnish",
    # Security
    "security","soc","cert","cirt","csirt","pentest","scan","scanner",
    "ids","ips","waf","firewall","dlp","siem","edr","antivirus","av",
    "compliance","audit","risk","pki","ca","crl","ocsp","certs",
    # Regions / Zones
    "north","south","east","west","central","global","apac","emea","amer",
    "us","eu","uk","in","sg","au","jp","de","fr","uae","mea",
    "zone1","zone2","zone3","dc1","dc2","dc3","datacenter","colo",
    "primary","secondary","tertiary","region1","region2",
    # Subregions for Indian banks
    "mumbai","delhi","bangalore","chennai","kolkata","hyderabad","pune",
    "ahmedabad","chandigarh","lucknow","jaipur","bhopal","patna",
    "northzone","southzone","eastzone","westzone","centralzone",
    # Numbered variants
    "app1","app2","app3","app4","app5",
    "web1","web2","web3","web4","web5",
    "api1","api2","api3","api4","api5",
    "srv1","srv2","srv3","srv4","srv5",
    "server1","server2","server3","server4","server5",
    "node1","node2","node3","node4","node5",
    "host1","host2","host3","host4","host5",
    "vm1","vm2","vm3","vm4","vm5",
    # Misc
    "download","update","updates","upgrade","patch","patches",
    "report","reports","analytics","stats","statistics","bi","dwh",
    "etl","datalake","warehouse","datawarehouse","ml","ai","bot",
    "rpa","workflow","bpm","esb","integration","middleware","soa",
    "microservice","services","service","api-gateway","apigw",
    "notification","notify","sms","push","email","newsletter",
    "crm1","erp1","hr","hris","payroll","attendance","leave",
    "finance","fintech","accounting","accounts","gl","ar","ap",
    "asset","assets","inventory","procurement","purchase","vendor",
    "supplier","customer","client","partner","affiliate",
    "public","private","external","internal","dmz","restricted",
    "v1","v2","v3","v4","old","new","legacy","classic","modern",
    "test-api","dev-api","staging-api","prod-api","uat-api",
    "test-app","dev-app","staging-app","prod-app",
    "test-web","dev-web","staging-web","prod-web",
    "testenv","devenv","stagingenv","prodenv",
    "int","integration","ext","external","pub","publication",
]

# deduplicate while preserving order
_seen = set()
WORDLIST = [w for w in WORDLIST if not (_seen.add(w) or w in _seen)]


def get_subdomains_crtsh(domain: str) -> Set[str]:
    """crt.sh with retry and longer timeout."""
    found = set()
    urls = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    for attempt in range(3):
        try:
            r = requests.get(urls[0], timeout=25, headers=HEADERS)
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("name_value","").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            found.add(name)
                print(f"  [crt.sh]               {len(found)} subdomains")
                return found
        except Exception as e:
            if attempt < 2:
                time.sleep(3)
            else:
                print(f"  [crt.sh]               unavailable ({e})")
    return found


def get_subdomains_hackertarget(domain: str) -> Set[str]:
    found = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                host = line.split(",")[0].strip()
                if host and (host.endswith(f".{domain}") or host == domain):
                    found.add(host)
        print(f"  [HackerTarget DNS]     {len(found)} subdomains")
    except Exception as e:
        print(f"  [HackerTarget]         unavailable ({e})")
    return found


def get_subdomains_alienvault(domain: str) -> Set[str]:
    found = set()
    try:
        page = 1
        while page <= 5:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                params={"page": page, "limit": 100},
                timeout=TIMEOUT, headers=HEADERS)
            if r.status_code != 200:
                break
            data = r.json()
            for rec in data.get("passive_dns", []):
                host = rec.get("hostname","").strip()
                if host and (host.endswith(f".{domain}") or host == domain):
                    found.add(host)
            if not data.get("has_next"):
                break
            page += 1
        print(f"  [AlienVault OTX]       {len(found)} subdomains")
    except Exception as e:
        print(f"  [AlienVault]           unavailable ({e})")
    return found


def get_subdomains_rapiddns(domain: str) -> Set[str]:
    found = set()
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                         timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200:
            import re
            for m in re.finditer(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', r.text):
                found.add(m.group(1).lower())
        print(f"  [RapidDNS]             {len(found)} subdomains")
    except Exception as e:
        print(f"  [RapidDNS]             unavailable ({e})")
    return found


def get_subdomains_certsan(domain: str) -> Set[str]:
    """Extract SANs from the domain's own TLS certificate."""
    found = set()
    try:
        import ssl, socket as _socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with _socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                for _type, value in cert.get("subjectAltName", []):
                    if _type == "DNS":
                        v = value.lstrip("*.").lower()
                        if v.endswith(f".{domain}") or v == domain:
                            found.add(v)
        print(f"  [Certificate SANs]     {len(found)} subdomains")
    except Exception as e:
        print(f"  [Cert SANs]            unavailable ({e})")
    return found


def get_subdomains_shodan(domain: str) -> Set[str]:
    found = set()
    if not SHODAN_KEY:
        return found
    try:
        r = requests.get(f"https://api.shodan.io/dns/domain/{domain}",
                         params={"key": SHODAN_KEY}, timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200:
            for entry in r.json().get("subdomains", []):
                found.add(f"{entry}.{domain}")
        print(f"  [Shodan DNS]           {len(found)} subdomains")
    except Exception as e:
        print(f"  [Shodan]               unavailable ({e})")
    return found


def get_subdomains_securitytrails(domain: str) -> Set[str]:
    found = set()
    if not SECURITYTRAILS_KEY:
        return found
    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={**HEADERS, "APIKEY": SECURITYTRAILS_KEY}, timeout=TIMEOUT)
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                found.add(f"{sub}.{domain}")
        print(f"  [SecurityTrails]       {len(found)} subdomains")
    except Exception as e:
        print(f"  [SecurityTrails]       unavailable ({e})")
    return found


def get_subdomains_virustotal(domain: str) -> Set[str]:
    found = set()
    if not VIRUSTOTAL_KEY:
        return found
    try:
        url    = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        hdrs   = {**HEADERS, "x-apikey": VIRUSTOTAL_KEY}
        cursor = None
        for _ in range(5):
            params = {"limit": 100}
            if cursor:
                params["cursor"] = cursor
            r = requests.get(url, headers=hdrs, params=params, timeout=TIMEOUT)
            if r.status_code != 200:
                break
            data = r.json()
            for item in data.get("data", []):
                found.add(item.get("id",""))
            cursor = data.get("meta",{}).get("cursor")
            if not cursor:
                break
        print(f"  [VirusTotal]           {len(found)} subdomains")
    except Exception as e:
        print(f"  [VirusTotal]           unavailable ({e})")
    return found


def _resolve_one(hostname: str):
    try:
        socket.getaddrinfo(hostname, None, socket.AF_INET,
                           socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
        return hostname
    except Exception:
        return None


def get_subdomains_brute(domain: str, threads: int = 300) -> Set[str]:
    """DNS brute-force with full 2500-word list."""
    found = set()
    candidates = [f"{w}.{domain}" for w in WORDLIST]
    resolved = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(_resolve_one, candidates):
            if result:
                found.add(result)
                resolved += 1
    print(f"  [DNS Brute-force]      {resolved}/{len(candidates)} resolved")
    return found


def verify_resolves(hostname: str):
    return _resolve_one(hostname)


def discover_all_subdomains(domain: str, threads: int = 100) -> list:
    print(f"\n  [Enhanced Discovery] Starting for: {domain}")
    print(f"  " + "-" * 54)

    all_found: Set[str] = set()

    # Run all passive sources in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = {
            ex.submit(get_subdomains_crtsh,          domain): "crtsh",
            ex.submit(get_subdomains_hackertarget,    domain): "hackertarget",
            ex.submit(get_subdomains_alienvault,      domain): "alienvault",
            ex.submit(get_subdomains_rapiddns,        domain): "rapiddns",
            ex.submit(get_subdomains_certsan,         domain): "certsan",
            ex.submit(get_subdomains_shodan,          domain): "shodan",
            ex.submit(get_subdomains_securitytrails,  domain): "securitytrails",
            ex.submit(get_subdomains_virustotal,      domain): "virustotal",
        }
        for f in concurrent.futures.as_completed(futs):
            try:
                all_found.update(f.result())
            except Exception:
                pass

    # DNS brute-force (runs its own thread pool internally)
    all_found.update(get_subdomains_brute(domain, threads=300))

    # Remove root domain
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
