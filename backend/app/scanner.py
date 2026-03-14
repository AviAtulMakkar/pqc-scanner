#!/usr/bin/env python3
"""
=============================================================
  PQC CBOM SCANNER  —  Quantum-Ready Cybersecurity Tool
  Cryptographic Bill of Materials for Public-Facing Assets
  Banking Edition | NIST FIPS 203 / 204 / 205
=============================================================

WHAT THIS SCRIPT DOES:
  1.  Discover all subdomains via live passive DNS sources
  2.  Resolve each host to an IP address
  3.  Port scan to find open services
  4.  Use sslyze to exhaustively enumerate ALL supported cipher
      suites, TLS versions, and the negotiated key exchange group
      (sslyze bypasses local OpenSSL limits and avoids WAF triggers)
  5.  Parse X.509 certificate signature algorithm to check if it
      uses a PQC algorithm (required for "Fully Quantum Safe" label)
  6.  Assess PQC readiness per endpoint
  7.  Issue "PQC Ready" / "Fully Quantum Safe" labels where earned
  8.  Export a CycloneDX 1.6 CBOM JSON (industry standard format)
  9.  Generate a readable HTML report for presentation

INSTALL:
  pip install requests colorama sslyze cryptography

USAGE:
  python3 discovery.py -d example.com
  python3 discovery.py -d example.com --ports web --output report
=============================================================
"""

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import struct
import sys
import time
import uuid
import warnings
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings()

# Suppress known benign deprecation warnings:
#   1. CryptographyDeprecationWarning from sslyze's bundled CA trust store
#      (a negative serial number in one of Mozilla's root certs — not our cert)
#   2. DeprecationWarning for ssl.TLSVersion.TLSv1 (handled in code; filter belt-and-braces)
warnings.filterwarnings(
    "ignore",
    message=".*negative serial number.*",
    category=Warning,
)
warnings.filterwarnings(
    "ignore",
    message=".*TLSv1.*deprecated.*",
    category=DeprecationWarning,
)

# sslyze is the industry-standard TLS scanner — it handles cipher
# enumeration properly without the limitations of Python's ssl module.
#
# IMPORTANT — WHY sslyze MIGHT SHOW "not installed" EVEN AFTER pip install:
#
#   On Windows with multiple Python versions, pip installs packages for ONE
#   specific Python interpreter. If you run the script with a different Python
#   than the one pip used, the packages won't be found.
#
#   The fix: always use the SAME Python executable for both pip and the script.
#   Use:  python -m pip install sslyze     (installs for the Python you run with)
#   Then: python discovery.py -d example.com
#
#   If you use "py -3.14" to run, use "py -3.14 -m pip install sslyze" to install.
try:
    from sslyze import (
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
        ScanCommand,
    )
    # ServerNotReachable was removed in sslyze 6.x — errors are handled via scan result objects
    pass  # no additional imports needed from sslyze.errors
    SSLYZE_AVAILABLE = True
    SSLYZE_IMPORT_ERROR = None
except ImportError as _sslyze_err:
    SSLYZE_AVAILABLE = False
    SSLYZE_IMPORT_ERROR = str(_sslyze_err)
except Exception as _sslyze_err:
    SSLYZE_AVAILABLE = False
    SSLYZE_IMPORT_ERROR = f"{type(_sslyze_err).__name__}: {_sslyze_err}"  

# cryptography library gives us proper X.509 certificate parsing
# including the signature algorithm field (needed for PQC cert detection)
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives import hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# ── Colour helpers ────────────────────────────────────────────
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    def green(t):  return Fore.GREEN  + str(t) + Style.RESET_ALL
    def red(t):    return Fore.RED    + str(t) + Style.RESET_ALL
    def yellow(t): return Fore.YELLOW + str(t) + Style.RESET_ALL
    def cyan(t):   return Fore.CYAN   + str(t) + Style.RESET_ALL
except ImportError:
    def green(t):  return str(t)
    def red(t):    return str(t)
    def yellow(t): return str(t)
    def cyan(t):   return str(t)


# =============================================================
#  PORT LISTS
# =============================================================

WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

TOP_PORTS = [
    # Web
    80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
    # Email (TLS)
    25, 465, 587, 993, 995,
    # TLS-based VPN
    500, 1194, 1723, 4500,
    # Databases
    3306, 5432, 6379, 9200, 27017,
    # Other common TLS services
    22, 53, 389, 636, 3389, 5900, 9090,
]


# =============================================================
#  IANA NAMED GROUPS REGISTRY
#  Source: RFC 8446 §4.2.7, RFC 7919, IANA PQC assignments
#  Used when parsing raw ServerHello key_share extension bytes.
#  Format: group_id → (short_name, description, is_quantum_safe)
# =============================================================

NAMED_GROUPS = {
    # Classical elliptic curves — all vulnerable to Shor's algorithm
    0x0017: ("secp256r1",           "NIST P-256",                                    False),
    0x0018: ("secp384r1",           "NIST P-384",                                    False),
    0x0019: ("secp521r1",           "NIST P-521",                                    False),
    0x001D: ("x25519",              "X25519 (Curve25519)",                           False),
    0x001E: ("x448",                "X448 (Curve448)",                               False),
    # Finite-field DH — also vulnerable to quantum computers
    0x0100: ("ffdhe2048",           "FFDHE-2048",                                    False),
    0x0101: ("ffdhe3072",           "FFDHE-3072",                                    False),
    # ── Hybrid PQC (IANA-finalised, deployed by Google/Cloudflare/Chrome) ──
    # RFC 8446 §4.2.8 / draft-ietf-tls-hybrid-design
    0x11EB: ("SecP256r1MLKEM768",   "Hybrid P-256+ML-KEM-768 (IANA final)",          True),
    0x11EC: ("X25519MLKEM768",      "Hybrid X25519+ML-KEM-768 (IANA final)",         True),
    # Draft hybrid codes — still in wide deployment (Cloudflare, older Chrome)
    0x6399: ("X25519Kyber768d00",   "Hybrid X25519+Kyber768 Draft-00 (PQC)",         True),
    0x639A: ("P256Kyber768d00",     "Hybrid P-256+Kyber768 Draft-00 (PQC)",          True),
    # NIST-standardised pure post-quantum (FIPS 203 — ML-KEM)
    0xFE30: ("ML-KEM-512",          "NIST ML-KEM-512 FIPS 203",                      True),
    0xFE31: ("ML-KEM-768",          "NIST ML-KEM-768 FIPS 203",                      True),
    0xFE32: ("ML-KEM-1024",         "NIST ML-KEM-1024 FIPS 203",                     True),
}

# TLS cipher suite byte-code → OpenSSL name (for raw ServerHello parsing)
CIPHER_ID_TO_NAME = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xC027: "ECDHE-RSA-AES128-SHA256",
    0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384",
    0x002F: "AES128-SHA",
    0x0035: "AES256-SHA",
}

# X.509 signature algorithm OIDs that are quantum-safe
# Source: NIST FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
PQC_SIGNATURE_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44 (FIPS 204)",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65 (FIPS 204)",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87 (FIPS 204)",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s (FIPS 205)",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f (FIPS 205)",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s (FIPS 205)",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f (FIPS 205)",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s (FIPS 205)",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f (FIPS 205)",
    # Falcon (NIST alternate candidate)
    "1.3.9999.3.6":             "Falcon-512",
    "1.3.9999.3.9":             "Falcon-1024",
}

# Signature algorithms that are quantum-vulnerable
VULNERABLE_SIG_ALGORITHMS = [
    "sha256WithRSAEncryption",
    "sha384WithRSAEncryption",
    "sha512WithRSAEncryption",
    "sha1WithRSAEncryption",
    "ecdsa-with-SHA256",
    "ecdsa-with-SHA384",
    "ecdsa-with-SHA512",
    "dsa-with-SHA256",
]

# PQC key exchange algorithm names — matched case-insensitively against
# group names from both sslyze ephemeral_key and our raw parser.
# Must cover all variants: IANA-final names, draft names, sslyze internal names.
PQC_KEX_NAMES = [
    "x25519mlkem768",       # IANA final (0x11ec) — Google/Chrome production
    "secp256r1mlkem768",    # IANA final (0x11eb)
    "x25519kyber768",       # draft hybrid (0x6399) — Cloudflare/older Chrome
    "p256kyber768",         # draft hybrid (0x639a)
    "kyber",                # any kyber variant
    "ml-kem", "mlkem",      # any ML-KEM variant
    "x25519mlkem",          # sslyze may abbreviate
]


# =============================================================
#  PQC ASSESSMENT ENGINE
#  Decides the quantum readiness label for one TLS endpoint.
#  Takes into account: TLS version, KEX group, cipher suite,
#  AND the certificate signature algorithm.
# =============================================================

RECOMMENDATIONS = {
    "upgrade_tls": [
        "Upgrade TLS version to 1.3 immediately — TLS 1.2 and below are not quantum safe.",
        "Disable TLS 1.2, 1.1, 1.0 and all SSLv3 cipher suites at the load balancer.",
    ],
    "upgrade_kex": [
        "Replace key exchange with ML-KEM-768 per NIST FIPS 203.",
        "As an interim step, deploy hybrid X25519Kyber768 (already used by Cloudflare/Google).",
        "Configure your TLS library to advertise PQC named groups in the supported_groups extension.",
    ],
    "upgrade_cert": [
        "The certificate uses a classical signature algorithm vulnerable to quantum computers.",
        "Request a new certificate signed with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
        "Work with your CA (Certificate Authority) to obtain a PQC-signed certificate.",
        "Note: Most public CAs do not yet issue PQC certificates — plan for migration.",
    ],
    "hndl_warning": [
        "HIGH HNDL RISK: Adversaries may be recording this traffic today to decrypt later.",
        "Treat all data sent over this endpoint as potentially compromised in the future.",
        "Prioritise migration for endpoints carrying sensitive banking or customer data.",
    ],
}


def assess_pqc_readiness(tls_version, kex_group_name, kex_is_pqc,
                          cert_sig_algorithm, cert_sig_is_pqc):
    """
    Determine the PQC readiness label for one TLS endpoint.

    The label is determined by checking three things in order:

    1. TLS version — must be 1.3 minimum
    2. Key exchange — must use a PQC or hybrid-PQC algorithm
    3. Certificate signature — must use ML-DSA or SLH-DSA for full label

    Labels:
      FULLY QUANTUM SAFE   — TLS 1.3 + PQC KEX + PQC certificate signature
      PQC READY            — TLS 1.3 + PQC KEX, but classical certificate
      PQC NOT READY        — TLS 1.3 but classical key exchange
      NOT QUANTUM SAFE     — TLS 1.2 or below
    """
    recommendations = []
    certificate_label = None

    # Check TLS version first — this is the baseline requirement
    is_tls13 = (tls_version == "TLSv1.3")

    if not is_tls13:
        recommendations += RECOMMENDATIONS["upgrade_tls"]
        recommendations += RECOMMENDATIONS["hndl_warning"]
        kex_info = f" — Key Exchange: {kex_group_name}" if kex_group_name and kex_group_name not in ("Unknown", "TLS1.3-KEX") else ""
        return {
            "label":             "NOT QUANTUM SAFE",
            "label_class":       "danger",
            "certificate_label": None,
            "posture":           f"{tls_version}{kex_info} — Not quantum safe",
            "recommendations":   recommendations
        }

    # TLS 1.3 confirmed — now check key exchange
    if not kex_is_pqc:
        recommendations += RECOMMENDATIONS["upgrade_kex"]
        recommendations += RECOMMENDATIONS["upgrade_cert"]
        return {
            "label":             "PQC NOT READY",
            "label_class":       "warn",
            "certificate_label": None,
            "posture":           "TLS 1.3 present, but key exchange is still classical",
            "recommendations":   recommendations
        }

    # PQC key exchange confirmed — now check the certificate signature
    if cert_sig_is_pqc:
        # Best case: TLS 1.3 + PQC KEX + PQC certificate
        certificate_label = "Fully Quantum Safe"
        return {
            "label":             "FULLY QUANTUM SAFE",
            "label_class":       "safe",
            "certificate_label": certificate_label,
            "posture":           "TLS 1.3 + PQC Key Exchange + PQC Certificate Signature",
            "recommendations":   [
                "This endpoint fully meets NIST PQC requirements.",
                "Monitor NIST updates for algorithm rotation guidance.",
                "Ensure all certificate renewals continue using PQC algorithms.",
            ]
        }
    else:
        # PQC KEX but classical certificate signature
        certificate_label = "Post Quantum Cryptography (PQC) Ready"
        recommendations += RECOMMENDATIONS["upgrade_cert"]
        return {
            "label":             "PQC READY",
            "label_class":       "pqc-ready",
            "certificate_label": certificate_label,
            "posture":           "TLS 1.3 + PQC Key Exchange — certificate signature upgrade needed",
            "recommendations":   recommendations
        }


# =============================================================
#  SUBDOMAIN DISCOVERY
#  All passive DNS sources — no wordlists.
# =============================================================

def get_subdomains_from_crtsh(domain):
    """
    Query crt.sh Certificate Transparency logs.
    Every TLS certificate ever issued for a domain is publicly logged.
    This is the single best passive subdomain source.
    """
    found = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, verify=False
        )
        for entry in r.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if domain in name and name != domain:
                    found.add(name)
        print(green(f"  [crt.sh CT Logs]       {len(found)} subdomains"))
    except Exception as e:
        print(yellow(f"  [crt.sh]               unavailable ({e})"))
    return found


def get_subdomains_from_hackertarget(domain):
    """HackerTarget passive DNS database API."""
    found = set()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10
        )
        for line in r.text.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip()
                if domain in sub and sub != domain:
                    found.add(sub)
        print(green(f"  [HackerTarget DNS]     {len(found)} subdomains"))
    except Exception as e:
        print(yellow(f"  [HackerTarget]         unavailable ({e})"))
    return found


def get_subdomains_from_alienvault(domain):
    """AlienVault OTX passive DNS records."""
    found = set()
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=10
        )
        for record in r.json().get("passive_dns", []):
            h = record.get("hostname", "").strip()
            if domain in h and h != domain:
                found.add(h)
        print(green(f"  [AlienVault OTX]       {len(found)} subdomains"))
    except Exception as e:
        print(yellow(f"  [AlienVault OTX]       unavailable ({e})"))
    return found


def get_subdomains_from_rapiddns(domain):
    """RapidDNS passive DNS scrape."""
    found = set()
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=10, headers={"User-Agent": "Mozilla/5.0"}
        )
        for match in re.findall(
            r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>',
            r.text
        ):
            if match != domain:
                found.add(match)
        print(green(f"  [RapidDNS]             {len(found)} subdomains"))
    except Exception as e:
        print(yellow(f"  [RapidDNS]             unavailable ({e})"))
    return found


def get_subdomains_from_cert_san(domain):
    """
    Connect to the root domain on port 443 and read the certificate's
    Subject Alternative Names. Many servers list all their subdomains
    on a single wildcard or multi-domain certificate.
    """
    found = set()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                cert = s.getpeercert()
                for t, v in cert.get("subjectAltName", []):
                    if t == "DNS":
                        v = v.strip().lstrip("*.")
                        if domain in v and v != domain:
                            found.add(v)
        print(green(f"  [Certificate SANs]     {len(found)} subdomains"))
    except Exception as e:
        print(yellow(f"  [Certificate SANs]     unavailable ({e})"))
    return found


def verify_resolves(hostname):
    """Return hostname if it resolves via DNS, else None."""
    try:
        # Use getaddrinfo without mutating the global socket timeout
        socket.getaddrinfo(hostname, None, socket.AF_INET,
                           socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
        return hostname
    except Exception:
        return None


def discover_subdomains(domain, threads=100):
    """
    Run all passive DNS sources and verify each result resolves.
    Returns sorted list of confirmed live subdomains.
    """
    print(f"\n  Subdomain discovery for: {domain}")
    print(f"  " + "-" * 54)

    all_found = set()
    all_found.update(get_subdomains_from_crtsh(domain))
    all_found.update(get_subdomains_from_hackertarget(domain))
    all_found.update(get_subdomains_from_alienvault(domain))
    all_found.update(get_subdomains_from_rapiddns(domain))
    all_found.update(get_subdomains_from_cert_san(domain))

    print(f"\n  Total from all sources : {len(all_found)}")
    print(f"  Verifying DNS resolution...")

    confirmed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(verify_resolves, all_found):
            if result:
                confirmed.append(result)

    print(green(f"  Confirmed live hosts   : {len(confirmed)}"))
    return sorted(confirmed)


# =============================================================
#  PORT SCANNING
# =============================================================

def is_port_open(ip, port, timeout=0.8):
    """Try TCP connect. Returns port number if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None


def scan_ports(ip, port_list):
    """Scan all ports in parallel. Returns sorted list of open ports."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        for result in ex.map(lambda p: is_port_open(ip, p), port_list):
            if result:
                open_ports.append(result)
    return sorted(open_ports)


# =============================================================
#  RAW TLS SERVERHELLO PARSER
#
#  Purpose: extract the key_share group ID directly from the wire.
#
#  Why we need this:
#    In TLS 1.3, the key exchange algorithm is negotiated via the
#    key_share extension in the ServerHello. The cipher suite name
#    (e.g. TLS_AES_256_GCM_SHA384) deliberately omits this info
#    (see RFC 8446). Python's ssl module completes the handshake
#    internally and never exposes which group was selected.
#
#    We bypass this by opening a raw TCP socket, sending our own
#    ClientHello, and reading the ServerHello bytes before Python's
#    ssl layer has any involvement. We then parse the bytes manually
#    per RFC 8446 to find extension 0x0033 (key_share) and read the
#    2-byte named group ID from it.
#
#    For TLS 1.2 there is no key_share extension — we read the key
#    exchange from the cipher suite name instead (accurate per RFC 5246).
# =============================================================

def _gen_x25519_keypair():
    """Generate a real ephemeral X25519 keypair. Returns (private_key_obj, public_bytes)."""
    if CRYPTOGRAPHY_AVAILABLE:
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            priv = X25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return pub_bytes
        except Exception:
            pass
    import os
    return os.urandom(32)


# SHA-256("HelloRetryRequest") — RFC 8446 §4.1.3
# A ServerHello with this exact random value is actually a HelloRetryRequest.
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891"
    "C2A211167ABB8C5E079E09E2C8A8339C"
)


def build_client_hello_x25519_only(hostname):
    """
    Build a ClientHello that ONLY offers X25519 in key_share, but advertises
    all PQC groups in supported_groups.

    WHY THIS WORKS (the HRR dance):
    We cannot send fake ML-KEM keys — BoringSSL (Google) validates them and
    sends illegal_parameter. Instead:

    1. We send X25519 in key_share + PQC groups in supported_groups
    2. If the server supports PQC, it sends a HelloRetryRequest (HRR)
       specifying the PQC group it wants (e.g. 0x11EC)
    3. We parse the HRR — the selected_group field tells us exactly which
       PQC group the server prefers
    4. If the server doesn't support PQC, it accepts X25519 and sends
       a normal ServerHello with group 0x001D

    This is how real TLS clients (Chrome, Firefox) negotiate PQC too.
    """
    import os
    sni = hostname.encode()
    x25519_pub = _gen_x25519_keypair()

    # SNI (0x0000)
    sni_data = b'\x00' + struct.pack(">H", len(sni)) + sni
    sni_ext  = (struct.pack(">H", 0x0000)
                + struct.pack(">H", len(sni_data) + 2)
                + struct.pack(">H", len(sni_data))
                + sni_data)

    # supported_versions (0x002b) — TLS 1.3 + 1.2
    sv_ext = struct.pack(">H", 0x002b) + struct.pack(">H", 5) + b'\x04\x03\x04\x03\x03'

    # supported_groups (0x000a) — advertise ALL groups including PQC
    # Server reads this to know we WANT PQC, then sends HRR
    groups     = list(NAMED_GROUPS.keys())
    groups_raw = b''.join(struct.pack(">H", g) for g in groups)
    sg_ext     = (struct.pack(">H", 0x000a)
                  + struct.pack(">H", len(groups_raw) + 2)
                  + struct.pack(">H", len(groups_raw))
                  + groups_raw)

    # key_share (0x0033) — ONLY X25519, which we can generate validly
    ks_x25519  = struct.pack(">H", 0x001D) + struct.pack(">H", 32) + x25519_pub
    ks_ext     = (struct.pack(">H", 0x0033)
                  + struct.pack(">H", len(ks_x25519) + 2)
                  + struct.pack(">H", len(ks_x25519))
                  + ks_x25519)

    # signature_algorithms (0x000d)
    sig_algs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501]
    sa_raw   = b''.join(struct.pack(">H", s) for s in sig_algs)
    sa_ext   = (struct.pack(">H", 0x000d)
                + struct.pack(">H", len(sa_raw) + 2)
                + struct.pack(">H", len(sa_raw))
                + sa_raw)

    all_exts  = sni_ext + sv_ext + sg_ext + ks_ext + sa_ext
    ext_block = struct.pack(">H", len(all_exts)) + all_exts

    cipher_ids = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C, 0x009D]
    cs_raw     = b''.join(struct.pack(">H", c) for c in cipher_ids)
    cs_block   = struct.pack(">H", len(cs_raw)) + cs_raw

    body = b'\x03\x03' + os.urandom(32) + b'\x00' + cs_block + b'\x01\x00' + ext_block
    hs   = b'\x01' + struct.pack(">I", len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack(">H", len(hs)) + hs


def read_tls_records(sock, timeout=5, max_bytes=65536):
    """Read raw bytes from socket, respecting TLS record boundaries."""
    data = b''
    sock.settimeout(timeout)
    try:
        while len(data) < max_bytes:
            # Need at least 5 bytes for record header
            while len(data) < 5:
                chunk = sock.recv(1024)
                if not chunk:
                    return data
                data += chunk
            record_len = struct.unpack(">H", data[3:5])[0]
            target = 5 + record_len
            while len(data) < target:
                chunk = sock.recv(4096)
                if not chunk:
                    return data
                data += chunk
            # Got one complete record — if it's Alert or we have ServerHello/HRR, stop
            if data[0] == 0x15:  # Alert
                return data
            if data[0] == 0x16 and len(data) >= 6 and data[5] in (0x02, 0x06):
                return data  # ServerHello (0x02) or HelloRetryRequest equivalent
            # Could be multiple records — keep reading up to max
            if len(data) >= target:
                break
    except (socket.timeout, OSError):
        pass
    return data


def parse_server_response(raw_bytes):
    """
    Parse TLS server response. Handles both:
      - ServerHello  → extract key_share group (tells us negotiated KEX)
      - HelloRetryRequest → extract selected_group (tells us server's PREFERRED KEX)

    An HRR looks like a ServerHello but has a specific magic random value.
    The HRR contains a key_share extension with just the selected group ID (2 bytes),
    NOT a full key_share entry — that's how we know which group the server wants.

    Returns dict with: tls_version, key_group_id, key_group_name,
                       key_group_pqc, cipher_name, is_hrr
    """
    result = {}
    pos = 0

    while pos < len(raw_bytes) - 5:
        if raw_bytes[pos] != 0x16:
            pos += 1
            continue

        record_len = struct.unpack(">H", raw_bytes[pos+3:pos+5])[0]
        record_end = pos + 5 + record_len
        if record_end > len(raw_bytes):
            break

        record_data = raw_bytes[pos+5:record_end]
        pos = record_end

        if len(record_data) < 4 or record_data[0] != 0x02:
            continue

        # ServerHello / HRR body
        bp = 4          # skip handshake header (type+len = 4 bytes)
        if bp + 2 + 32 > len(record_data):
            break

        # legacy_version (2) + random (32)
        random_field = record_data[bp+2:bp+2+32]
        is_hrr = (random_field == HRR_RANDOM)
        bp += 2 + 32

        # session_id
        if bp >= len(record_data): break
        sid_len = record_data[bp]
        bp += 1 + sid_len

        # cipher suite (2 bytes)
        if bp + 2 > len(record_data): break
        cipher_id = struct.unpack(">H", record_data[bp:bp+2])[0]
        result["cipher_id"]   = cipher_id
        result["cipher_name"] = CIPHER_ID_TO_NAME.get(cipher_id, f"0x{cipher_id:04X}")
        bp += 3  # cipher(2) + compression(1)

        # extensions
        if bp + 2 > len(record_data): break
        ext_total = struct.unpack(">H", record_data[bp:bp+2])[0]
        bp += 2
        ep = bp

        while ep + 4 <= bp + ext_total and ep + 4 <= len(record_data):
            ext_type = struct.unpack(">H", record_data[ep:ep+2])[0]
            ext_len  = struct.unpack(">H", record_data[ep+2:ep+4])[0]
            ext_data = record_data[ep+4:ep+4+ext_len]
            ep += 4 + ext_len

            # supported_versions → real TLS version
            if ext_type == 0x002b and len(ext_data) >= 2:
                ver = struct.unpack(">H", ext_data[0:2])[0]
                result["tls_version"] = {
                    0x0304: "TLSv1.3", 0x0303: "TLSv1.2",
                    0x0302: "TLSv1.1", 0x0301: "TLSv1.0",
                }.get(ver, f"0x{ver:04X}")

            # key_share → group selection
            if ext_type == 0x0033 and len(ext_data) >= 2:
                group_id = struct.unpack(">H", ext_data[0:2])[0]
                result["key_group_id"] = group_id
                result["is_hrr"] = is_hrr
                if group_id in NAMED_GROUPS:
                    name, desc, is_pqc = NAMED_GROUPS[group_id]
                    result["key_group_name"] = name
                    result["key_group_desc"] = desc
                    result["key_group_pqc"]  = is_pqc
                else:
                    result["key_group_name"] = f"Unknown(0x{group_id:04X})"
                    result["key_group_desc"] = "Unknown group"
                    result["key_group_pqc"]  = False

        result["is_hrr"] = is_hrr
        return result

    return result


def get_key_exchange_via_raw_handshake(hostname, ip, port):
    """
    Detect the PQC key exchange group a server supports using the HRR dance:

    1. Send ClientHello with only X25519 in key_share + PQC groups in supported_groups
    2a. If server supports PQC → sends HelloRetryRequest (HRR) with its preferred group
        → HRR key_share extension contains just the 2-byte group ID it wants
    2b. If server doesn't support PQC → sends normal ServerHello with X25519
        → key_share extension contains the X25519 group (0x001D)

    In both cases we learn the server's actual KEX capability from one round trip.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        try:
            sock.sendall(build_client_hello_x25519_only(hostname))
            raw = read_tls_records(sock, timeout=5)
        finally:
            sock.close()
        if not raw:
            return None
        parsed = parse_server_response(raw)
        return parsed if parsed else None
    except Exception:
        return None


def get_tls12_kex_from_cipher_name(cipher_name):
    """
    Infer key exchange algorithm from cipher suite name.

    TLS 1.2 (RFC 5246): cipher name encodes KEX directly — this is accurate.
      e.g. ECDHE-RSA-AES256-GCM-SHA384 → ECDHE
           DHE-RSA-AES128-SHA           → DHE

    TLS 1.3 (RFC 8446): cipher names like TLS_AES_256_GCM_SHA384 do NOT
      encode the KEX — it's negotiated separately via key_share extension.
      For TLS 1.3 we return "TLS1.3-KEX" as a placeholder; the real KEX
      must come from the raw HRR/ServerHello parser.
    """
    c = cipher_name.upper()
    # TLS 1.3 cipher names start with TLS_AES or TLS_CHACHA
    if c.startswith("TLS_AES") or c.startswith("TLS_CHACHA"):
        return "TLS1.3-KEX", "TLS 1.3 key exchange (see key_share)", False
    if   "ECDHE" in c: return "ECDHE", "ECDHE (quantum-vulnerable)", False
    elif "DHE"   in c: return "DHE",   "DHE (quantum-vulnerable)",   False
    elif "ECDH"  in c: return "ECDH",  "ECDH (quantum-vulnerable)",  False
    elif "RSA"   in c: return "RSA",   "RSA (quantum-vulnerable)",   False
    elif "KYBER" in c or "ML-KEM" in c:
        return "ML-KEM", "NIST ML-KEM FIPS 203 (quantum-safe)", True
    else:
        return "Unknown", f"Cannot infer KEX from: {cipher_name}", False


# =============================================================
#  CERTIFICATE DEEP INSPECTION
#
#  Gap addressed: X.509 signature algorithm must be checked
#  to determine if the certificate itself is quantum-safe.
#  A PQC key exchange + classical RSA certificate = NOT fully safe.
#  The "Fully Quantum Safe" label requires a PQC signature algorithm
#  on the certificate (ML-DSA per FIPS 204, or SLH-DSA per FIPS 205).
# =============================================================

def get_raw_certificate_bytes(hostname, ip, port, timeout=5):
    """
    Fetch the raw DER-encoded certificate bytes from the server.
    Tries multiple strategies to maximise cert retrieval success rate.
    """
    def _try_fetch(connect_host, sni_host, timeout, min_ver=None):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if min_ver:
                try:
                    ctx.minimum_version = min_ver
                except AttributeError:
                    pass
            with socket.create_connection((connect_host, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=sni_host) as tls_sock:
                    return tls_sock.getpeercert(binary_form=True), tls_sock.getpeercert()
        except Exception:
            return None, None

    # Strategy 1: hostname SNI + TLS 1.2 minimum (avoids deprecation warning)
    der, std = _try_fetch(ip, hostname, timeout, ssl.TLSVersion.TLSv1_2)
    if der:
        return der, std

    # Strategy 2: retry without minimum version (supports TLS 1.0/1.1 legacy servers)
    der, std = _try_fetch(ip, hostname, timeout, None)
    if der:
        return der, std

    # Strategy 3: connect directly to IP with no SNI (catches SNI-rejecting servers)
    der, std = _try_fetch(ip, ip, timeout, None)
    if der:
        return der, std

    return None, None


def parse_certificate_details(der_cert_bytes, std_cert_dict):
    """
    Use the `cryptography` library to parse the X.509 certificate
    and extract the signature algorithm OID — the field that tells
    us whether the certificate itself is quantum-safe.

    Python's built-in ssl module cannot give us this OID.
    The `cryptography` library parses the full DER structure.

    Returns a dict with all certificate details.
    """
    details = {
        "subject":           "Unknown",
        "issuer":            "Unknown",
        "expiry":            "Unknown",
        "serial":            "Unknown",
        "san_domains":       [],
        "sig_algorithm":     "Unknown",
        "sig_algorithm_oid": "Unknown",
        "sig_is_pqc":        False,
        "key_type":          "Unknown",
        "key_bits":          "Unknown",
    }

    # Parse basic fields — prefer cryptography lib (works with CERT_NONE),
    # fall back to ssl dict (only populated when cert is trusted/verified)
    if std_cert_dict:
        subject_dict = {}
        for field_list in std_cert_dict.get("subject", []):
            for k, v in field_list:
                subject_dict[k] = v
        issuer_dict = {}
        for field_list in std_cert_dict.get("issuer", []):
            for k, v in field_list:
                issuer_dict[k] = v

        if subject_dict.get("commonName"):
            details["subject"] = subject_dict["commonName"]
        if issuer_dict.get("organizationName"):
            details["issuer"]  = issuer_dict["organizationName"]
        if std_cert_dict.get("notAfter"):
            details["expiry"]  = std_cert_dict["notAfter"]
        if std_cert_dict.get("serialNumber"):
            details["serial"]  = std_cert_dict["serialNumber"]
        details["san_domains"] = [
            v for t, v in std_cert_dict.get("subjectAltName", []) if t == "DNS"
        ]

    # Use `cryptography` library for deep parsing if available
    if CRYPTOGRAPHY_AVAILABLE and der_cert_bytes:
        try:
            cert = x509.load_der_x509_certificate(der_cert_bytes)

            # Subject / issuer / expiry — parse from DER, works for ALL certs
            # (ssl's getpeercert() only returns these when CERT_REQUIRED is set)
            try:
                cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if cn:
                    details["subject"] = cn[0].value
            except Exception:
                pass
            try:
                org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                if org:
                    details["issuer"] = org[0].value
                else:
                    cn_i = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    if cn_i:
                        details["issuer"] = cn_i[0].value
            except Exception:
                pass
            try:
                details["expiry"] = cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
            except AttributeError:
                try:
                    details["expiry"] = cert.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT")
                except Exception:
                    pass
            try:
                details["serial"] = str(cert.serial_number)
            except Exception:
                pass
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                details["san_domains"] = san_ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass

            # Get the signature algorithm OID
            sig_alg     = cert.signature_algorithm_oid
            sig_alg_oid = sig_alg.dotted_string

            # OID → friendly name lookup (cryptography's .name attr is often empty)
            _OID_NAMES = {
                "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
                "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
                "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
                "1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
                "1.2.840.10045.4.3.2":   "ecdsa-with-SHA256",
                "1.2.840.10045.4.3.3":   "ecdsa-with-SHA384",
                "1.2.840.10045.4.3.4":   "ecdsa-with-SHA512",
                "2.16.840.1.101.3.4.3.2":"id-dsa-with-sha256",
            }
            sig_alg_display = (
                PQC_SIGNATURE_OIDS.get(sig_alg_oid)         # PQC name first
                or _OID_NAMES.get(sig_alg_oid)              # known classical name
                or getattr(sig_alg, "name", None)           # cryptography attr
                or sig_alg_oid                              # raw OID fallback
            )

            is_pqc   = sig_alg_oid in PQC_SIGNATURE_OIDS

            details["sig_algorithm"]     = sig_alg_display
            details["sig_algorithm_oid"] = sig_alg_oid
            details["sig_is_pqc"]        = is_pqc

            # Get public key type and size
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                details["key_type"] = "RSA"
                details["key_bits"] = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                details["key_type"] = "EC"
                details["key_bits"] = pub_key.key_size
            else:
                details["key_type"] = type(pub_key).__name__
                details["key_bits"] = "N/A"

        except Exception:
            pass

    return details


# =============================================================
#  SSLYZE-BASED CIPHER SUITE ENUMERATION
#
#  Gap addressed: Cipher enumeration using sslyze instead of
#  manual per-cipher probing.
#
#  Why sslyze:
#    1. It uses its own bundled TLS stack (nassl wrapping OpenSSL)
#       which is independent of your system's OpenSSL version.
#       This means it can offer and detect PQC cipher suites even
#       if your machine's OpenSSL doesn't support them.
#    2. It enumerates cipher suites in a single efficient scan
#       rather than one TCP connection per cipher.
#    3. It is purpose-built to avoid triggering WAF rate limits.
#    4. It extracts the negotiated key exchange group directly from
#       the handshake (the Supported Groups / key_share data).
#
#  Fallback: if sslyze is not installed, we fall back to our raw
#  ServerHello parser which at least gets the preferred cipher + KEX.
# =============================================================

def run_sslyze_scan(hostname, ip, port):
    """
    Run a full sslyze TLS scan on one host:port.
    Returns a structured dict with all findings, or None on failure.
    """
    if not SSLYZE_AVAILABLE:
        return None

    try:
        location     = ServerNetworkLocation(hostname=hostname, port=port, ip_address=ip)
        scan_request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
            }
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])
        scan_result = next(scanner.get_results())

        # Check for connectivity errors (server unreachable / TLS handshake failed)
        if getattr(scan_result, "connectivity_error_trace", None) is not None:
            return None

        # Access the inner result object — attribute name changed across sslyze versions
        inner = getattr(scan_result, "scan_result", None)
        if inner is None:
            return None

        result = {
            "tls_versions_supported":  [],
            "ciphers_by_version":      {},
            "all_ciphers":             [],
            "vulnerable_ciphers":      [],
            "pqc_ciphers":             [],
            "preferred_cipher":        None,
            "preferred_tls_version":   None,
            "key_exchange_group":      None,
            "key_exchange_is_pqc":     False,
        }

        # sslyze ScanCommand enum values map directly to snake_case attribute names
        # on the inner result object. e.g. ScanCommand.TLS_1_3_CIPHER_SUITES → tls_1_3_cipher_suites
        version_commands = [
            (ScanCommand.TLS_1_3_CIPHER_SUITES, "TLSv1.3"),
            (ScanCommand.TLS_1_2_CIPHER_SUITES, "TLSv1.2"),
            (ScanCommand.TLS_1_1_CIPHER_SUITES, "TLSv1.1"),
            (ScanCommand.TLS_1_0_CIPHER_SUITES, "TLSv1.0"),
            (ScanCommand.SSL_3_0_CIPHER_SUITES, "SSLv3"),
            (ScanCommand.SSL_2_0_CIPHER_SUITES, "SSLv2"),
        ]

        for command, version_label in version_commands:
            try:
                attr_name = command.value.lower()
                scan_cmd_result = getattr(inner, attr_name, None)

                if scan_cmd_result is None:
                    continue

                # Skip commands that errored (e.g. SSLv2 probe rejected)
                if hasattr(scan_cmd_result, "error_reason") and scan_cmd_result.error_reason:
                    continue

                accepted = getattr(scan_cmd_result, "accepted_cipher_suites", None)
                if not accepted:
                    continue

                result["tls_versions_supported"].append(version_label)
                cipher_names = []

                for cipher_suite in accepted:
                    name = cipher_suite.cipher_suite.name
                    cipher_names.append(name)
                    result["all_ciphers"].append(name)

                    name_lower = name.lower()
                    name_upper = name.upper()
                    if any(pqc in name_lower for pqc in PQC_KEX_NAMES):
                        result["pqc_ciphers"].append(name)
                    elif any(v in name_upper for v in ["ECDHE", "DHE", "RSA", "ECDH"]):
                        result["vulnerable_ciphers"].append(name)

                    # Extract key exchange group from ephemeral_key if present
                    ek = getattr(cipher_suite, "ephemeral_key", None)
                    if ek is not None:
                        kex_name = (getattr(ek, "curve_name", None)
                                    or getattr(ek, "prime_name", None)
                                    or type(ek).__name__.replace("KeyInfo", "").replace("EphemeralKey", ""))
                        if kex_name:
                            kex_lower  = kex_name.lower()
                            is_pqc_kex = any(pqc in kex_lower for pqc in PQC_KEX_NAMES)
                            if result["key_exchange_group"] is None or is_pqc_kex:
                                result["key_exchange_group"]  = kex_name
                                result["key_exchange_is_pqc"] = is_pqc_kex

                result["ciphers_by_version"][version_label] = cipher_names

                if result["preferred_cipher"] is None and cipher_names:
                    result["preferred_cipher"]      = cipher_names[0]
                    result["preferred_tls_version"] = version_label

            except Exception:
                continue

        # Supplement with raw ServerHello parser for KEX group (TLS 1.3 key_share extension)
        # sslyze often doesn't populate ephemeral_key for TLS 1.3
        if result["key_exchange_group"] is None and result["tls_versions_supported"]:
            raw = get_key_exchange_via_raw_handshake(hostname, ip, port)
            if raw and raw.get("key_group_name"):
                result["key_exchange_group"]  = raw["key_group_name"]
                result["key_exchange_is_pqc"] = raw.get("key_group_pqc", False)

        return result if result["tls_versions_supported"] else None

    except Exception as e:
        # Print the reason sslyze failed so it's visible in the scan output
        print(yellow(f"  [sslyze] {hostname}:{port} → {type(e).__name__}: {e}"))
        return None


# =============================================================
#  FULL HOST SCAN
#  Puts everything together for one host.
# =============================================================

def detect_service_type(hostname, port):
    """Detect service type from port number and HTTP response signals."""
    # Port-based service classification (no HTTP probe needed)
    PORT_TYPES = {
        25:   "SMTP TLS",
        465:  "SMTPS",
        587:  "SMTP STARTTLS",
        993:  "IMAPS",
        995:  "POP3S",
        500:  "TLS-based VPN (IKEv2)",
        1194: "TLS-based VPN (OpenVPN)",
        1723: "TLS-based VPN (PPTP)",
        4500: "TLS-based VPN (IKEv2 NAT-T)",
        22:   "SSH",
        53:   "DNS-over-TLS",
        389:  "LDAP",
        636:  "LDAPS",
        3306: "MySQL TLS",
        5432: "PostgreSQL TLS",
        6379: "Redis TLS",
        9200: "Elasticsearch TLS",
        27017:"MongoDB TLS",
        3389: "RDP TLS",
        5900: "VNC TLS",
    }
    if port in PORT_TYPES:
        return PORT_TYPES[port]

    # HTTP probe for web/API ports
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{hostname}:{port}", timeout=4,
                verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 PQC-Scanner/1.0"}
            )
            ct   = r.headers.get("Content-Type", "").lower()
            body = r.text.lower()[:1000]
            hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}

            # API detection — check Content-Type and common API response patterns
            if "application/json" in ct:
                return "API Endpoint"
            if "application/graphql" in ct or "graphql" in body:
                return "GraphQL API"
            if "swagger" in body or "openapi" in body or "/api-docs" in body:
                return "API (Swagger/OpenAPI)"
            if "application/xml" in ct or "text/xml" in ct:
                return "API (XML/SOAP)"
            # REST API heuristic — JSON body without HTML
            if body.strip().startswith("{") or body.strip().startswith("["):
                return "API Endpoint"
            # Check for API-specific headers
            if "x-api-version" in hdrs or "x-ratelimit" in hdrs or "x-request-id" in hdrs:
                return "API Endpoint"
            return "Web Server"
        except Exception:
            continue
    return "TLS Service"


def scan_single_host(hostname, port_list):
    """
    Full scan pipeline for one host:
      1. Resolve IP
      2. Scan ports
      3. Per port: sslyze scan (or raw fallback) + cert parsing + PQC assessment
    """
    ip = None
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return None

    open_ports = scan_ports(ip, port_list)
    if not open_ports:
        return None

    port_results = []

    for port in open_ports:
        service_type = detect_service_type(hostname, port)

        # ── Step 1: Get cipher suite data ──────────────────────────
        # Priority: sslyze (full) → raw ServerHello (KEX group) → ssl (cipher only)
        sslyze_data = run_sslyze_scan(hostname, ip, port)

        if sslyze_data:
            preferred_cipher    = sslyze_data["preferred_cipher"]
            tls_version         = sslyze_data["preferred_tls_version"] or "Unknown"
            kex_group           = sslyze_data["key_exchange_group"] or "Unknown"
            kex_is_pqc          = sslyze_data["key_exchange_is_pqc"]
            all_ciphers         = sslyze_data["all_ciphers"]
            vulnerable_ciphers  = sslyze_data["vulnerable_ciphers"]
            pqc_ciphers         = sslyze_data["pqc_ciphers"]
            ciphers_by_version  = sslyze_data["ciphers_by_version"]
            detection_method    = "sslyze (full enumeration)"

        else:
            # ── Raw ServerHello parse — reads key_share from the wire ──
            # This is the ONLY way to detect PQC KEX when sslyze isn't available.
            # We send a PQC-capable ClientHello and parse the server's key_share reply.
            raw_result = get_key_exchange_via_raw_handshake(hostname, ip, port)

            # ── ssl module fallback — cipher name only, KEX always Unknown ──
            # Python's ssl module completes the handshake internally and never
            # exposes the negotiated named group. We can only get the cipher name.
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=5) as raw_s:
                    with ctx.wrap_socket(raw_s, server_hostname=hostname) as tls_s:
                        ci          = tls_s.cipher()
                        tls_version = tls_s.version() or "Unknown"
                        cipher_name = ci[0] if ci else "Unknown"
                kex_short, kex_desc, kex_is_pqc_ssl = get_tls12_kex_from_cipher_name(cipher_name)
            except Exception:
                port_results.append({
                    "port": port, "has_tls": False,
                    "service_type": service_type, "tls": None, "pqc": None
                })
                continue

            # Merge: raw_result gives us the real KEX group (TLS 1.3 HRR/ServerHello)
            # For TLS 1.2 raw_result will have no key_group_name — that's expected,
            # because TLS 1.2 has no key_share extension. KEX is read from cipher name.
            if raw_result and raw_result.get("key_group_name"):
                kex_group  = raw_result["key_group_name"]
                kex_is_pqc = raw_result.get("key_group_pqc", False)
                if raw_result.get("tls_version"):
                    tls_version = raw_result["tls_version"]
                detection_method = "raw_serverhello + ssl"
            else:
                # TLS 1.2: KEX is accurately inferred from the cipher suite name
                # (RFC 5246 — cipher name encodes the KEX algorithm)
                # TLS 1.3 with failed raw parse: mark as unknown
                kex_group  = kex_short
                kex_is_pqc = kex_is_pqc_ssl
                if tls_version == "TLSv1.2" or tls_version.startswith("TLSv1."):
                    detection_method = f"cipher-name inference ({tls_version})"
                else:
                    detection_method = "ssl_fallback (KEX unknown)"

            preferred_cipher   = cipher_name
            all_ciphers        = [preferred_cipher]
            # Classify cipher correctly based on KEX inferred from name
            is_vuln = any(v in cipher_name.upper() for v in ["ECDHE", "DHE", "RSA", "ECDH"])
            vulnerable_ciphers = [preferred_cipher] if is_vuln and not kex_is_pqc else []
            pqc_ciphers        = [preferred_cipher] if kex_is_pqc else []
            ciphers_by_version = {tls_version: [preferred_cipher]}

        # ── Step 2: Deep certificate parsing ───────────────────────
        der_bytes, std_cert = get_raw_certificate_bytes(hostname, ip, port)
        cert_details        = parse_certificate_details(der_bytes, std_cert)

        # ── Step 3: PQC assessment ──────────────────────────────────
        pqc_result = assess_pqc_readiness(
            tls_version        = tls_version,
            kex_group_name     = kex_group,
            kex_is_pqc         = kex_is_pqc,
            cert_sig_algorithm = cert_details["sig_algorithm"],
            cert_sig_is_pqc    = cert_details["sig_is_pqc"],
        )

        port_results.append({
            "port":              port,
            "has_tls":           True,
            "service_type":      service_type,
            "tls": {
                "version":           tls_version,
                "preferred_cipher":  preferred_cipher,
                "all_ciphers":       all_ciphers,
                "vulnerable_ciphers":vulnerable_ciphers,
                "pqc_ciphers":       pqc_ciphers,
                "ciphers_by_version":ciphers_by_version,
                "key_exchange":      kex_group,
                "key_exchange_pqc":  kex_is_pqc,
                "detection_method":  detection_method,
            },
            "certificate":       cert_details,
            "pqc":               pqc_result,
        })

    return {"hostname": hostname, "ip": ip, "ports": port_results}


# =============================================================
#  CYCLONEDX 1.6 CBOM EXPORT
#
#  Gap addressed: output must be a standardised CBOM format.
#  CycloneDX 1.6 is the OWASP standard for cryptographic BOMs.
#  It represents each cryptographic asset as a "component" with
#  crypto-properties, and uses "dependencies" to link endpoints
#  to their cipher suites and certificates.
#
#  Schema reference: https://cyclonedx.org/specification/overview/
# =============================================================

def export_cyclonedx_cbom(domain, hosts, scan_time, elapsed):
    """
    Build a CycloneDX 1.6 CBOM JSON document.

    Structure:
      - metadata: scan info
      - components: one entry per endpoint, cipher suite, and certificate
      - dependencies: links endpoints to their crypto assets
      - vulnerabilities: quantum-unsafe findings
    """

    cbom = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": scan_time,
            "tools": [{
                "vendor":  "PQC CBOM Scanner",
                "name":    "PQC Discovery Module",
                "version": "2.0",
            }],
            "component": {
                "type":    "application",
                "name":    domain,
                "description": "Public-facing application under PQC assessment",
            }
        },
        "components":      [],
        "dependencies":    [],
        "vulnerabilities": [],
    }

    vuln_id_counter = 1

    for host in hosts:
        for port_info in host["ports"]:
            if not port_info["has_tls"]:
                continue

            tls      = port_info["tls"]
            cert     = port_info["certificate"]
            pqc      = port_info["pqc"]
            endpoint = f"{host['hostname']}:{port_info['port']}"
            comp_ref = f"endpoint-{host['hostname'].replace('.', '-')}-{port_info['port']}"

            # ── Endpoint component ──────────────────────────────
            endpoint_component = {
                "type":        "service",
                "bom-ref":     comp_ref,
                "name":        host["hostname"],
                "version":     tls["version"],
                "description": f"{port_info['service_type']} on port {port_info['port']}",
                "properties": [
                    {"name": "pqc:assessment",     "value": pqc["label"]},
                    {"name": "pqc:posture",         "value": pqc["posture"]},
                    {"name": "network:ip",          "value": host["ip"]},
                    {"name": "network:port",        "value": str(port_info["port"])},
                    {"name": "tls:version",         "value": tls["version"]},
                    {"name": "tls:keyExchange",     "value": tls["key_exchange"]},
                    {"name": "tls:kexPqcSafe",      "value": str(tls["key_exchange_pqc"])},
                    {"name": "tls:detectionMethod", "value": tls["detection_method"]},
                ],
                "cryptoProperties": {
                    "assetType":       "protocol",
                    "protocolProperties": {
                        "type":        "tls",
                        "version":     tls["version"],
                        "cipherSuites": tls["all_ciphers"],
                        "ikev2TransformTypes": [{
                            "transformType": "KEY_EXCHANGE",
                            "transformId":   tls["key_exchange"],
                        }],
                    }
                }
            }

            # Add the PQC certificate label if awarded
            if pqc.get("certificate_label"):
                endpoint_component["properties"].append({
                    "name":  "pqc:certificateLabel",
                    "value": pqc["certificate_label"]
                })

            cbom["components"].append(endpoint_component)

            dep_refs = []

            # ── Cipher suite components ─────────────────────────
            for cipher in tls["all_ciphers"]:
                cipher_ref = f"cipher-{comp_ref}-{cipher.lower().replace('_','-')}"
                dep_refs.append(cipher_ref)
                is_pqc = cipher in tls.get("pqc_ciphers", [])
                is_vuln = cipher in tls.get("vulnerable_ciphers", [])

                cbom["components"].append({
                    "type":    "cryptographic-asset",
                    "bom-ref": cipher_ref,
                    "name":    cipher,
                    "cryptoProperties": {
                        "assetType":      "algorithm",
                        "algorithmProperties": {
                            "primitive":    "ae",
                            "parameterSetIdentifier": cipher,
                            "executionEnvironment": "software",
                            "implementationPlatform": "unknown",
                            "certificationLevel":
                                ["FIPS140-3"] if is_pqc else [],
                            "mode": "cbc" if "CBC" in cipher else "gcm",
                            "padding": "none",
                            "cryptoFunctions": ["keygen", "encrypt", "decrypt"],
                            "classicalSecurityLevel": 256 if "256" in cipher else 128,
                            "nistQuantumSecurityLevel": 5 if is_pqc else 0,
                        }
                    },
                    "properties": [
                        {"name": "pqc:safe",        "value": str(is_pqc)},
                        {"name": "pqc:vulnerable",  "value": str(is_vuln)},
                    ]
                })

            # ── Certificate component ───────────────────────────
            cert_ref = f"cert-{comp_ref}"
            dep_refs.append(cert_ref)
            cbom["components"].append({
                "type":    "cryptographic-asset",
                "bom-ref": cert_ref,
                "name":    f"Certificate: {cert['subject']}",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName":      cert["subject"],
                        "issuerName":       cert["issuer"],
                        "notValidAfter":    cert["expiry"],
                        "serialNumber":     cert["serial"],
                        "signatureAlgorithmRef": cert["sig_algorithm"],
                        "subjectPublicKeyRef":   cert["key_type"],
                    }
                },
                "properties": [
                    {"name": "cert:signatureAlgorithm",    "value": cert["sig_algorithm"]},
                    {"name": "cert:signatureAlgorithmOid", "value": cert["sig_algorithm_oid"]},
                    {"name": "cert:keyType",               "value": str(cert["key_type"])},
                    {"name": "cert:keyBits",               "value": str(cert["key_bits"])},
                    {"name": "cert:pqcSignature",          "value": str(cert["sig_is_pqc"])},
                ]
            })

            # ── Dependencies ────────────────────────────────────
            cbom["dependencies"].append({
                "ref":      comp_ref,
                "dependsOn": dep_refs
            })

            # ── Vulnerabilities (quantum-unsafe findings) ────────
            if pqc["label"] != "FULLY QUANTUM SAFE":
                for rec in pqc["recommendations"]:
                    cbom["vulnerabilities"].append({
                        "id":          f"PQC-{vuln_id_counter:04d}",
                        "source": {
                            "name": "NIST PQC Assessment",
                            "url":  "https://csrc.nist.gov/projects/post-quantum-cryptography"
                        },
                        "ratings": [{
                            "severity": "critical" if pqc["label_class"] == "danger"
                                        else "medium",
                            "method":   "PQC-ASSESSMENT",
                        }],
                        "description": f"[{endpoint}] {pqc['label']}: {rec}",
                        "affects": [{"ref": comp_ref}],
                    })
                    vuln_id_counter += 1

    return cbom


# =============================================================
#  TERMINAL OUTPUT
# =============================================================

def print_host(host):
    """Print a clean readable summary of one host to the terminal."""
    print(f"\n  Host : {host['hostname']}")
    print(f"  IP   : {host['ip']}")
    print(f"  " + "-" * 56)

    for p in host["ports"]:
        port    = p["port"]
        service = p["service_type"]

        if not p["has_tls"]:
            print(f"  Port {port:5}  |  {service:22}  |  No TLS")
            continue

        tls  = p["tls"]
        cert = p["certificate"]
        pqc  = p["pqc"]

        if pqc["label_class"] == "safe":
            label_str = green(pqc["label"])
        elif pqc["label_class"] == "pqc-ready":
            label_str = cyan(pqc["label"])
        elif pqc["label_class"] == "warn":
            label_str = yellow(pqc["label"])
        else:
            label_str = red(pqc["label"])

        print(f"  Port {port:5}  |  {service:22}  |  {tls['version']:8}  |  {label_str}")
        print(f"         Preferred cipher  : {tls['preferred_cipher'] or 'Unknown'}")
        print(f"         Key exchange      : {tls['key_exchange']}  (PQC: {tls['key_exchange_pqc']})")
        print(f"         Detection method  : {tls['detection_method']}")
        print(f"         Cert signature    : {cert['sig_algorithm']}  (PQC: {cert['sig_is_pqc']})")
        print(f"         Cert issued to    : {cert['subject']}")
        print(f"         Cert issuer       : {cert['issuer']}")
        print(f"         Cert expires      : {cert['expiry']}")
        print(f"         All ciphers found : {len(tls['all_ciphers'])}  "
              f"(vulnerable: {len(tls['vulnerable_ciphers'])}  pqc: {len(tls['pqc_ciphers'])})")

        if pqc.get("certificate_label"):
            print(green(f"         ★ LABEL AWARDED  : {pqc['certificate_label']}"))

        if pqc["label_class"] != "safe":
            print(f"         Actions needed   :")
            for i, rec in enumerate(pqc["recommendations"][:2], 1):
                print(f"           {i}. {rec}")

    print(f"  " + "-" * 56)


# =============================================================
#  HTML REPORT
# =============================================================

def build_html_report(domain, hosts, elapsed, scan_time):
    """Generate the HTML presentation report."""

    # Summary counts
    total_tls   = sum(1 for h in hosts for p in h["ports"] if p["has_tls"])
    fully_safe  = sum(1 for h in hosts for p in h["ports"]
                      if p.get("pqc") and p["pqc"]["label_class"] == "safe")
    pqc_ready   = sum(1 for h in hosts for p in h["ports"]
                      if p.get("pqc") and p["pqc"]["label_class"] == "pqc-ready")
    pqc_not_rdy = sum(1 for h in hosts for p in h["ports"]
                      if p.get("pqc") and p["pqc"]["label_class"] == "warn")
    not_safe    = sum(1 for h in hosts for p in h["ports"]
                      if p.get("pqc") and p["pqc"]["label_class"] == "danger")
    awarded     = sum(1 for h in hosts for p in h["ports"]
                      if p.get("pqc") and p["pqc"].get("certificate_label"))

    # Build host cards
    host_cards = ""
    for host in hosts:
        host_cards += _build_host_card(host)

    hndl_banner = ""
    if not_safe > 0 or pqc_not_rdy > 0:
        hndl_banner = """
        <div class="hndl-banner">
            <strong>&#9888; HNDL Risk Detected</strong> &mdash; One or more assets are vulnerable to
            <strong>Harvest Now, Decrypt Later</strong> attacks. Adversaries may record
            encrypted traffic today and decrypt it once quantum computers become available.<br><br>
            <span class="nist-ref">
                Migration path: &nbsp;
                NIST FIPS 203 (ML-KEM) &nbsp;&#183;&nbsp;
                NIST FIPS 204 (ML-DSA) &nbsp;&#183;&nbsp;
                NIST FIPS 205 (SLH-DSA)
            </span>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQC CBOM Report &mdash; {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg:#0a0e1a; --surface:#111827; --surface2:#1a2236; --border:#1e2d45;
            --safe:#00d4aa; --safe-dim:rgba(0,212,170,.10); --safe-b:rgba(0,212,170,.25);
            --pqcr:#4da6ff; --pqcr-dim:rgba(77,166,255,.10); --pqcr-b:rgba(77,166,255,.25);
            --warn:#f5a623; --warn-dim:rgba(245,166,35,.10); --warn-b:rgba(245,166,35,.25);
            --danger:#ff4d6d; --danger-dim:rgba(255,77,109,.10); --danger-b:rgba(255,77,109,.25);
            --text:#e2e8f0; --muted:#94a3b8; --dim:#64748b; --accent:#3b82f6;
        }}
        *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
        body{{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;font-size:14px;line-height:1.6}}
        .topbar{{background:var(--surface);border-bottom:1px solid var(--border);padding:0 32px;height:54px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}}
        .topbar-title{{font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;letter-spacing:.06em;color:var(--accent);display:flex;align-items:center;gap:10px}}
        .dot{{width:8px;height:8px;border-radius:50%;background:var(--safe);animation:pulse 2.5s ease-in-out infinite}}
        @keyframes pulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:.4;transform:scale(1.5)}}}}
        .topbar-meta{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted)}}
        .container{{max-width:1120px;margin:0 auto;padding:36px 24px}}
        .page-header{{margin-bottom:32px}}
        .page-header h1{{font-size:26px;font-weight:600;letter-spacing:-.02em;margin-bottom:6px}}
        .page-header h1 .dn{{color:var(--accent)}}
        .subtitle{{font-size:13px;color:var(--muted)}}
        .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:32px}}
        .stat{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 18px}}
        .stat-n{{font-family:'IBM Plex Mono',monospace;font-size:30px;font-weight:600;line-height:1.1;margin-bottom:4px}}
        .stat-l{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
        .stat.safe .stat-n{{color:var(--safe)}} .stat.pqcr .stat-n{{color:var(--pqcr)}}
        .stat.warn .stat-n{{color:var(--warn)}} .stat.danger .stat-n{{color:var(--danger)}}
        .stat.accent .stat-n{{color:var(--accent)}}
        .hndl-banner{{background:var(--danger-dim);border:1px solid var(--danger-b);border-radius:8px;padding:16px 20px;margin-bottom:28px;font-size:13px;color:var(--muted);line-height:1.8}}
        .hndl-banner strong{{color:var(--danger)}}
        .nist-ref{{display:inline-block;margin-top:6px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--accent)}}
        .legend{{display:flex;flex-wrap:wrap;gap:16px;padding:14px 20px;background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:28px;font-size:12px;color:var(--muted)}}
        .li{{display:flex;align-items:center;gap:8px}}
        .ld{{width:10px;height:10px;border-radius:2px;flex-shrink:0}}
        .ld.safe{{background:var(--safe)}} .ld.pqcr{{background:var(--pqcr)}}
        .ld.warn{{background:var(--warn)}} .ld.danger{{background:var(--danger)}}
        .sh{{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.10em;color:var(--dim);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border)}}
        .host-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:16px;overflow:hidden}}
        .host-card.hd{{border-left:3px solid var(--danger)}}
        .host-card.hw{{border-left:3px solid var(--warn)}}
        .host-card.hs{{border-left:3px solid var(--safe)}}
        .host-card.hp{{border-left:3px solid var(--pqcr)}}
        .hh{{display:flex;justify-content:space-between;align-items:center;padding:12px 18px;background:var(--surface2)}}
        .hn{{font-family:'IBM Plex Mono',monospace;font-size:14px;font-weight:600}}
        .hi{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted)}}
        .hpc{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:3px 10px}}
        .pc{{padding:12px 18px 16px;display:flex;flex-direction:column;gap:10px}}
        .pe{{border-radius:6px;border:1px solid var(--border);overflow:hidden}}
        .pe.safe{{background:var(--safe-dim);border-color:var(--safe-b)}}
        .pe.pqc-ready{{background:var(--pqcr-dim);border-color:var(--pqcr-b)}}
        .pe.warn{{background:var(--warn-dim);border-color:var(--warn-b)}}
        .pe.danger{{background:var(--danger-dim);border-color:var(--danger-b)}}
        .pe.no-tls{{background:var(--surface2);border-color:var(--border)}}
        .ptr{{display:flex;align-items:center;gap:10px;padding:10px 14px;flex-wrap:wrap}}
        .pn{{font-family:'IBM Plex Mono',monospace;font-size:15px;font-weight:600;min-width:58px}}
        .stt{{font-size:11px;font-weight:500;background:rgba(255,255,255,.06);border:1px solid var(--border);padding:2px 8px;border-radius:3px;color:var(--muted)}}
        .tv{{font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;background:var(--surface2);border:1px solid var(--border);padding:2px 8px;border-radius:3px}}
        .badge{{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;padding:3px 10px;border-radius:3px;white-space:nowrap;margin-left:auto}}
        .badge.safe{{color:var(--safe);background:var(--safe-dim);border:1px solid var(--safe-b)}}
        .badge.pqc-ready{{color:var(--pqcr);background:var(--pqcr-dim);border:1px solid var(--pqcr-b)}}
        .badge.warn{{color:var(--warn);background:var(--warn-dim);border:1px solid var(--warn-b)}}
        .badge.danger{{color:var(--danger);background:var(--danger-dim);border:1px solid var(--danger-b)}}
        .badge.no-tls{{color:var(--dim);background:rgba(100,116,139,.1);border:1px solid var(--border)}}
        .cd{{display:grid;grid-template-columns:1fr 1fr;gap:6px 24px;padding:6px 14px 10px;font-size:12px}}
        .cr{{display:flex;flex-direction:column;gap:1px}}
        .cl{{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim)}}
        .cv{{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--text);word-break:break-all}}
        .cv.safe{{color:var(--safe)}} .cv.warn{{color:var(--warn)}} .cv.danger{{color:var(--danger)}}
        .award{{margin:0 14px 10px;padding:8px 14px;background:var(--safe-dim);border:1px solid var(--safe-b);border-radius:5px;font-size:12px;font-weight:600;color:var(--safe)}}
        .recs{{margin:0 14px 12px;padding:10px 14px;background:rgba(0,0,0,.2);border-left:2px solid var(--warn);border-radius:0 5px 5px 0}}
        .recs.danger{{border-left-color:var(--danger)}}
        .rt{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--warn);margin-bottom:6px}}
        .rt.danger{{color:var(--danger)}}
        .rl{{list-style:none;display:flex;flex-direction:column;gap:4px}}
        .rl li{{font-size:12px;color:var(--muted);padding-left:16px;position:relative}}
        .rl li::before{{content:'&#8594;';position:absolute;left:0;color:var(--warn)}}
        .rl.danger li::before{{color:var(--danger)}}
        .cipher-pills{{display:flex;flex-wrap:wrap;gap:4px;margin:0 14px 10px}}
        .cp{{font-family:'IBM Plex Mono',monospace;font-size:10px;padding:2px 6px;border-radius:3px;border:1px solid}}
        .cp.safe{{background:var(--safe-dim);border-color:var(--safe-b);color:var(--safe)}}
        .cp.danger{{background:var(--danger-dim);border-color:var(--danger-b);color:var(--danger)}}
        .cp.neutral{{background:rgba(255,255,255,.04);border-color:var(--border);color:var(--muted)}}
        .footer{{margin-top:48px;padding-top:18px;border-top:1px solid var(--border);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--dim)}}
        @media(max-width:680px){{.cd{{grid-template-columns:1fr}}.stats{{grid-template-columns:repeat(2,1fr)}}.ptr{{flex-direction:column;align-items:flex-start}}.badge{{margin-left:0}}}}
    </style>
</head>
<body>
<div class="topbar">
    <div class="topbar-title"><div class="dot"></div>PQC CBOM Scanner &mdash; Cryptographic Bill of Materials</div>
    <div class="topbar-meta">Generated: {scan_time} &nbsp;|&nbsp; Duration: {elapsed}s</div>
</div>
<div class="container">
    <div class="page-header">
        <h1>Cryptographic Inventory &mdash; <span class="dn">{domain}</span></h1>
        <div class="subtitle">Quantum-Ready Assessment &nbsp;&#183;&nbsp; CycloneDX 1.6 CBOM &nbsp;&#183;&nbsp; NIST FIPS 203/204/205</div>
    </div>
    <div class="stats">
        <div class="stat accent"><div class="stat-n">{len(hosts)}</div><div class="stat-l">Live Hosts</div></div>
        <div class="stat accent"><div class="stat-n">{total_tls}</div><div class="stat-l">TLS Endpoints</div></div>
        <div class="stat safe"><div class="stat-n">{fully_safe}</div><div class="stat-l">Fully Quantum Safe</div></div>
        <div class="stat pqcr"><div class="stat-n">{pqc_ready}</div><div class="stat-l">PQC Ready</div></div>
        <div class="stat warn"><div class="stat-n">{pqc_not_rdy}</div><div class="stat-l">PQC Not Ready</div></div>
        <div class="stat danger"><div class="stat-n">{not_safe}</div><div class="stat-l">Not Quantum Safe</div></div>
        <div class="stat safe"><div class="stat-n">{awarded}</div><div class="stat-l">Labels Awarded</div></div>
    </div>
    {hndl_banner}
    <div class="legend">
        <div class="li"><div class="ld safe"></div>Fully Quantum Safe — TLS 1.3 + PQC KEX + PQC Certificate</div>
        <div class="li"><div class="ld pqcr"></div>PQC Ready — TLS 1.3 + PQC KEX, classical certificate</div>
        <div class="li"><div class="ld warn"></div>PQC Not Ready — TLS 1.3, classical key exchange</div>
        <div class="li"><div class="ld danger"></div>Not Quantum Safe — TLS 1.2 or below</div>
    </div>
    <div class="sh">Cryptographic Inventory &mdash; All Discovered Endpoints</div>
    {host_cards if host_cards else '<p style="color:var(--dim);padding:20px 0">No responsive hosts found.</p>'}
    <div class="footer">
        <span>PQC CBOM Scanner v2.0 &nbsp;&#183;&nbsp; CycloneDX 1.6 &nbsp;&#183;&nbsp; NIST FIPS 203/204/205</span>
        <span>Target: {domain} &nbsp;&#183;&nbsp; {scan_time}</span>
    </div>
</div>
</body>
</html>"""


def _build_host_card(host):
    has_danger = any(p.get("pqc") and p["pqc"]["label_class"] == "danger" for p in host["ports"])
    has_warn   = any(p.get("pqc") and p["pqc"]["label_class"] == "warn"   for p in host["ports"])
    has_pqcr   = any(p.get("pqc") and p["pqc"]["label_class"] == "pqc-ready" for p in host["ports"])
    hcls = "hd" if has_danger else "hw" if has_warn else "hp" if has_pqcr else "hs"

    tls_count   = sum(1 for p in host["ports"] if p["has_tls"])
    port_html   = "".join(_build_port_entry(host["hostname"], p) for p in host["ports"])

    return f"""
    <div class="host-card {hcls}">
        <div class="hh">
            <div><div class="hn">{host['hostname']}</div><div class="hi">{host['ip']}</div></div>
            <span class="hpc">{len(host['ports'])} port{'s' if len(host['ports'])!=1 else ''} &nbsp;&#183;&nbsp; {tls_count} TLS</span>
        </div>
        <div class="pc">{port_html}</div>
    </div>"""


def _build_port_entry(hostname, port_info):
    port    = port_info["port"]
    service = port_info["service_type"]

    if not port_info["has_tls"]:
        return f"""<div class="pe no-tls"><div class="ptr">
            <span class="pn">:{port}</span>
            <span class="stt">{service}</span>
            <span class="badge no-tls">No TLS</span></div></div>"""

    tls  = port_info["tls"]
    cert = port_info["certificate"]
    pqc  = port_info["pqc"]
    cls  = pqc["label_class"]

    # Cipher pills
    pills = ""
    for c in tls["all_ciphers"]:
        pcls = "safe" if c in tls["pqc_ciphers"] else "danger" if c in tls["vulnerable_ciphers"] else "neutral"
        pills += f'<span class="cp {pcls}">{c}</span>'

    # Award
    award_html = ""
    if pqc.get("certificate_label"):
        award_html = f'<div class="award">&#10003; &nbsp; <strong>{pqc["certificate_label"]}</strong> &nbsp;&#183;&nbsp; NIST FIPS 203/204/205</div>'

    # Recommendations
    recs_html = ""
    if cls not in ("safe",):
        bc = "danger" if cls == "danger" else ""
        items = "".join(f"<li>{r}</li>" for r in pqc["recommendations"])
        recs_html = f'<div class="recs {bc}"><div class="rt {bc}">Recommended Actions</div><ul class="rl {bc}">{items}</ul></div>'

    # SAN display
    san = ", ".join(cert["san_domains"][:4])
    if len(cert["san_domains"]) > 4:
        san += f" +{len(cert['san_domains'])-4} more"

    kex_cls = "safe" if tls["key_exchange_pqc"] else "danger"
    sig_cls = "safe" if cert["sig_is_pqc"] else "danger"

    return f"""
    <div class="pe {cls}">
        <div class="ptr">
            <span class="pn">:{port}</span>
            <span class="stt">{service}</span>
            <span class="tv">{tls['version']}</span>
            <span class="badge {cls}">{pqc['label']}</span>
        </div>
        <div class="cd">
            <div class="cr"><span class="cl">Preferred Cipher</span><span class="cv">{tls['preferred_cipher'] or 'Unknown'}</span></div>
            <div class="cr"><span class="cl">Key Exchange</span><span class="cv {kex_cls}">{tls['key_exchange']}</span></div>
            <div class="cr"><span class="cl">Cert Subject</span><span class="cv">{cert['subject']}</span></div>
            <div class="cr"><span class="cl">Cert Issuer</span><span class="cv">{cert['issuer']}</span></div>
            <div class="cr"><span class="cl">Cert Expiry</span><span class="cv">{cert['expiry']}</span></div>
            <div class="cr"><span class="cl">Cert Signature Algorithm</span><span class="cv {sig_cls}">{cert['sig_algorithm']}</span></div>
            <div class="cr"><span class="cl">Public Key</span><span class="cv">{cert['key_type']} {cert['key_bits']} bit</span></div>
            <div class="cr"><span class="cl">Detection Method</span><span class="cv">{tls['detection_method']}</span></div>
            <div class="cr" style="grid-column:1/-1"><span class="cl">SAN Domains</span><span class="cv">{san or 'None'}</span></div>
        </div>
        {f'<div style="padding:2px 14px 8px;font-size:11px;color:var(--muted)">All cipher suites ({len(tls["all_ciphers"])}):</div><div class="cipher-pills">{pills}</div>' if tls["all_ciphers"] else ''}
        {award_html}
        {recs_html}
    </div>"""


# =============================================================
#  MAIN
# =============================================================

def _debug_kex(host, port=443):
    """Quick test of PQC detection via HRR dance. Run: python discovery.py --debug-kex google.com"""
    print(f"\n  [debug-kex] Target: {host}:{port}")
    ip = socket.gethostbyname(host)
    print(f"  [debug-kex] Resolved: {ip}")
    print(f"  [debug-kex] Strategy: send X25519-only ClientHello + PQC in supported_groups")
    print(f"  [debug-kex] Expected: server sends HRR (if PQC) or ServerHello (if classical)")

    hello = build_client_hello_x25519_only(host)
    print(f"  [debug-kex] ClientHello size: {len(hello)} bytes")

    sock = socket.create_connection((ip, port), timeout=8)
    sock.sendall(hello)
    raw = read_tls_records(sock, timeout=8)
    sock.close()
    print(f"  [debug-kex] Server responded: {len(raw)} bytes")
    print(f"  [debug-kex] First bytes (hex): {raw[:16].hex()}")

    if not raw:
        print(red("  [debug-kex] No response")); return
    if raw[0] == 0x15:
        alert = raw[6] if len(raw) > 6 else 0
        print(red(f"  [debug-kex] TLS Alert received (code {alert}) — server rejected hello"))
        return

    parsed = parse_server_response(raw)
    if not parsed:
        print(red(f"  [debug-kex] Could not parse response. Raw: {raw[:40].hex()}"))
        return

    is_hrr = parsed.get("is_hrr", False)
    grp_id = parsed.get("key_group_id")
    grp_nm = parsed.get("key_group_name", "?")
    is_pqc = parsed.get("key_group_pqc", False)
    tlsver = parsed.get("tls_version", "?")

    print()
    if is_hrr:
        print(green(f"  [debug-kex] ✓ Got HelloRetryRequest — server supports PQC!"))
        print(green(f"  [debug-kex]   Server wants group: 0x{grp_id:04X} = {grp_nm}"))
        print(green(f"  [debug-kex]   PQC: {is_pqc}  TLS: {tlsver}"))
    else:
        print(yellow(f"  [debug-kex] Got ServerHello (no HRR) — server chose X25519"))
        print(yellow(f"  [debug-kex]   Group: 0x{grp_id:04X if grp_id else 0:04X} = {grp_nm}"))
        print(yellow(f"  [debug-kex]   PQC: {is_pqc}  TLS: {tlsver}"))
        print(yellow(f"  [debug-kex]   This server does not support PQC key exchange"))


def main():
    parser = argparse.ArgumentParser(
        description="PQC CBOM Scanner — Quantum-Ready Cybersecurity Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 discovery.py -d example.com
  python3 discovery.py -d example.com --ports web --output report
  python3 discovery.py -d example.com --threads 200

Install:
  pip install requests colorama sslyze cryptography
        """
    )
    parser.add_argument("-d", "--domain",  required=False, default=None)
    parser.add_argument("--ports", choices=["web","top"], default="top",
                        help="web=8 HTTP/S ports | top=20 common ports (default)")
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--output",  default=None)
    parser.add_argument("--debug-kex", metavar="HOST",
                        help="Quick test: send PQC ClientHello to HOST:443 and print "
                             "the negotiated key exchange group. Use this to verify "
                             "PQC detection works before a full scan. "
                             "Example: --debug-kex google.com")
    args = parser.parse_args()

    # ── Quick KEX debug mode ──────────────────────────────────────────
    if args.debug_kex:
        _debug_kex(args.debug_kex)
        return

    if not args.domain:
        parser.error("argument -d/--domain is required (unless using --debug-kex)")

    domain    = re.sub(r"^https?://", "", args.domain).strip("/").lower()
    port_list = WEB_PORTS if args.ports == "web" else TOP_PORTS

    # ── Dependency check — diagnose exactly what is missing and why ──
    if not SSLYZE_AVAILABLE:
        print()
        print(red("  ╔══════════════════════════════════════════════════════════╗"))
        print(red("  ║  sslyze NOT AVAILABLE — running in fallback mode         ║"))
        print(red("  ╚══════════════════════════════════════════════════════════╝"))
        if SSLYZE_IMPORT_ERROR:
            print(yellow(f"  Import error: {SSLYZE_IMPORT_ERROR}"))
        print()

        # Detect the most common Windows issue: wrong Python / pip mismatch
        python_exe  = sys.executable
        python_ver  = sys.version.split()[0]
        print(yellow(f"  You are running: {python_exe}"))
        print(yellow(f"  Python version : {python_ver}"))
        print()
        print(yellow("  The most common cause on Windows is that pip installed"))
        print(yellow("  sslyze for a DIFFERENT Python than the one running this script."))
        print()
        print(yellow("  Fix — run these two commands with the SAME Python:"))
        print(cyan( f'      {python_exe} -m pip install sslyze cryptography requests colorama'))
        print(cyan( f'      {python_exe} discovery.py -d <target>'))
        print()
        print(yellow("  Then re-run and sslyze should show: available"))
        print()

    if not CRYPTOGRAPHY_AVAILABLE:
        print(yellow("  [!] cryptography not available — cert signature algorithm detection limited"))
        print(cyan(f'      {sys.executable} -m pip install cryptography'))
        print()

    print("=" * 60)
    print("  PQC CBOM SCANNER  —  Quantum-Ready Cybersecurity Tool")
    print("  CycloneDX 1.6 | NIST FIPS 203 / 204 / 205")
    print("=" * 60)
    print(f"  Target  : {domain}")
    print(f"  Ports   : {args.ports}  ({len(port_list)} ports)")
    print(f"  Threads : {args.threads}")
    if SSLYZE_AVAILABLE:
        print(green("  sslyze  : available (full cipher enumeration)"))
    else:
        print(red(  "  sslyze  : NOT available — fallback mode (see instructions above)"))
    print(f"  crypto  : {'available' if CRYPTOGRAPHY_AVAILABLE else 'not installed (limited cert parsing)'}")
    print("=" * 60)

    scan_time  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    timer_start = time.time()

    # Step 1: subdomains
    subs      = discover_subdomains(domain, threads=args.threads)
    all_hosts = [domain] + subs

    print(f"\n  Scanning {len(all_hosts)} hosts ...\n  {'='*56}")

    # Step 2: parallel host scan
    scanned = []
    done    = 0
    total   = len(all_hosts)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_single_host, h, port_list): h for h in all_hosts}
        for f in concurrent.futures.as_completed(futures):
            done += 1
            result = f.result()
            if result:
                scanned.append(result)
                print_host(result)
            sys.stdout.write(f"\r  Progress: {done}/{total}")
            sys.stdout.flush()

    print(f"\r  Progress: {total}/{total}  done\n")
    elapsed = round(time.time() - timer_start, 1)

    # Step 3: summary
    fully_safe  = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"]=="safe")
    pqc_ready   = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"]=="pqc-ready")
    pqc_not_rdy = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"]=="warn")
    not_safe    = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"]=="danger")
    awarded     = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"].get("certificate_label"))

    print("=" * 60)
    print(f"  SCAN COMPLETE  ({elapsed}s)")
    print("=" * 60)
    print(f"  Hosts scanned        : {total}")
    print(f"  Hosts responsive     : {len(scanned)}")
    print(green( f"  Fully Quantum Safe   : {fully_safe} endpoints"))
    print(cyan(  f"  PQC Ready            : {pqc_ready} endpoints"))
    print(yellow(f"  PQC Not Ready        : {pqc_not_rdy} endpoints"))
    print(red(   f"  Not Quantum Safe     : {not_safe} endpoints"))
    print(green( f"  Labels Awarded       : {awarded}"))
    print("=" * 60)

    base = args.output or f"pqc_cbom_{domain}_{int(time.time())}"

    # Save HTML report
    html_file = base + ".html"
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(build_html_report(domain, scanned, elapsed, scan_time))
    print(green(f"\n  HTML Report  →  {html_file}"))

    # Save CycloneDX 1.6 CBOM JSON
    cbom      = export_cyclonedx_cbom(domain, scanned, scan_time, elapsed)
    cbom_file = base + ".cdx.json"
    with open(cbom_file, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2)
    print(green(f"  CBOM (CycloneDX)  →  {cbom_file}"))
    print()


if __name__ == "__main__":
    main()
