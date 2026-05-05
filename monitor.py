#!/usr/bin/env python3
"""
Vietnamese Domain Typosquatting & Fake Marketing Site Monitor
=============================================================
Proactively scans for typosquatted / fake-brand domains targeting
major Vietnamese corporations and appends findings to blacklist.txt.

Dependencies:
    pip install dnspython dnstwist tldextract requests
"""

import socket
import itertools
import datetime
import logging
import os
import sys
import json
from pathlib import Path
from typing import Optional
import concurrent.futures

# Add near the top of monitor.py
MAX_CANDIDATES_PER_BRAND = 500   # hard cap per brand
DNS_WORKERS = 20                  # concurrent DNS threads
DNS_TIMEOUT = 2.0                 # seconds per lookup (was 3.0)

def check_domain(domain: str, whitelist: set, blacklist: set):
    """Worker function for thread pool."""
    base = extract_base(domain)
    if base in whitelist or domain.lower() in whitelist:
        return None
    if base in blacklist or domain.lower() in blacklist:
        return None
    ip = resolve_a_record(domain, timeout=DNS_TIMEOUT)
    return domain.lower() if ip else None

def scan_brand(brand, whitelist, existing_blacklist):
    logger.info("Scanning brand: %s", brand.upper())

    candidates = build_full_domain_list(brand)

    # Hard cap to avoid timeout
    if len(candidates) > MAX_CANDIDATES_PER_BRAND:
        logger.warning("  Capping %d candidates to %d", len(candidates), MAX_CANDIDATES_PER_BRAND)
        candidates = candidates[:MAX_CANDIDATES_PER_BRAND]

    logger.info("  Checking %d domain candidates (threaded)", len(candidates))

    new_finds = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
        futures = {
            executor.submit(check_domain, d, whitelist, existing_blacklist): d
            for d in candidates
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                logger.warning("  [HIT] %s", result)
                new_finds.append(result)

    # dnstwist pass (keep but limit TLDs)
    for tld in [".vn", ".com"]:   # reduced from 3 TLDs to 2
        dnstwist_hits = run_dnstwist(brand, tld)
        for domain in dnstwist_hits:
            base = extract_base(domain)
            if base not in whitelist and base not in existing_blacklist \
                    and domain not in new_finds:
                new_finds.append(domain.lower())

    logger.info("  Brand %s: %d new domain(s) found.", brand, len(new_finds))
    return new_finds
# ---------------------------------------------------------------------------
# Optional / graceful imports
# ---------------------------------------------------------------------------
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logging.warning("dnspython not installed – falling back to socket for DNS checks.")

try:
    import dnstwist
    HAS_DNSTWIST = True
except ImportError:
    HAS_DNSTWIST = False
    logging.warning("dnstwist not installed – homoglyph/punycode permutations disabled.")

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False
    logging.warning("tldextract not installed – basic TLD splitting used.")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("monitor.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ── DATA STRUCTURES ──────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

# Official / whitelisted domains (never flagged)
OFFICIAL_WHITELIST: list[str] = [
    # Viettel
    "viettel.vn", "viettelstore.vn", "viettel.com.vn",
    # FPT
    "fpt.com.vn", "fptshop.com.vn", "fpttelecom.com.vn", "fpt.vn",
    # Vingroup family
    "vingroup.net", "vinfast.vn", "vinhomes.vn", "vincom.com.vn",
    "vinmec.com", "vinschool.edu.vn",
    # Mobile World / Dien May Xanh
    "thegioididong.com", "dienmayxanh.com", "bachhoaxanh.com",
    # Banking
    "vietcombank.com.vn", "techcombank.com.vn", "vpbank.com.vn",
    "acb.com.vn", "mbbank.com.vn",
    # Logistics
    "ghn.vn", "ghtk.vn",
    # Others
    "vinamilk.com.vn", "masan.com.vn", "masanconsumer.com",
    "tiki.vn", "sendo.vn", "lazada.vn",
    "vnpt.vn", "vinaphone.com.vn",
]

# Brand keywords to monitor
TARGET_BRANDS: list[str] = [
    "viettel", "fpt", "vinfast", "vinhomes", "vingroup",
    "thegioididong", "dienmayxanh", "vinamilk", "masan",
    "vietcombank", "techcombank", "vpbank", "acb",
    "ghn", "ghtk", "vnpt", "vinaphone",
]

# Vietnamese SEO / scam keyword suffixes
VN_SEO_KEYWORDS: list[str] = [
    "khuyenmai", "uudai", "tongdai", "lapmang", "goicuoc",
    "tuyendung", "mienphi", "vayvon", "chinhhang", "giare",
    "san-sale", "sale", "hanoi", "hcm", "shopee", "lazada",
    "online", "store", "vip", "official", "dangky",
    "dichvu", "hotline", "lienhe", "sim", "goicom",
    "internet", "fiber", "4g", "5g", "tgdd",
]

# TLDs to probe (Vietnamese-focused + generic abuse TLDs)
TARGET_TLDS: list[str] = [
    ".vn", ".com.vn", ".net.vn", ".org.vn",
    ".com", ".net", ".site", ".xyz", ".top",
    ".info", ".store", ".vip", ".online", ".ink",
]

# Homoglyph substitution table (Latin look-alikes + Vietnamese-adjacent tricks)
HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["à", "á", "â", "ã", "4", "@"],
    "e": ["è", "é", "ê", "3"],
    "i": ["l", "1", "í", "ì"],
    "o": ["0", "ó", "ò", "ô", "ơ"],
    "u": ["ú", "ù", "ư"],
    "v": ["w", "ν"],   # Greek nu looks like v in some fonts
    "t": ["7"],
    "g": ["9", "q"],
    "c": ["k"],
    "s": ["5"],
    "b": ["6"],
}

# ---------------------------------------------------------------------------
# ── FILE PATHS ───────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).parent
WHITELIST_FILE = BASE_DIR / "whitelist.txt"
BLACKLIST_FILE = BASE_DIR / "blacklist.txt"

# ---------------------------------------------------------------------------
# ── UTILITY HELPERS ──────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def load_file_set(path: Path) -> set[str]:
    """Load a text file into a set of lowercased, stripped lines."""
    if not path.exists():
        return set()
    lines = path.read_text(encoding="utf-8").splitlines()
    return {ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")}


def append_to_blacklist(domains: list[str]) -> None:
    """Append new domains to blacklist.txt with an ISO timestamp."""
    if not domains:
        return
    timestamp = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with BLACKLIST_FILE.open("a", encoding="utf-8") as fh:
        fh.write(f"\n# --- Scan: {timestamp} ---\n")
        for d in sorted(domains):
            fh.write(f"{d}\n")
    logger.info("Appended %d domain(s) to %s", len(domains), BLACKLIST_FILE)


def extract_base(domain: str) -> str:
    """Return the registrable part of a domain (e.g. foo.com.vn -> foo.com.vn)."""
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    return domain.lower()

# ---------------------------------------------------------------------------
# ── DNS RESOLUTION ───────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def resolve_a_record(domain: str, timeout: float = 3.0) -> Optional[str]:
    """
    Return the first A-record IP for *domain*, or None if unresolvable.
    Uses dnspython when available, else falls back to socket.getaddrinfo.
    """
    domain = domain.strip().lower().rstrip(".")

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        try:
            answers = resolver.resolve(domain, "A")
            return str(answers[0])
        except Exception:
            return None
    else:
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET,
                                       proto=socket.IPPROTO_TCP)
            return infos[0][4][0] if infos else None
        except Exception:
            return None

# ---------------------------------------------------------------------------
# ── PERMUTATION ENGINE ───────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def generate_keyword_permutations(brand: str) -> list[str]:
    """
    Generate domain *names* (without TLD) by combining brand + SEO keywords.

    Patterns:
        brand-keyword      (e.g. viettel-khuyenmai)
        brandkeyword       (e.g. viettelkhuyenmai)
        keyword-brand      (e.g. khuyenmai-viettel)
        keywordbrand       (e.g. khuyenmaiviettel)
    """
    results: list[str] = []
    for kw in VN_SEO_KEYWORDS:
        results.extend([
            f"{brand}-{kw}",
            f"{brand}{kw}",
            f"{kw}-{brand}",
            f"{kw}{brand}",
        ])
    return results


def generate_homoglyph_permutations(brand: str, max_swaps: int = 1) -> list[str]:
    """
    Generate candidate domain names by substituting characters with homoglyphs.

    *max_swaps* limits the number of simultaneous substitutions to avoid
    an exponential explosion (default=1 → one substitution at a time).
    """
    results: set[str] = set()
    chars = list(brand)

    # Collect positions that have homoglyphs
    swap_positions = [i for i, ch in enumerate(chars) if ch in HOMOGLYPHS]

    for num_swaps in range(1, max_swaps + 1):
        for positions in itertools.combinations(swap_positions, num_swaps):
            # Cartesian product of substitutions at each chosen position
            glyph_choices = [HOMOGLYPHS[chars[p]] for p in positions]
            for combo in itertools.product(*glyph_choices):
                mutated = chars[:]
                for p, g in zip(positions, combo):
                    mutated[p] = g
                candidate = "".join(mutated)
                if candidate != brand:
                    results.add(candidate)

    return list(results)


def generate_typo_permutations(brand: str) -> list[str]:
    """
    Classic typosquatting patterns:
        - Character deletion (viettl)
        - Character doubling (vieettel)
        - Adjacent-key swaps (viettel → viertel)
        - Missing hyphen / extra hyphen
        - Common prefix/suffix insertions (my-, get-, use-, -vn, -net)
    """
    results: set[str] = set()
    n = len(brand)

    # Deletion
    for i in range(n):
        results.add(brand[:i] + brand[i+1:])

    # Doubling
    for i in range(n):
        results.add(brand[:i] + brand[i] * 2 + brand[i+1:])

    # Swap adjacent
    for i in range(n - 1):
        lst = list(brand)
        lst[i], lst[i+1] = lst[i+1], lst[i]
        results.add("".join(lst))

    # Prefix / suffix padding
    for pad in ["my", "get", "use", "e", "i", "dang-ky", "chinh-hang"]:
        results.add(f"{pad}-{brand}")
        results.add(f"{brand}-{pad}")

    results.discard(brand)
    return list(results)


def build_full_domain_list(brand: str) -> list[str]:
    """
    Combine all permutation methods for *brand* and expand across all TLDs.
    Returns a flat list of fully-qualified domain strings.
    """
    names: set[str] = set()

    names.update(generate_keyword_permutations(brand))
    names.update(generate_homoglyph_permutations(brand, max_swaps=1))
    names.update(generate_typo_permutations(brand))

    # Add Vietnamese subdomain-style patterns (hanoi.brand-kw.vn)
    for kw in ["hanoi", "hcm", "hue", "danang"]:
        names.add(f"{kw}.{brand}-khuyenmai")
        names.add(f"{kw}.{brand}-uudai")

    full_domains: list[str] = []
    for name in names:
        for tld in TARGET_TLDS:
            full_domains.append(f"{name}{tld}")

    return full_domains

# ---------------------------------------------------------------------------
# ── DNSTWIST INTEGRATION ─────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def run_dnstwist(brand: str, tld: str = ".vn") -> list[str]:
    """
    Use dnstwist to generate advanced homoglyph / IDN / punycode permutations.

    dnstwist handles Unicode confusables such as:
        vıettel.vn  (ı = U+0131 LATIN SMALL LETTER DOTLESS I)
        vіettel.vn  (і = U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I)

    Returns a list of domain strings that have *registered* DNS records.
    """
    if not HAS_DNSTWIST:
        logger.debug("dnstwist unavailable – skipping IDN checks for %s", brand)
        return []

    seed = f"{brand}{tld}"
    logger.info("  [dnstwist] Scanning permutations for %s …", seed)

    try:
        # dnstwist ≥ 20230901 exposes a Python API
        results = dnstwist.run(
            domain=seed,
            registered=True,       # only return domains with DNS records
            format="list",
            threads=8,
        )
        # results is a list of dicts: {"fuzzer": "...", "domain": "...", ...}
        found: list[str] = []
        for entry in results:
            domain = entry.get("domain", "")
            if domain and domain != seed:
                found.append(domain.lower())
        logger.info("  [dnstwist] Found %d registered permutations for %s", len(found), seed)
        return found

    except Exception as exc:
        logger.warning("dnstwist error for %s: %s", seed, exc)
        return []

# ---------------------------------------------------------------------------
# ── MAIN SCANNER ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def scan_brand(
    brand: str,
    whitelist: set[str],
    existing_blacklist: set[str],
) -> list[str]:
    """
    Full pipeline for one brand:
      1. Generate permutations
      2. DNS-resolve each candidate
      3. Filter against whitelist + existing blacklist
      4. Run dnstwist for IDN/homoglyph coverage
    Returns list of *new* suspicious domains.
    """
    logger.info("Scanning brand: %s", brand.upper())

    candidates = build_full_domain_list(brand)
    logger.info("  Generated %d domain candidates", len(candidates))

    new_finds: list[str] = []

    for domain in candidates:
        base = extract_base(domain)

        # Skip whitelisted / already-known
        if base in whitelist or domain.lower() in whitelist:
            continue
        if base in existing_blacklist or domain.lower() in existing_blacklist:
            continue

        ip = resolve_a_record(domain)
        if ip:
            logger.warning("  [HIT] %s → %s", domain, ip)
            new_finds.append(domain.lower())

    # --- dnstwist pass (IDN / punycode) ---
    for tld in [".vn", ".com.vn", ".com"]:
        dnstwist_hits = run_dnstwist(brand, tld)
        for domain in dnstwist_hits:
            base = extract_base(domain)
            if base not in whitelist and base not in existing_blacklist \
                    and domain not in new_finds:
                logger.warning("  [dnstwist HIT] %s", domain)
                new_finds.append(domain.lower())

    logger.info("  Brand %s: %d new suspicious domain(s) found.", brand, len(new_finds))
    return new_finds


def run_scan() -> None:
    """Entry point: scan all target brands and update blacklist.txt."""
    logger.info("=" * 60)
    logger.info("Vietnamese Domain Monitor – scan started %s",
                datetime.datetime.utcnow().isoformat())
    logger.info("=" * 60)

    # Load reference files
    whitelist = load_file_set(WHITELIST_FILE)
    whitelist.update(extract_base(d) for d in OFFICIAL_WHITELIST)
    whitelist.update(d.lower() for d in OFFICIAL_WHITELIST)

    existing_blacklist = load_file_set(BLACKLIST_FILE)

    all_new: list[str] = []
    for brand in TARGET_BRANDS:
        found = scan_brand(brand, whitelist, existing_blacklist)
        all_new.extend(found)

    if all_new:
        logger.info("Total new suspicious domains: %d", len(all_new))
        append_to_blacklist(all_new)
        # Signal to CI that changes were made
        summary_file = BASE_DIR / "scan_summary.json"
        summary_file.write_text(
            json.dumps({
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "new_domains": len(all_new),
                "domains": all_new,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("Scan complete. Results written.")
    else:
        logger.info("No new suspicious domains found in this scan.")

    logger.info("=" * 60)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run_scan()
