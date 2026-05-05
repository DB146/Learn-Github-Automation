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
import sys
import json
import concurrent.futures
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# ── CONSTANTS ────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
MAX_CANDIDATES_PER_BRAND = 500   # hard cap per brand to avoid timeout
DNS_WORKERS              = 20    # concurrent DNS threads
DNS_TIMEOUT              = 2.0   # seconds per lookup

# ---------------------------------------------------------------------------
# ── OPTIONAL / GRACEFUL IMPORTS ──────────────────────────────────────────────
# ---------------------------------------------------------------------------
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import dnstwist
    HAS_DNSTWIST = True
except ImportError:
    HAS_DNSTWIST = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

# ---------------------------------------------------------------------------
# ── LOGGING ──────────────────────────────────────────────────────────────────
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

if not HAS_DNSPYTHON:
    logger.warning("dnspython not installed – falling back to socket for DNS checks.")
if not HAS_DNSTWIST:
    logger.warning("dnstwist not installed – homoglyph/punycode permutations disabled.")
if not HAS_TLDEXTRACT:
    logger.warning("tldextract not installed – basic TLD splitting used.")

# ---------------------------------------------------------------------------
# ── DATA STRUCTURES ──────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

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

TARGET_BRANDS: list[str] = [
    "viettel", "fpt", "vinfast", "vinhomes", "vingroup",
    "thegioididong", "dienmayxanh", "vinamilk", "masan",
    "vietcombank", "techcombank", "vpbank", "acb",
    "ghn", "ghtk", "vnpt", "vinaphone",
]

VN_SEO_KEYWORDS: list[str] = [
    "khuyenmai", "uudai", "tongdai", "lapmang", "goicuoc",
    "tuyendung", "mienphi", "vayvon", "chinhhang", "giare",
    "san-sale", "sale", "hanoi", "hcm", "shopee", "lazada",
    "online", "store", "vip", "official", "dangky",
    "dichvu", "hotline", "lienhe", "sim", "goicom",
    "internet", "fiber", "4g", "5g", "tgdd",
]

TARGET_TLDS: list[str] = [
    ".vn", ".com.vn", ".net.vn", ".org.vn",
    ".com", ".net", ".site", ".xyz", ".top",
    ".info", ".store", ".vip", ".online", ".ink",
]

HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["4", "@"],
    "e": ["3"],
    "i": ["l", "1"],
    "o": ["0"],
    "v": ["w"],
    "t": ["7"],
    "g": ["9"],
    "s": ["5"],
    "b": ["6"],
}

# ---------------------------------------------------------------------------
# ── FILE PATHS ───────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
BASE_DIR       = Path(__file__).parent
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

def resolve_a_record(domain: str, timeout: float = DNS_TIMEOUT) -> Optional[str]:
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
    brand-keyword, brandkeyword, keyword-brand, keywordbrand
    e.g. viettel-khuyenmai, viettelkhuyenmai, khuyenmai-viettel ...
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
    Substitute characters with ASCII look-alikes (one swap at a time).
    Unicode/IDN confusables are handled by dnstwist separately.
    """
    results: set[str] = set()
    chars = list(brand)
    swap_positions = [i for i, ch in enumerate(chars) if ch in HOMOGLYPHS]

    for num_swaps in range(1, max_swaps + 1):
        for positions in itertools.combinations(swap_positions, num_swaps):
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
    Character deletion, doubling, adjacent swaps, and common prefix/suffix pads.
    """
    results: set[str] = set()
    n = len(brand)

    for i in range(n):                          # deletion
        results.add(brand[:i] + brand[i+1:])
    for i in range(n):                          # doubling
        results.add(brand[:i] + brand[i] * 2 + brand[i+1:])
    for i in range(n - 1):                      # adjacent swap
        lst = list(brand)
        lst[i], lst[i+1] = lst[i+1], lst[i]
        results.add("".join(lst))
    for pad in ["my", "get", "use", "e", "i", "dang-ky", "chinh-hang"]:
        results.add(f"{pad}-{brand}")
        results.add(f"{brand}-{pad}")

    results.discard(brand)
    return list(results)


def build_full_domain_list(brand: str) -> list[str]:
    """
    Combine all permutation methods and expand across TARGET_TLDS.
    Returns a flat list of fully-qualified candidate domain strings.
    """
    names: set[str] = set()
    names.update(generate_keyword_permutations(brand))
    names.update(generate_homoglyph_permutations(brand, max_swaps=1))
    names.update(generate_typo_permutations(brand))

    # Vietnamese city-subdomain patterns: hanoi.viettel-khuyenmai.vn
    for city in ["hanoi", "hcm", "hue", "danang"]:
        names.add(f"{city}.{brand}-khuyenmai")
        names.add(f"{city}.{brand}-uudai")

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
    Use dnstwist to catch advanced IDN / Punycode / Unicode confusable attacks,
    e.g. viettel.vn with dotless-i (U+0131) that plain homoglyphs won't catch.
    Returns only domains that have active DNS records.
    """
    if not HAS_DNSTWIST:
        logger.debug("dnstwist unavailable – skipping IDN checks for %s", brand)
        return []

    seed = f"{brand}{tld}"
    logger.info("  [dnstwist] Scanning %s ...", seed)
    try:
        results = dnstwist.run(
            domain=seed,
            registered=True,
            format="list",
            threads=8,
        )
        found = [
            entry["domain"].lower()
            for entry in results
            if entry.get("domain") and entry["domain"] != seed
        ]
        logger.info("  [dnstwist] %d registered permutations for %s", len(found), seed)
        return found
    except Exception as exc:
        logger.warning("dnstwist error for %s: %s", seed, exc)
        return []

# ---------------------------------------------------------------------------
# ── THREADED DNS WORKER ──────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def _check_domain(domain: str, whitelist: set[str], blacklist: set[str]) -> Optional[str]:
    """
    Thread-pool worker: resolves one domain.
    Returns the domain string if live and not whitelisted/blacklisted, else None.
    """
    base = extract_base(domain)
    if base in whitelist or domain.lower() in whitelist:
        return None
    if base in blacklist or domain.lower() in blacklist:
        return None
    ip = resolve_a_record(domain)
    return domain.lower() if ip else None

# ---------------------------------------------------------------------------
# ── BRAND SCANNER ────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def scan_brand(
    brand: str,
    whitelist: set[str],
    existing_blacklist: set[str],
) -> list[str]:
    """
    Full pipeline for one brand:
      1. Generate permutation candidates
      2. Cap to MAX_CANDIDATES_PER_BRAND to stay within CI time budget
      3. Concurrent DNS resolution via thread pool
      4. dnstwist pass for IDN/Punycode coverage
    Returns list of new suspicious domains not already in whitelist/blacklist.
    """
    logger.info("Scanning brand: %s", brand.upper())

    candidates = build_full_domain_list(brand)

    if len(candidates) > MAX_CANDIDATES_PER_BRAND:
        logger.warning(
            "  Capping %d candidates to %d for brand %s",
            len(candidates), MAX_CANDIDATES_PER_BRAND, brand,
        )
        candidates = candidates[:MAX_CANDIDATES_PER_BRAND]

    logger.info("  Checking %d candidates with %d DNS threads ...", len(candidates), DNS_WORKERS)

    new_finds: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
        futures = {
            executor.submit(_check_domain, d, whitelist, existing_blacklist): d
            for d in candidates
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                logger.warning("  [HIT] %s", result)
                new_finds.append(result)

    # dnstwist pass — only two TLDs to keep runtime short
    for tld in [".vn", ".com"]:
        for domain in run_dnstwist(brand, tld):
            base = extract_base(domain)
            if (
                base not in whitelist
                and base not in existing_blacklist
                and domain not in new_finds
            ):
                logger.warning("  [dnstwist HIT] %s", domain)
                new_finds.append(domain.lower())

    logger.info("  Brand %s: %d new domain(s) found.", brand, len(new_finds))
    return new_finds

# ---------------------------------------------------------------------------
# ── ENTRY POINT ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def run_scan() -> None:
    """Scan all target brands and update blacklist.txt + scan_summary.json."""
    logger.info("=" * 60)
    logger.info("Vietnamese Domain Monitor - scan started %s",
                datetime.datetime.utcnow().isoformat())
    logger.info("=" * 60)

    whitelist = load_file_set(WHITELIST_FILE)
    whitelist.update(extract_base(d) for d in OFFICIAL_WHITELIST)
    whitelist.update(d.lower() for d in OFFICIAL_WHITELIST)

    existing_blacklist = load_file_set(BLACKLIST_FILE)

    all_new: list[str] = []
    for brand in TARGET_BRANDS:
        found = scan_brand(brand, whitelist, existing_blacklist)
        all_new.extend(found)

    if all_new:
        logger.info("Total new suspicious domains found: %d", len(all_new))
        append_to_blacklist(all_new)
        summary = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "new_domains": len(all_new),
            "domains": all_new,
        }
        (BASE_DIR / "scan_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("scan_summary.json written.")
    else:
        logger.info("No new suspicious domains found in this scan.")

    logger.info("=" * 60)


if __name__ == "__main__":
    run_scan()
