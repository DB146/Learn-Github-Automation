#!/usr/bin/env python3
"""
Vietnamese Domain Typosquatting & Fake Marketing Site Monitor
=============================================================
Proactively scans for typosquatted / fake-brand domains targeting
major Vietnamese corporations and appends findings to blacklist.txt.

Whitelist source of truth: whitelist.txt (repo root).
The hardcoded OFFICIAL_WHITELIST constant has been removed; all safe
domains must live in whitelist.txt so that updates are auditable via
Git history and do not require touching this script.

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

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
MAX_CANDIDATES_PER_BRAND = 4000  # hard cap per brand
DNS_WORKERS              = 20    # concurrent DNS threads
DNS_TIMEOUT              = 2.0   # seconds per lookup

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
BASE_DIR       = Path(__file__).parent
WHITELIST_FILE = BASE_DIR / "whitelist.txt"
BLACKLIST_FILE = BASE_DIR / "blacklist.txt"

# ---------------------------------------------------------------------------
# ── WHITELIST LOADING ────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def load_whitelist() -> set[str]:
    """
    Load the whitelist exclusively from whitelist.txt.

    The function builds a comprehensive lookup set that covers three forms
    of every whitelisted entry so that no legitimate domain slips through:

      1. The exact lowercased entry as written   ("fptshop.com.vn")
      2. The registrable base extracted by tldextract ("fptshop.com.vn")
         — for most entries these are identical, but subdomains like
         "vpbank.online-banking.vpbank.com.vn" collapse correctly.
      3. The bare SLD (second-level domain label, "fptshop") — used to
         short-circuit brand-prefix checks without a TLD.

    Raises FileNotFoundError if whitelist.txt is missing, so CI fails loudly
    rather than running an unprotected scan.
    """
    if not WHITELIST_FILE.exists():
        raise FileNotFoundError(
            f"whitelist.txt not found at {WHITELIST_FILE}. "
            "The file must exist in the repository root before scanning."
        )

    raw_lines = WHITELIST_FILE.read_text(encoding="utf-8").splitlines()
    entries: set[str] = set()

    for line in raw_lines:
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue

        entries.add(line)                          # exact form
        entries.add(extract_base(line))            # registrable base
        entries.add(_bare_sld(line))               # bare label (e.g. "fptshop")

    logger.info(
        "Whitelist loaded: %d raw entries → %d lookup tokens from %s",
        sum(1 for ln in raw_lines
            if ln.strip() and not ln.strip().startswith("#")),
        len(entries),
        WHITELIST_FILE,
    )
    return entries


def _bare_sld(domain: str) -> str:
    """Return just the SLD label, e.g. 'fptshop' from 'fptshop.com.vn'."""
    if HAS_TLDEXTRACT:
        return tldextract.extract(domain).domain.lower()
    # Fallback: first label before the first dot
    return domain.split(".")[0].lower()


def is_whitelisted(domain: str, whitelist: set[str]) -> bool:
    """
    Return True if *domain* (or any of its derived forms) appears in the
    whitelist set.  Checks:
      - exact full domain
      - registrable base  (strips subdomain prefix)
      - bare SLD label    (strips TLD entirely)
    """
    domain = domain.strip().lower().rstrip(".")
    return (
        domain in whitelist
        or extract_base(domain) in whitelist
        or _bare_sld(domain) in whitelist
    )

# ---------------------------------------------------------------------------
# ── OTHER FILE HELPERS ────────────────────────────────────────────────────────
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
    """Return the registrable part of a domain (e.g. foo.com.vn → foo.com.vn)."""
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
    Generate domain names (without TLD) by combining brand + SEO keywords.

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

    *max_swaps* limits simultaneous substitutions to avoid exponential explosion
    (default=1 → one substitution at a time).
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
    Classic typosquatting patterns:
        - Character deletion
        - Character doubling
        - Adjacent-key swaps
        - Common prefix/suffix insertions
    """
    results: set[str] = set()
    n = len(brand)

    for i in range(n):
        results.add(brand[:i] + brand[i+1:])           # deletion

    for i in range(n):
        results.add(brand[:i] + brand[i] * 2 + brand[i+1:])  # doubling

    for i in range(n - 1):
        lst = list(brand)
        lst[i], lst[i+1] = lst[i+1], lst[i]
        results.add("".join(lst))                       # adjacent swap

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

    Returns a list of domain strings that have registered DNS records.
    """
    if not HAS_DNSTWIST:
        logger.debug("dnstwist unavailable – skipping IDN checks for %s", brand)
        return []

    seed = f"{brand}{tld}"
    logger.info("  [dnstwist] Scanning permutations for %s …", seed)

    try:
        results = dnstwist.run(
            domain=seed,
            registered=True,
            format="list",
            threads=8,
        )
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

def check_domain(
    domain: str,
    whitelist: set[str],
    blacklist: set[str],
) -> Optional[str]:
    """
    Worker function executed in the thread pool.

    Returns the lowercased domain string if it:
      - is NOT whitelisted (via all three lookup forms)
      - is NOT already in the blacklist
      - resolves to at least one A record

    Returns None otherwise.
    """
    # Full whitelist check: exact, base, and bare SLD
    if is_whitelisted(domain, whitelist):
        return None

    # Already known-bad — skip to avoid duplicate entries
    base = extract_base(domain)
    if base in blacklist or domain.lower() in blacklist:
        return None

    ip = resolve_a_record(domain, timeout=DNS_TIMEOUT)
    return domain.lower() if ip else None


def scan_brand(
    brand: str,
    whitelist: set[str],
    existing_blacklist: set[str],
) -> list[str]:
    logger.info("Scanning brand: %s", brand.upper())

    candidates = build_full_domain_list(brand)

    if len(candidates) > MAX_CANDIDATES_PER_BRAND:
        logger.warning(
            "  Capping %d candidates to %d for brand %s",
            len(candidates), MAX_CANDIDATES_PER_BRAND, brand,
        )
        candidates = candidates[:MAX_CANDIDATES_PER_BRAND]

    logger.info("  Checking %d domain candidates (threaded)", len(candidates))

    new_finds: list[str] = []
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

    # dnstwist pass (two primary TLDs to stay within timeout budget)
    for tld in [".vn", ".com"]:
        for domain in run_dnstwist(brand, tld):
            if not is_whitelisted(domain, whitelist) \
                    and extract_base(domain) not in existing_blacklist \
                    and domain not in new_finds:
                new_finds.append(domain.lower())

    logger.info("  Brand %s: %d new domain(s) found.", brand, len(new_finds))
    return new_finds


def run_scan() -> None:
    """Entry point: load whitelist, scan all target brands, update blacklist.txt."""
    logger.info("=" * 60)
    logger.info(
        "Vietnamese Domain Monitor – scan started %s",
        datetime.datetime.utcnow().isoformat(),
    )
    logger.info("=" * 60)

    # ── Whitelist: single source of truth is whitelist.txt ──────────────────
    # Raises FileNotFoundError if the file is absent — CI job will fail loudly.
    whitelist = load_whitelist()

    # ── Blacklist: domains already actioned ─────────────────────────────────
    existing_blacklist = load_file_set(BLACKLIST_FILE)

    all_new: list[str] = []
    for brand in TARGET_BRANDS:
        found = scan_brand(brand, whitelist, existing_blacklist)
        all_new.extend(found)

    if all_new:
        logger.info("Total new suspicious domains: %d", len(all_new))
        append_to_blacklist(all_new)
        summary_file = BASE_DIR / "scan_summary.json"
        summary_file.write_text(
            json.dumps(
                {
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "new_domains": len(all_new),
                    "domains": all_new,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        logger.info("Scan complete. Results written.")
    else:
        logger.info("No new suspicious domains found in this scan.")

    logger.info("=" * 60)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run_scan()
