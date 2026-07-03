#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw Watch — list_leaks.py
List the latest company data leaks published on ransomware leak sites
(ransomware.live aggregator, clearnet, no Tor). France-focused by default.

Metadata-only: lists leak ENTRIES (company, group, date, sector, .onion
location). Never downloads leaked files.

Usage:
  python3 list_leaks.py                          # 20 latest FR leaks (table)
  python3 list_leaks.py --limit 40
  python3 list_leaks.py --country DE
  python3 list_leaks.py --country ALL            # global recent feed
  python3 list_leaks.py --sector Healthcare
  python3 list_leaks.py --group thegentlemen
  python3 list_leaks.py --json                   # or --csv
"""
import sys, os, json, csv, argparse

# ── bootstrap ─────────────────────────────────────────────────────
_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)

_env = os.path.join(_skill_dir, ".env")
if os.path.exists(_env):
    try:
        from dotenv import load_dotenv
        load_dotenv(_env, override=False)
    except ImportError:
        pass
# ──────────────────────────────────────────────────────────────────

try:
    import requests
except ImportError:
    print("ERROR: requests not installed.  Run:  pip install requests", file=sys.stderr)
    sys.exit(1)

API_BASE     = os.environ.get("RANSOMWARE_LIVE_API", "https://api-pro.ransomware.live").rstrip("/")
API_KEY      = os.environ.get("RANSOMWARE_LIVE_API_KEY", "")
HTTP_TIMEOUT = int(os.environ.get("WATCH_HTTP_TIMEOUT", "60"))

_GLOBAL = ("ALL", "WORLD", "*", "")


def fetch_leaks(country, sector, group):
    if not API_KEY:
        raise RuntimeError(
            "RANSOMWARE_LIVE_API_KEY missing. Get a free key at "
            "https://www.ransomware.live/ and add it to .env")
    is_global = (country or "").upper() in _GLOBAL
    params = {"order": "discovered"}
    if not is_global:
        params["country"] = country.upper()
    if sector:
        params["sector"] = sector
    if group:
        params["group"] = group
    # /victims/recent is fast for the unfiltered global case; otherwise search.
    use_search = (not is_global) or sector or group
    url = f"{API_BASE}/victims/search" if use_search else f"{API_BASE}/victims/recent"
    r = requests.get(url, timeout=HTTP_TIMEOUT,
                     params=params,
                     headers={"User-Agent": "OnionClaw-Watch/0.1", "X-API-KEY": API_KEY})
    if r.status_code in (401, 403):
        raise RuntimeError(
            f"ransomware.live returned {r.status_code} — invalid API key. "
            "Get a free key at https://www.ransomware.live/")
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else data.get("victims", data.get("data", []))


def row(v):
    return {
        "date":    str(v.get("discovered") or v.get("published") or "")[:10],
        "company": v.get("victim") or v.get("post_title") or "?",
        "group":   v.get("group_name") or v.get("group") or "?",
        "country": v.get("country") or "?",
        "sector":  v.get("activity") or "?",
        "source":  v.get("post_url") or v.get("permalink") or v.get("website") or "",
    }


def main():
    p = argparse.ArgumentParser(
        description="OnionClaw Watch — list latest company leaks (ransomware.live)")
    p.add_argument("--version", action="version", version="OnionClaw Watch list_leaks 0.1")
    p.add_argument("--country", default="FR",
                   help="ISO code (default FR); use ALL for the global feed")
    p.add_argument("--sector", default=None, help="Filter by sector (see /listsectors)")
    p.add_argument("--group", default=None, help="Filter by ransomware group (exact)")
    p.add_argument("--limit", type=int, default=20, help="Max entries (default 20)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--csv", action="store_true", help="Output CSV")
    args = p.parse_args()

    try:
        vics = fetch_leaks(args.country, args.sector, args.group)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    rows = [row(v) for v in vics[:args.limit]]
    scope = "MONDIAL" if (args.country or "").upper() in _GLOBAL else args.country.upper()

    if args.json:
        print(json.dumps({"scope": scope, "count": len(rows), "leaks": rows},
                         indent=2, ensure_ascii=False))
    elif args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=["date", "company", "group", "country", "sector", "source"])
        w.writeheader()
        w.writerows(rows)
    else:
        filt = " ".join(f for f in [f"[{scope}]",
                                    f"secteur={args.sector}" if args.sector else "",
                                    f"groupe={args.group}" if args.group else ""] if f)
        print(f"Dernières fuites entreprises {filt} — {len(rows)} sur {len(vics)} disponibles\n")
        print(f"{'DATE':<11} {'ENTREPRISE':<34} {'GROUPE':<15} {'PAYS':<5} SECTEUR")
        print("─" * 90)
        for r in rows:
            print(f"{r['date']:<11} {r['company'][:33]:<34.34} {r['group'][:14]:<15.15} "
                  f"{r['country']:<5.5} {r['sector']}")


if __name__ == "__main__":
    main()
