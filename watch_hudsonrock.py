#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw Watch — watch_hudsonrock.py
Query Hudson Rock's Cavalier infostealer intelligence (clearnet API, no Tor)
for each client domain, and alert when compromised credentials are detected.

Metadata-only by design: the free tier returns COUNTS + DATES + URLs, never
plaintext passwords — which is exactly the "signal, not the loot" doctrine.
This script stores only counts/dates. Get a free key at:
  https://www.hudsonrock.com/free-api-key

Usage:
  python3 watch_hudsonrock.py --clients clients.json --dry-run
  python3 watch_hudsonrock.py --clients clients.json --raw     # dump raw API JSON (schema tuning)
  python3 watch_hudsonrock.py --clients clients.json           # send emails

Cron (daily):
  30 6 * * * cd /path/to/OnionClaw && python3 watch_hudsonrock.py --clients clients.json
"""
import sys, os, json, argparse

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

# Reuse the SMTP sender from the ransomware connector (single source of truth)
try:
    from watch_ransomware import send_email
except Exception:
    send_email = None

API_BASE   = os.environ.get("HUDSONROCK_API", "https://api.hudsonrock.com/json/v3").rstrip("/")
API_KEY    = os.environ.get("HUDSONROCK_API_KEY", "")
STATE_PATH = os.path.expanduser(
    os.environ.get("ONIONCLAW_HUDSON_STATE", os.path.join(_skill_dir, ".hudson_state.json")))
HTTP_TIMEOUT = int(os.environ.get("WATCH_HTTP_TIMEOUT", "30"))


# ── data acquisition ──────────────────────────────────────────────
def domain_overview(domain):
    """Fetch the infostealer exposure overview for one domain."""
    if not API_KEY:
        raise RuntimeError(
            "HUDSONROCK_API_KEY missing. Get a free key at "
            "https://www.hudsonrock.com/free-api-key and add it to .env")
    url = f"{API_BASE}/search-by-domain/overview"
    r = requests.post(url, timeout=HTTP_TIMEOUT,
                      headers={"accept": "application/json",
                               "content-type": "application/json",
                               "api-key": API_KEY,
                               "User-Agent": "OnionClaw-Watch/0.1"},
                      json={"domains": [domain]})
    if r.status_code in (401, 403):
        raise RuntimeError(
            f"Hudson Rock returned {r.status_code} — invalid API key. "
            "Get a free key at https://www.hudsonrock.com/free-api-key")
    r.raise_for_status()
    return r.json()


# ── resilient parsing (schema not verifiable without a key) ────────
_COUNT_KEYS = {
    "employees": ("employees", "compromised_employees", "total_employees"),
    "users":     ("users", "compromised_users", "total_users"),
    "third":     ("third_parties", "compromised_third_parties", "third_party"),
    "total":     ("total", "total_stealers", "stealers"),
}
_DATE_KEYS = ("last_employee_compromised", "last_user_compromised",
              "last_compromised", "date_compromised")


def _dig(obj, domain):
    """Return the overview sub-object for a domain from a variety of shapes."""
    if not isinstance(obj, dict):
        return {}
    # {"data": {...}} or {"data": {"example.com": {...}}}
    data = obj.get("data", obj)
    if isinstance(data, dict):
        if domain in data and isinstance(data[domain], dict):
            return data[domain]
        return data
    if isinstance(data, list) and data:
        return data[0] if isinstance(data[0], dict) else {}
    return {}


def extract_counts(resp, domain):
    node = _dig(resp, domain)
    out = {"employees": 0, "users": 0, "third": 0, "total": 0, "last": None}
    for k, aliases in _COUNT_KEYS.items():
        for a in aliases:
            v = node.get(a)
            if isinstance(v, (int, float)):
                out[k] = int(v)
                break
    if not out["total"]:
        out["total"] = out["employees"] + out["users"] + out["third"]
    for a in _DATE_KEYS:
        if node.get(a):
            out["last"] = node[a]
            break
    return out


# ── state (dedup: alert only when exposure grows) ─────────────────
def load_state():
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def is_new_exposure(domain, counts, state):
    """Alert if total grew or the last-compromised date changed vs stored state."""
    prev = state.get(domain, {})
    return (counts["total"] > prev.get("total", 0)
            or (counts["last"] and counts["last"] != prev.get("last")))


# ── alerting ──────────────────────────────────────────────────────
def render_alert(client, domain, counts):
    return (
        f"[OnionClaw Watch] Identifiants compromis — {client['name']}\n"
        f"\n"
        f"Domaine        : {domain}\n"
        f"Postes employés compromis : {counts['employees']}\n"
        f"Utilisateurs / clients    : {counts['users']}\n"
        f"Tiers                     : {counts['third']}\n"
        f"Total exposition (stealers): {counts['total']}\n"
        f"Dernière compromission     : {counts['last'] or '?'}\n"
        f"Source          : Hudson Rock Cavalier (infostealer intelligence)\n"
        f"\n"
        f"Métadonnées uniquement (compteurs + dates). Aucun mot de passe stocké.\n"
        f"Action : reset immédiat des identifiants concernés + investigation ciblée.\n"
    )


# ── main ──────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="OnionClaw Watch — Hudson Rock infostealer monitoring")
    p.add_argument("--version", action="version", version="OnionClaw Watch hudsonrock 0.1")
    p.add_argument("--clients", required=True, help="Path to clients JSON")
    p.add_argument("--dry-run", action="store_true", help="Print alerts instead of emailing")
    p.add_argument("--json", action="store_true", help="Output structured JSON only")
    p.add_argument("--raw", action="store_true",
                   help="Dump raw API response per domain (schema tuning on first real key)")
    p.add_argument("--no-state", action="store_true", help="Ignore dedup state")
    args = p.parse_args()

    try:
        with open(args.clients) as f:
            clients = json.load(f).get("clients", [])
    except Exception as e:
        print(f"ERROR: cannot read clients file: {e}", file=sys.stderr)
        sys.exit(1)

    # domain -> list of client objects owning it
    domain_owners = {}
    for c in clients:
        for d in c.get("domains", []):
            domain_owners.setdefault(d.strip().lower(), []).append(c)

    if not domain_owners:
        print("No client domains to check.", file=sys.stderr)
        sys.exit(1)

    state = {} if args.no_state else load_state()
    alerts = []

    for domain, owners in domain_owners.items():
        try:
            resp = domain_overview(domain)
        except Exception as e:
            print(f"ERROR: Hudson Rock lookup failed for {domain}: {e}", file=sys.stderr)
            sys.exit(1)

        if args.raw:
            print(f"── RAW {domain} ──")
            print(json.dumps(resp, indent=2, ensure_ascii=False)[:2000])
            continue

        counts = extract_counts(resp, domain)
        if counts["total"] <= 0:
            continue
        if not args.no_state and not is_new_exposure(domain, counts, state):
            continue
        state[domain] = {"total": counts["total"], "last": counts["last"]}
        for c in owners:
            alerts.append({"client": c["name"], "domain": domain,
                           "counts": counts, "alert_email": c.get("alert_email")})

    if args.raw:
        return

    if args.json:
        print(json.dumps({"domains_checked": len(domain_owners), "alerts": alerts},
                         indent=2, ensure_ascii=False))
    else:
        print(f"Checked {len(domain_owners)} domain(s) — {len(alerts)} new exposure alert(s).")
        for a in alerts:
            client_obj = next(c for c in clients if c["name"] == a["client"])
            subject = (f"[OnionClaw Watch] {a['client']} — {a['counts']['total']} "
                       f"identifiant(s) compromis ({a['domain']})")
            body = render_alert(client_obj, a["domain"], a["counts"])
            if args.dry_run or not a.get("alert_email"):
                print("─" * 60)
                print(f"TO: {a.get('alert_email') or '(no email — dry)'}")
                print(subject)
                print(body)
            elif send_email is None:
                print(f"✗ send_email unavailable (watch_ransomware import failed)", file=sys.stderr)
            else:
                try:
                    send_email(a["alert_email"], subject, body)
                    print(f"✓ alert sent to {a['alert_email']} ({a['client']})")
                except Exception as e:
                    print(f"✗ email failed for {a['client']}: {e}", file=sys.stderr)

    if not args.no_state and not args.dry_run:
        save_state(state)


if __name__ == "__main__":
    main()
