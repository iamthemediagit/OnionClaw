#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw Watch — watch_ransomware.py
Poll the ransomware.live aggregator (clearnet API, no Tor), match recent
ransomware victims against your clients' assets, and alert by email.

Metadata-only by design: stores victim name / group / date / source / matched
asset. Never downloads or retains stolen data.

Usage:
  python3 watch_ransomware.py --clients clients.json --dry-run
  python3 watch_ransomware.py --clients clients.json          # send emails
  python3 watch_ransomware.py --clients clients.json --json    # machine-readable

Cron (every 6h):
  0 */6 * * * cd /path/to/OnionClaw && python3 watch_ransomware.py --clients clients.json
"""
import sys, os, json, argparse, smtplib, ssl
from email.message import EmailMessage

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

API_BASE   = os.environ.get("RANSOMWARE_LIVE_API", "https://api-pro.ransomware.live").rstrip("/")
API_KEY    = os.environ.get("RANSOMWARE_LIVE_API_KEY", "")
STATE_PATH = os.path.expanduser(
    os.environ.get("ONIONCLAW_WATCH_STATE", os.path.join(_skill_dir, ".watch_state.json")))
HTTP_TIMEOUT = int(os.environ.get("WATCH_HTTP_TIMEOUT", "30"))


# ── data acquisition ──────────────────────────────────────────────
def fetch_recent_victims():
    """Pull recently disclosed ransomware victims from the aggregator.

    ransomware.live now requires a free API key (X-API-KEY header).
    Register one at https://www.ransomware.live/ and set RANSOMWARE_LIVE_API_KEY.
    """
    if not API_KEY:
        raise RuntimeError(
            "RANSOMWARE_LIVE_API_KEY missing. Get a free key at "
            "https://www.ransomware.live/ and add it to .env")
    url = f"{API_BASE}/victims/recent"
    r = requests.get(url, timeout=HTTP_TIMEOUT,
                     params={"order": "discovered"},
                     headers={"User-Agent": "OnionClaw-Watch/0.1",
                              "X-API-KEY": API_KEY})
    if r.status_code in (401, 403):
        raise RuntimeError(
            f"ransomware.live returned {r.status_code} — invalid API key. "
            "Get a free key at https://www.ransomware.live/")
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else data.get("victims", data.get("data", []))


# ── matching ──────────────────────────────────────────────────────
def _norm(s):
    return (s or "").strip().lower()


def victim_haystack(v):
    """Concatenate the searchable text of a victim record (metadata only)."""
    parts = [v.get("post_title"), v.get("victim"), v.get("website"),
             v.get("domain"), v.get("description"), v.get("country")]
    return " ".join(_norm(p) for p in parts if p)


def match_client(victim, client):
    """Return the list of client tokens (names/domains) found in the victim."""
    hay = victim_haystack(victim)
    hits = []
    for token in client.get("names", []) + client.get("domains", []):
        t = _norm(token)
        if t and t in hay:
            hits.append(token)
    return hits


def victim_key(v):
    """Stable dedup key for a victim record."""
    return v.get("id") or "|".join([
        _norm(v.get("post_title") or v.get("victim")),
        _norm(v.get("group_name") or v.get("group")),
        _norm(v.get("discovered") or v.get("published")),
    ])


# ── state (dedup) ─────────────────────────────────────────────────
def load_state():
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                return set(json.load(f).get("seen", []))
        except Exception:
            return set()
    return set()


def save_state(seen):
    os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump({"seen": sorted(seen)}, f, indent=2)


# ── alerting ──────────────────────────────────────────────────────
def render_alert(client, victim, hits):
    return (
        f"[OnionClaw Watch] Exposition possible — {client['name']}\n"
        f"\n"
        f"Correspondance : {', '.join(hits)}\n"
        f"Victime listée : {victim.get('post_title') or victim.get('victim')}\n"
        f"Groupe         : {victim.get('group_name') or victim.get('group')}\n"
        f"Découvert le    : {victim.get('discovered') or victim.get('published')}\n"
        f"Pays / secteur  : {victim.get('country', '?')} / {victim.get('activity', '?')}\n"
        f"Source          : {victim.get('post_url') or victim.get('url') or API_BASE}\n"
        f"\n"
        f"Métadonnées uniquement. Aucune donnée volée n'est stockée.\n"
        f"Action : vérifier via investigation ciblée (OnionClaw) avant notification client.\n"
    )


def send_email(to_addr, subject, body):
    host = os.environ.get("SMTP_HOST")
    if not host:
        raise RuntimeError("SMTP_HOST not configured in .env (use --dry-run to test without email)")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    pwd  = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM", user or "onionclaw@localhost")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=HTTP_TIMEOUT) as s:
            if user:
                s.login(user, pwd)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=HTTP_TIMEOUT) as s:
            s.starttls(context=ctx)
            if user:
                s.login(user, pwd)
            s.send_message(msg)


# ── main ──────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="OnionClaw Watch — ransomware.live victim monitoring")
    p.add_argument("--version", action="version", version="OnionClaw Watch ransomware 0.1")
    p.add_argument("--clients", required=True,
                   help="Path to clients JSON (see clients.example.json)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print alerts to stdout instead of sending email")
    p.add_argument("--json", action="store_true", help="Output raw JSON only")
    p.add_argument("--no-state", action="store_true",
                   help="Ignore dedup state (re-alert everything)")
    args = p.parse_args()

    try:
        with open(args.clients) as f:
            clients = json.load(f).get("clients", [])
    except Exception as e:
        print(f"ERROR: cannot read clients file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        victims = fetch_recent_victims()
    except Exception as e:
        print(f"ERROR: ransomware.live fetch failed: {e}", file=sys.stderr)
        sys.exit(1)

    seen = set() if args.no_state else load_state()
    new_seen = set(seen)
    alerts = []

    for v in victims:
        key = victim_key(v)
        for client in clients:
            hits = match_client(v, client)
            if not hits:
                continue
            dedup = f"{client['name']}::{key}"
            if dedup in seen:
                continue
            new_seen.add(dedup)
            alerts.append({
                "client": client["name"],
                "matched": hits,
                "victim": v.get("post_title") or v.get("victim"),
                "group": v.get("group_name") or v.get("group"),
                "discovered": v.get("discovered") or v.get("published"),
                "source": v.get("post_url") or v.get("url"),
                "country": v.get("country"),
                "activity": v.get("activity"),
                "alert_email": client.get("alert_email"),
            })

    if args.json:
        print(json.dumps({"scanned": len(victims), "alerts": alerts}, indent=2, ensure_ascii=False))
    else:
        print(f"Scanned {len(victims)} recent victims — {len(alerts)} new match(es).")
        for a in alerts:
            subject = f"[OnionClaw Watch] {a['client']} — {a['victim']} ({a['group']})"
            client_obj = next(c for c in clients if c["name"] == a["client"])
            body = render_alert(client_obj, {
                "post_title": a["victim"], "group_name": a["group"],
                "discovered": a["discovered"], "post_url": a["source"],
                "country": a.get("country"), "activity": a.get("activity"),
            }, a["matched"])
            if args.dry_run or not a.get("alert_email"):
                print("─" * 60)
                print(f"TO: {a.get('alert_email') or '(no email — dry)'}")
                print(subject)
                print(body)
            else:
                try:
                    send_email(a["alert_email"], subject, body)
                    print(f"✓ alert sent to {a['alert_email']} ({a['client']})")
                except Exception as e:
                    print(f"✗ email failed for {a['client']}: {e}", file=sys.stderr)

    if not args.no_state and not args.dry_run:
        save_state(new_seen)


if __name__ == "__main__":
    main()
