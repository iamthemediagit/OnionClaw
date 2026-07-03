#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw Watch — evidence.py
Build a defensible proof-of-compromise dossier for a ransomware victim.

Captures the ATTACKER'S OWN published proof (leak-site claim, screenshot,
dates, group, .onion URL) + metadata — never the stolen dataset. Each artifact
is SHA-256 hashed; the manifest can be RFC 3161 timestamped (freeTSA by default,
swappable to an eIDAS-qualified TSA). Chain of custody per ISO/IEC 27037.

Usage:
  python3 evidence.py --victim-id <id>
  python3 evidence.py --query "Au Vieux Campeur"
  python3 evidence.py --client "Maars" --clients clients.json
  python3 evidence.py --victim-id <id> --onion --timestamp
  python3 evidence.py --query "..." --no-screenshot

Env (.env): EVIDENCE_OPERATOR, EVIDENCE_TSA_URL, EVIDENCE_OUT_DIR
"""
import sys, os, json, argparse, hashlib, re, subprocess, platform
import datetime as _dt

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

VERSION      = "0.1"
API_BASE     = os.environ.get("RANSOMWARE_LIVE_API", "https://api-pro.ransomware.live").rstrip("/")
API_KEY      = os.environ.get("RANSOMWARE_LIVE_API_KEY", "")
OPERATOR     = os.environ.get("EVIDENCE_OPERATOR", "unknown operator")
TSA_URL      = os.environ.get("EVIDENCE_TSA_URL", "https://freetsa.org/tsr")
OUT_DIR      = os.path.expanduser(os.environ.get("EVIDENCE_OUT_DIR", os.path.join(_skill_dir, "evidence")))
HTTP_TIMEOUT = int(os.environ.get("WATCH_HTTP_TIMEOUT", "45"))

_H = {"User-Agent": "OnionClaw-Watch-Evidence/" + VERSION, "X-API-KEY": API_KEY}


def _utc_now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _get(url, **kw):
    last = None
    for _ in range(3):
        try:
            return requests.get(url, headers=_H, timeout=HTTP_TIMEOUT, **kw)
        except requests.exceptions.RequestException as e:
            last = e
    raise RuntimeError(f"request failed after retries: {type(last).__name__}")


# ── victim resolution ─────────────────────────────────────────────
def resolve(args):
    if not API_KEY:
        raise RuntimeError("RANSOMWARE_LIVE_API_KEY missing (see .env).")
    if args.victim_id:
        r = _get(f"{API_BASE}/victim/{args.victim_id}")
        if r.status_code in (401, 403):
            raise RuntimeError(f"ransomware.live {r.status_code} — invalid API key.")
        r.raise_for_status()
        rec = r.json()
        return rec[0] if isinstance(rec, list) and rec else rec
    term = args.query
    if args.client:
        with open(args.clients) as f:
            clients = json.load(f).get("clients", [])
        c = next((c for c in clients
                  if args.client.lower() in [c["name"].lower(), *[n.lower() for n in c.get("names", [])]]),
                 None)
        if not c:
            raise RuntimeError(f"client '{args.client}' not found in {args.clients}")
        term = c.get("names", [c["name"]])[0]
    if not term:
        raise RuntimeError("provide --victim-id, --query or --client")
    r = _get(f"{API_BASE}/victims/search", params={"q": term})
    r.raise_for_status()
    data = r.json()
    vics = data if isinstance(data, list) else data.get("victims", data.get("data", []))
    if not vics:
        raise RuntimeError(f"no victim found for '{term}'")
    if len(vics) > 1:
        print(f"⚠ {len(vics)} résultats pour '{term}' — le 1er est retenu "
              f"(précisez --victim-id pour cibler).", file=sys.stderr)
    return vics[0]


# ── hashing & artifacts ───────────────────────────────────────────
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def capture_onion(post_url, dest):
    try:
        import sicry
    except Exception:
        return "sicry.py introuvable — capture .onion ignorée"
    try:
        res = sicry.fetch(post_url)
    except Exception as e:
        return f"échec fetch Tor ({type(e).__name__}) — Tor lancé ?"
    if res.get("error"):
        return f"post injoignable (status {res.get('status', 0)}) — hidden service offline ?"
    with open(dest, "w") as f:
        f.write(f"URL: {post_url}\nTITLE: {res.get('title','')}\nSTATUS: {res.get('status')}\n")
        f.write("-" * 60 + "\n")
        f.write(res.get("text", ""))
    return None


def rfc3161_timestamp(manifest_path, out_tsr):
    if not subprocess.run(["which", "openssl"], capture_output=True).returncode == 0:
        return "openssl introuvable — horodatage ignoré"
    tsq = out_tsr + ".tsq"
    try:
        subprocess.run(["openssl", "ts", "-query", "-data", manifest_path,
                        "-sha256", "-cert", "-no_nonce", "-out", tsq],
                       check=True, capture_output=True)
        with open(tsq, "rb") as f:
            body = f.read()
        r = requests.post(TSA_URL, data=body, timeout=HTTP_TIMEOUT,
                          headers={"Content-Type": "application/timestamp-query"})
        if r.status_code != 200 or "timestamp-reply" not in r.headers.get("content-type", ""):
            return f"TSA {TSA_URL} a répondu {r.status_code} — horodatage échoué"
        with open(out_tsr, "wb") as f:
            f.write(r.content)
        return None
    except Exception as e:
        return f"horodatage échoué ({type(e).__name__})"


# ── dossier ───────────────────────────────────────────────────────
def write_dossier(path, rec, folder, captured_at, artifacts, ts_status, onion_status):
    def g(k):
        return rec.get(k) or "—"
    tool = f"OnionClaw Watch evidence {VERSION} · Python {platform.python_version()} · {platform.platform()}"
    lines = [
        f"# Dossier de preuve — {g('post_title') or g('victim')}",
        "",
        "> Preuve de compromission (matériel publié par l'attaquant + métadonnées).",
        "> **Aucune donnée volée n'est téléchargée ni conservée.**",
        "",
        "## Chaîne de custody (ISO/IEC 27037)",
        "",
        f"- **Identifiant de preuve** : `{os.path.basename(folder)}`",
        f"- **Capturé le (UTC)** : {captured_at}",
        f"- **Opérateur** : {OPERATOR}",
        f"- **Outil** : {tool}",
        f"- **Source** : ransomware.live API (`{API_BASE}`)",
        f"- **Post leak-site** : {g('post_url')}",
        "",
        "## Victime & revendication",
        "",
        f"| Champ | Valeur |",
        f"|---|---|",
        f"| Entreprise | {g('post_title') or g('victim')} |",
        f"| Groupe ransomware | {g('group_name')} |",
        f"| Pays / secteur | {g('country')} / {g('activity')} |",
        f"| Date attaque | {g('attackdate')} |",
        f"| Découvert (leak site) | {g('discovered')} |",
        f"| Publié | {g('published')} |",
        f"| Rançon | {g('ransom')} |",
        f"| Volume annoncé | {g('data_size')} |",
        f"| Permalink | {g('permalink')} |",
        "",
        "## Artefacts (SHA-256)",
        "",
        f"| Fichier | SHA-256 |",
        f"|---|---|",
    ]
    for name, h in artifacts:
        lines.append(f"| `{name}` | `{h}` |")
    lines += [
        "",
        f"Vérification : `sha256sum -c MANIFEST.sha256`",
        "",
        "## Horodatage",
        "",
        (f"- Jeton RFC 3161 : `timestamp.tsr` (TSA `{TSA_URL}`)" if ts_status is None
         else f"- Horodatage : ⚠ {ts_status}"),
        "- Pour une valeur probante renforcée, pointer `EVIDENCE_TSA_URL` vers une TSA "
        "**eIDAS-qualifiée** (Datasure/ANSSI, SK Estonie).",
        "",
    ]
    if onion_status is not None:
        lines.append(f"> Note capture .onion : {onion_status}\n")
    lines += [
        "## Valeur probante & cadre légal",
        "",
        "- **Niveau du présent dossier** : capture + SHA-256 + horodatage + custody = "
        "preuve technique **solide** (présomption d'exactitude, art. 41 eIDAS si TSA qualifiée).",
        "- **Contentieux/pénal** : privilégier un **constat de commissaire de justice** "
        "(NF Z67-147) — valeur d'acte authentique.",
        "- **Métadonnées-only** : on capture la preuve publiée par l'attaquant, jamais le "
        "jeu de données volé (évite le recel, art. 321-1 CP).",
        "- **Rétention** : supprimer sous **30 jours** après remise au client, sauf conservation "
        "légale (minimisation, art. 5-1-e RGPD).",
        "",
        "## À remettre au client (obligations)",
        "",
        "- **CNIL** (RGPD art. 33) : notification sous **72 h** à compter de la connaissance.",
        "- **ANSSI** (NIS2, entités essentielles/importantes) : alerte précoce **24 h**.",
        "- Ce dossier établit la date/heure de connaissance et matérialise la menace.",
        "",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


# ── main ──────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="OnionClaw Watch — proof-of-compromise dossier")
    p.add_argument("--version", action="version", version=f"OnionClaw Watch evidence {VERSION}")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--victim-id", help="ransomware.live victim id")
    g.add_argument("--query", help="keyword to resolve the victim")
    g.add_argument("--client", help="client name (from --clients JSON)")
    p.add_argument("--clients", default="clients.json", help="clients JSON (with --client)")
    p.add_argument("--onion", action="store_true", help="also capture the live .onion post (needs Tor)")
    p.add_argument("--timestamp", action="store_true", help="RFC 3161 timestamp the manifest")
    p.add_argument("--no-screenshot", action="store_true", help="skip attacker screenshot download")
    p.add_argument("--out", default=None, help="output base dir (default EVIDENCE_OUT_DIR)")
    args = p.parse_args()

    try:
        rec = resolve(args)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    captured_at = _utc_now()
    name = rec.get("post_title") or rec.get("victim") or "victim"
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "victim"
    day = str(rec.get("discovered") or rec.get("published") or captured_at)[:10]
    base = os.path.expanduser(args.out) if args.out else OUT_DIR
    folder = os.path.join(base, f"{slug}_{day}")
    os.makedirs(folder, exist_ok=True)

    # record.json
    rec_path = os.path.join(folder, "record.json")
    with open(rec_path, "w") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
    artifacts_files = ["record.json"]

    # screenshot
    if not args.no_screenshot and rec.get("screenshot"):
        sc = rec["screenshot"]
        url = sc if str(sc).startswith("http") else "https://www.ransomware.live" + sc
        try:
            r = _get(url)
            if r.status_code == 200 and r.content:
                with open(os.path.join(folder, "screenshot.png"), "wb") as f:
                    f.write(r.content)
                artifacts_files.append("screenshot.png")
            else:
                print(f"⚠ screenshot indisponible (HTTP {r.status_code})", file=sys.stderr)
        except Exception as e:
            print(f"⚠ screenshot échoué ({type(e).__name__})", file=sys.stderr)

    # optional live .onion capture
    onion_status = None
    if args.onion:
        pu = rec.get("post_url") or ""
        if ".onion" in pu:
            onion_status = capture_onion(pu, os.path.join(folder, "onion_post.txt"))
            if onion_status is None:
                artifacts_files.append("onion_post.txt")
            else:
                print(f"⚠ capture .onion : {onion_status}", file=sys.stderr)
        else:
            onion_status = "pas d'URL .onion dans l'enregistrement"

    # manifest
    manifest_path = os.path.join(folder, "MANIFEST.sha256")
    artifacts = []
    with open(manifest_path, "w") as f:
        for fn in artifacts_files:
            h = sha256_file(os.path.join(folder, fn))
            artifacts.append((fn, h))
            f.write(f"{h}  {fn}\n")

    # optional timestamp over the manifest
    ts_status = "non demandé (--timestamp)"
    if args.timestamp:
        ts_status = rfc3161_timestamp(manifest_path, os.path.join(folder, "timestamp.tsr"))
        if ts_status is None:
            print(f"✓ horodatage RFC 3161 obtenu ({TSA_URL})")
        else:
            print(f"⚠ {ts_status}", file=sys.stderr)

    write_dossier(os.path.join(folder, "dossier.md"), rec, folder, captured_at,
                  artifacts, ts_status if args.timestamp else "non demandé", onion_status)

    print(f"✓ Dossier de preuve : {folder}")
    for fn, h in artifacts:
        print(f"  {fn:<16} {h[:16]}…")
    print(f"  dossier.md       (chaîne de custody + note légale)")


if __name__ == "__main__":
    main()
