# ARCHI — OnionClaw Watch

> Cascade : [IDEA](./IDEA.md) → [PRD](./PRD.md) → **ARCHI** → [TASKS](./TASKS.md)
> Statut : draft v0 · 2026-07-03

## Principe directeur

La **veille continue** repose sur les **agrégateurs + Telegram**, pas sur le crawl `.onion` direct.
Raisons (issues de l'exploration) : miroirs de leak sites instables (rotation quotidienne), ~1 500 IP de sortie Tor bloquées par Cloudflare/DDoS-Guard, exposition légale accrue si on télécharge la donnée. Les agrégateurs gèrent la découverte de miroirs et la dédup, et réduisent le risque juridique.
**OnionClaw reste la brique d'investigation `.onion` ciblée, à la demande.**

## Pipeline cible

```
Sources                     Traitement                    Sortie
────────────────────────    ──────────────────────────    ─────────────────
Agrégateurs DLS         ┐
 · ransomware.live API  │
 · ransomlook API       ├─► Ingestion ─► Parser/NER ─► Matching ─► Dédup ─► Storage ─► Alerting
 · dls-monitor (UE)     │   (clients    (spaCy +      (vs actifs  (MinHash  (PG +      (email/
Telegram monitoring     ┘    API/bot)    regex)        client,     LSH)      ES)        webhook/
 · canaux stealer logs                                 ES query)                        Slack)
                                                          │                                │
OnionClaw (investigation ciblée .onion, à la demande) ◄───┘                                ▼
 · pipeline.py / SICRY, sorties STIX/MISP                                          Rapport + triage
```

## Quels tools / librairies ?

**Réutilisé (existant, ne pas réinventer)**
- `sicry.py` — moteur SICRY : `search()`, `scrape_all()`, `fetch()`, `to_stix()`, `to_misp()`, `to_csv()`.
- `pipeline.py` — pipeline 7 étapes + **watch system** (`--watch` / `--interval` / `--watch-daemon` / `--daemon-poll`) : base du scheduler.
- Accès Tor : `requests[socks]`, `stem` (rotation circuits), SOCKS5 9050 / control 9051, TorPool.
- Parsing : `beautifulsoup4`.

### Séquençage des sources (décision — commencer par le gratuit, sans Tor)

| Ordre | Source | Feature | Coût | Tor | Statut |
|---|---|---|---|---|---|
| 1 | **ransomware.live** (API) | F2 victime ransomware | gratuit | non | **implémenté** (`watch_ransomware.py`) |
| 2 | **Hudson Rock Cavalier** (API) | F1 exposition infostealer/credentials par domaine | gratuit | non | à faire (Lot 1) |
| 3 | **HIBP** domain monitoring | F1 emails du domaine compromis | ⚠️ gratuit = self-service client uniquement ; usage tiers = Pro 379 $/mois | non | phase 2 (onboarding ou Pro) |
| 4 | **Telegram** (stealer logs frais) | F6 | moyen | non | v1 |
| 5 | **ransomlook / dls-monitor** (UE) | F2 (redondance/UE) | gratuit | non | v1 |
| 6 | **OnionClaw `.onion`** | F5 investigation ciblée | Tor | **oui** | à la demande, après un hit |

→ Les 3 premières sources (gratuites, sans Tor) couvrent ~80 % du MVP. Le crawl `.onion` n'intervient qu'en investigation après un match.

**À ajouter**
- **Clients agrégateurs** : wrappers HTTP REST pour ransomware.live *(fait)* / Hudson Rock / HIBP, puis ransomlook / dls-monitor.
- **Telegram** : bot API (monitoring de canaux par mots-clés : domaines, emails, marques client).
- **NER / matching** : `spaCy` (entités : emails, domaines, personnes) + regex ciblées.
- **Recherche / matching** : **Elasticsearch** (index des actifs client + full-text sur métadonnées ingérées).
- **Dédup** : `datasketch` (MinHash LSH) pour le sprawl de miroirs + hash SHA-256 pour l'exact.
- **Stockage** : **PostgreSQL** (données structurées : clients, actifs, alertes, audit) + Elasticsearch (recherche).
- **API / orchestration** : **FastAPI** (couche service, endpoints, auth).
- **Alerting** : SMTP / webhooks / Slack.

## Comment réaliser les features

| Feature (PRD) | Composant | Réutilise |
|---|---|---|
| F1 monitoring domaines/emails/marques | modèle « actifs client » (PG) + index ES | — (nouveau) |
| F2 alertes ransomware DLS | clients agrégateurs → ingestion | — |
| F3 matching + dédup | NER + ES query + MinHash LSH | — |
| F4 alerting | dispatcher SMTP/webhook/Slack | — |
| F5 investigation `.onion` | appel OnionClaw à la demande | `pipeline.py`, `sicry.to_stix/misp` |
| F6 Telegram / stealer logs | bot Telegram + parser | — |
| scheduler récurrent | scheduler multi-tenant | **`pipeline.py` watch** (`--watch`/`--interval`/`--daemon-poll`) |
| F9 multi-tenant | isolation par client (schéma PG + namespace ES) | remplace le SQLite mono-opérateur actuel |
| audit / rétention | table audit PG + purge planifiée | — |

## Dépendances

- **Externes** : API ransomware.live / ransomlook / dls-monitor ; Telegram Bot API ; fournisseur SMTP.
- **Tor** : requis **uniquement** pour l'investigation `.onion` (pas la veille continue).
- **Infra** : hébergement **UE** (RGPD data residency) ; PostgreSQL + Elasticsearch managés UE.
- **LLM** : provider déjà branché dans OnionClaw (`ask.py`) pour la synthèse de rapports (mode `corporate`/`ransomware`).

## Gaps à combler (état actuel → cible)

| Brique | Actuel (v2.1.13) | Cible |
|---|---|---|
| Détection de fuite | recherche brute | matching PII/domaines vs inventaire client |
| Multi-tenant | SQLite mono-opérateur | isolation par client (PG + ES) |
| Alerting | fichiers JSON locaux | email/webhook/Slack |
| Dédup | texte brut | MinHash LSH + hash |
| Audit / rétention | néant | logs RGPD + purge après notification |
| Sources veille | 12 moteurs `.onion` | agrégateurs + Telegram (+ `.onion` à la demande) |

## Contraintes de conception liées au légal

- **Métadonnées-only** au niveau du stockage : le schéma PG ne stocke **pas** de mots de passe en clair ni de dumps — seulement source, date, type de données, actif client concerné.
- **Rétention courte** : purge automatique post-notification (job planifié).
- **Audit trail** : toute recherche / match / suppression loggée (qui, quand, quoi).
