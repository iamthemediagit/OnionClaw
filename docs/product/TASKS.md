# TASKS — OnionClaw Watch

> Cascade : [IDEA](./IDEA.md) → [PRD](./PRD.md) → [ARCHI](./ARCHI.md) → **TASKS**
> Statut : draft v0 · 2026-07-03
> Format : `[ ] Titre` — **Done :** critère · **Dép :** dépendances

## Lot 0 — Socle légal (bloquant, avant toute veille)

- [ ] **Template mandat client** — **Done :** doc signable (périmètre : domaines/marques/IP, fréquence, obligations notif) validé. · **Dép :** —
- [ ] **DPA RGPD (art. 28)** — **Done :** DPA type, base = intérêt légitime, minimisation, rétention. · **Dép :** —
- [ ] **Politique de rétention « métadonnées-only »** — **Done :** règles écrites (quoi stocker / jamais stocker / durée / purge). · **Dép :** —
- [ ] **Politique de confidentialité + note sources** — **Done :** page publique (sources, base légale, rétention). · **Dép :** DPA
- [ ] **Test balancing intérêt légitime documenté** — **Done :** LIA écrite (intérêt / nécessité / proportionnalité). · **Dép :** DPA

## Lot 1 — MVP (1 pilote payant, alerte < 48 h)

- [x] **Connecteur ransomware.live** — **Done :** poll API + matching actifs client + dédup + alerte email. · **Fait :** `watch_ransomware.py` + `clients.example.json`
- [x] **Connecteur Hudson Rock (Cavalier)** — **Done :** lookup exposition infostealer par domaine + dédup (nouvelle exposition) + alerte email, métadonnées-only. · **Fait :** `watch_hudsonrock.py` (⏳ test live en attente de la clé API)
- [~] **HIBP — PAS de connecteur au MVP (bloqué CGU).** Le gratuit (Pwned 0, ≤10 adresses) interdit l'usage « au bénéfice d'un tiers » ; surveiller les domaines clients = tier **Pro 379 $/mois**. `breachedDomain` API = clé payante. → Reporté phase 2, deux voies : (a) **onboarding** — le client vérifie *son* domaine et active *ses* notifs gratuites (CGU-clean, la vérif = preuve de mandat) ; (b) **Pro** une fois le revenu suffisant. · Réf. [Terms of Use](https://haveibeenpwned.com/TermsOfUse), [Subscription](https://haveibeenpwned.com/Subscription)
- [ ] **Modèle « actifs client »** — **Done :** passer de `clients.json` à un stockage structuré (PostgreSQL) + CRUD. · **Dép :** connecteurs
- [ ] **Index Elasticsearch actifs + métadonnées** — **Done :** index + requête de matching (remplace le matching substring actuel). · **Dép :** modèle actifs
- [ ] **Moteur de matching enrichi** — **Done :** NER (spaCy) + regex en plus du substring naïf actuel. · **Dép :** index ES
- [ ] **Dédup robuste** — **Done :** MinHash LSH + hash SHA-256 (au-delà du state file JSON actuel). · **Dép :** matching
- [ ] **Alerting** — **Done :** email fait ; ajouter webhook. · **Fait (email) :** `watch_ransomware.py`
- [ ] **Scheduler récurrent** — **Done :** cron OK pour MVP ; industrialiser via `pipeline.py` watch (`--interval`/`--daemon-poll`). · **Dép :** connecteurs
- [x] **Outil de découverte / prospection** — **Done :** listing des dernières fuites entreprises (filtres pays/secteur/groupe, table/json/csv), FR par défaut. · **Fait :** `list_leaks.py`
- [x] **Dossier de preuve (proof-of-compromise)** — **Done :** capture preuve publiée par l'attaquant (screenshot + métadonnées + option `.onion` live), SHA-256, horodatage RFC 3161, chaîne de custody ISO 27037, note légale FR (eIDAS/constat), + **identifiants de propagation** (magnet/infohash, hashes publiés, listing fichiers) pour tracer le dump ailleurs sans le télécharger. Métadonnées-only. · **Fait :** `evidence.py`
- [ ] **Investigation `.onion` à la demande** — **Done :** appel OnionClaw (`pipeline.py`) + sortie STIX/MISP intégrée au rapport. · **Dép :** —
- [ ] **Audit trail (PG)** — **Done :** table audit (recherche/match/suppression : qui/quand/quoi). · **Dép :** modèle actifs
- [ ] **Purge post-notification** — **Done :** job planifié appliquant la politique de rétention. · **Dép :** politique rétention (Lot 0)
- [ ] **Onboarding pilote** — **Done :** 1 client réel, mandat + DPA signés, veille active, 1 alerte de test validée. · **Dép :** tout Lot 1 + Lot 0

## Lot 2 — v1 (industrialisation)

- [ ] **Monitoring Telegram (stealer logs)** — **Done :** bot surveille N canaux par mots-clés client. · **Dép :** matching
- [ ] **Multi-tenant** — **Done :** isolation par client (schéma PG + namespace ES) ; remplace SQLite mono-opérateur. · **Dép :** modèle actifs, audit
- [ ] **Dashboard client** — **Done :** UI exposition + règles + historique d'alertes. · **Dép :** multi-tenant, API (FastAPI)
- [ ] **Couche API (FastAPI)** — **Done :** endpoints auth + gestion actifs/alertes. · **Dép :** modèle actifs
- [ ] **Rapport mensuel board-ready** — **Done :** génération auto (tendances + risk scoring) via LLM (`ask.py`). · **Dép :** storage alertes
- [ ] **Webhook / Slack** — **Done :** canaux d'alerte additionnels. · **Dép :** alerting email

## Lot 3 — v2 (différenciation)

- [ ] **Alerte prédictive** — **Done :** modèle de risque pré-DLS (patterns ciblage : secteur/géo/taille), POC validé. · **Dép :** historique DLS, storage
- [ ] **Canal MSSP white-label** — **Done :** multi-tenant + branding revendeur + pricing par client. · **Dép :** multi-tenant, dashboard
- [ ] **dls-monitor (source UE)** — **Done :** 3e source agrégateur intégrée. · **Dép :** clients API

## Traçabilité PRD → TASKS

| Feature PRD | Lot |
|---|---|
| F1, F2, F3, F4, F5 | Lot 1 (MVP) |
| F6, F7, F8, F9 | Lot 2 (v1) |
| F10, F11 | Lot 3 (v2) |
| Cadre légal §8 | Lot 0 |
