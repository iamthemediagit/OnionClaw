# IDEA — OnionClaw Watch

> Cascade : **IDEA** → [PRD](./PRD.md) → [ARCHI](./ARCHI.md) → [TASKS](./TASKS.md)
> Statut : draft v0 · 2026-07-03

## Quel est le projet ?

**OnionClaw Watch** — une plateforme de **veille dark web « breach-notification-as-a-service »** pour PME européennes.

On surveille en continu les sources de fuites (leak sites ransomware, stealer logs, canaux Telegram, forums) pour détecter l'exposition des données d'un client — identifiants, dumps, mention de la société comme victime — et on **l'avise vite**, avec un rapport actionnable.

Le socle existe déjà : OnionClaw (moteur SICRY + pipeline Robin) donne l'accès Tor et l'investigation `.onion`. Le produit ajoute la couche qui manque : **veille continue via agrégateurs, matching des actifs client, alerting, conformité RGPD**.

## Pour qui ?

- **Cœur de cible** : PME UE de 10 à 100 personnes, sans SOC interne, avec un RSSI seul / une DSI mutualisée / un dirigeant responsable de fait de la sécurité.
- **Phase 2** : MSSP / MSP qui veulent une couche dark web white-label pour leur portefeuille de clients.
- **Non-cible** : grands comptes déjà équipés (Recorded Future, ZeroFox…) et le grand public (HIBP suffit).

## Pourquoi le faire ?

1. **Marché porteur** — veille dark web ~1,2-1,5 Md$ (2025) → 4-5 Md$ (2033), UE +19 % YoY. Tiré par l'explosion ransomware (+30 % de victimes sur DLS), les amendes RGPD (4,2 Md€ en 2024) et **NIS2** (transposition FR attendue 2026 → reporting incident 24 h à l'ANSSI).
2. **Gap réel** — le haut de gamme est saturé et hors de prix pour une PME (50-500 k$/an) ; les outils gratuits n'ont pas de contexte métier. Aucun acteur majeur ne revendique un positionnement **RGPD-first / hébergement UE**. C'est la niche.
3. **Asset existant** — OnionClaw / SICRY est déjà opérationnel (accès Tor, 12 moteurs, sorties STIX/MISP, embryon de watch en `pipeline.py`). On capitalise, on ne repart pas de zéro.
4. **Avantage fondateur** — double profil ingénierie + direction : permet d'offrir le **triage analyste + rapport board-ready** que les feeds bruts (commodité) ne fournissent pas. C'est la différenciation.

## Principe non négociable

Veille **passive** et **métadonnées-only** : on ne télécharge jamais la donnée volée, on n'achète rien, on ne participe pas aux forums. Chaque mission repose sur un **mandat client écrit + DPA (intérêt légitime RGPD)**. C'est à la fois la contrainte légale (éviter le recel, art. 321-1 CP) et l'argument de vente (rassurer DPO / RSSI).

## Cœur technique (décision)

La veille continue s'appuie sur les **agrégateurs (ransomware.live, ransomlook API) + monitoring Telegram**, **pas** sur le crawl `.onion` direct (miroirs instables, IP Tor bloquées, exposition légale accrue). OnionClaw reste la **brique d'investigation ciblée** à la demande. Détail dans [ARCHI](./ARCHI.md).
