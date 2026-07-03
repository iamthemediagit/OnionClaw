# PRD — OnionClaw Watch

> Cascade : [IDEA](./IDEA.md) → **PRD** → [ARCHI](./ARCHI.md) → [TASKS](./TASKS.md)
> Statut : draft v0 · 2026-07-03

## 1. Problème / Solution

**Problème.** Les PME découvrent leurs fuites de données **trop tard** — souvent quand la donnée est déjà exploitée ou publiée sur un leak site. Or les délais légaux sont serrés : notification CNIL **72 h** (RGPD art. 33), reporting ANSSI **24 h** pour les entités NIS2. Les identifiants volés (stealer logs) sont exploités **en quelques heures**. Les outils du marché sont soit hors de prix (entreprise, 50 k$+/an), soit gratuits mais sans contexte métier ni accompagnement.

**Solution.** Une veille continue, abordable et **RGPD-first**, qui :
1. surveille les sources de fuite pertinentes (DLS ransomware, stealer logs, Telegram, forums) via agrégateurs ;
2. **matche** les découvertes contre l'inventaire d'actifs du client (domaines, emails, marques) ;
3. **alerte vite** (< 24-48 h) avec un rapport actionnable + triage analyste ;
4. **outille la conformité** (le client notifie CNIL/ANSSI, on lui fournit les éléments).

## 2. Avatar précis

**« Marc, RSSI-seul d'une PME industrielle de 60 personnes (UE). »**
- Pas de SOC, pas de temps pour du dark web à la main. Sous pression NIS2 depuis 2026.
- Craint l'amende RGPD et l'incident non détecté plus que le coût de l'outil.
- Décide ou co-décide un budget sécurité de quelques centaines d'€/mois sans validation lourde.
- Veut : une alerte claire, un interlocuteur qui comprend son métier, un rapport présentable au board.
- **Où le toucher** : réseau direct de Franck, LinkedIn (contenu NIS2/ransomware), partenaires MSP, événements sécu régionaux.

Variantes : DSI mutualisée multi-sites, dirigeant de TPE tech, DPO externe cherchant un fournisseur de preuve.

## 3. Niche

**Veille dark web RGPD-first pour PME UE.** Trois marqueurs de différenciation :
- **Hébergement + gouvernance UE** (data residency, conformité par défaut) — quasi absent chez les gros acteurs US.
- **PME-friendly** : prix, onboarding rapide, zéro jargon SOC.
- **Accompagnement humain** : triage analyste inclus, pas juste un feed brut.

## 4. Stratégie marketing

- **Positionnement** : « veille proactive de fuite de données » — **jamais** « intelligence pour law enforcement » ni « investigation criminelle ». Cadre défensif, conformité, sérénité.
- **Angle éditorial** : NIS2, obligations RGPD, cas ransomware sectoriels → contenu LinkedIn + articles.
- **Canaux** : (1) réseau et clients existants de Franck ; (2) revente via MSP/MSSP (phase 2) ; (3) inbound LinkedIn.
- **Pricing** : abonnement **200-500 €/mois par organisation** (par domaine / volume d'actifs surveillés). **Add-on triage analyste + rapport mensuel** en montée de gamme (400-800 €/mois). Canal MSSP : ~50 €/client revendu 200-300 €.
- **Preuve** : transparence sources + politique de rétention publiées ; 1 étude de cas pilote.

## 5. Features

| # | Feature | Priorité |
|---|---------|----------|
| F1 | Monitoring domaines / emails / marques du client | MVP |
| F2 | Alertes « victime ransomware » (surveillance DLS via agrégateurs) | MVP |
| F3 | Moteur de matching actifs client + dédup (pas d'alerte doublon) | MVP |
| F4 | Alerting email/webhook (+ Slack) | MVP |
| F5 | Investigation `.onion` ciblée à la demande (OnionClaw) | MVP (support) |
| F6 | Monitoring stealer logs / Telegram | v1 |
| F7 | Dashboard client (exposition, règles, historique) | v1 |
| F8 | Rapport mensuel board-ready (tendances, risk scoring) | v1 |
| F9 | Multi-tenant (isolation par client) | v1 |
| F10 | Alerte **prédictive** avant atterrissage sur DLS (patterns de ciblage) | v2 |
| F11 | Canal MSSP white-label | v2 |

## 6. MVP

**Objectif : 1 client pilote payant, veille continue + alerte < 48 h.**

Périmètre :
- Ingestion via **agrégateurs** (ransomware.live / ransomlook API) — pas de crawl `.onion` en continu.
- **Inventaire d'actifs** client (domaines, emails, nom de société).
- **Matching + dédup** → **alerte email** avec rapport + triage manuel de Franck.
- **Investigation `.onion` à la demande** via OnionClaw quand une piste le justifie.
- Socle légal en place : mandat + DPA + politique de rétention **métadonnées-only**.

Hors MVP : dashboard, Telegram, multi-tenant, prédictif (voir [TASKS](./TASKS.md)).

## 7. Killer feature (v2)

**Alerte prédictive** : anticiper le risque *avant* que la donnée n'atterrisse sur un DLS, à partir des patterns de ciblage des groupes ransomware (secteur, géographie, taille). Tous les outils PME sont réactifs — celui-ci préviendrait. Différenciation forte, à valider techniquement.

## 8. Cadre légal (intégré au produit, pas une annexe)

- **Mandat client écrit** par engagement : périmètre (domaines, marques, IP), fréquence, obligations de notification.
- **DPA (RGPD art. 28)** : base légale = **intérêt légitime** (art. 6-1-f), minimisation, rétention courte. Modèle HIBP.
- **Métadonnées-only** : jamais posséder/télécharger la donnée volée → évite le **recel** (art. 321-1 CP) et l'extraction frauduleuse (art. 323-3). Purge après notification.
- **Veille passive uniquement** : pas d'accès authentifié frauduleux, pas d'achat de données, pas de participation aux forums.
- **Répartition des rôles** : on est **processeur** ; **le client notifie CNIL (72 h) / ANSSI (NIS2, 24 h)**, on lui fournit les éléments.
- **Audit trail** complet + politique de confidentialité publiée.
