# ps_mem.py — Analyse mémoire Linux basée sur le PSS

`ps_mem.py` est un script Python conçu pour analyser avec précision la consommation mémoire réelle des processus Linux. Il exploite les informations fournies par le noyau via `/proc/<pid>/smaps` et, lorsque disponible, `/proc/<pid>/smaps_rollup`, afin de s’appuyer sur le **PSS (Proportional Set Size)**. Cette approche permet d’attribuer correctement la mémoire partagée et d’éviter toute double comptabilisation, contrairement aux métriques classiques basées sur le RSS.

Le script est particulièrement adapté aux environnements **PHP-FPM multi-pools**, en offrant une vision fiable de la consommation mémoire par programme, par PID ou par pool applicatif. Il constitue ainsi un outil pertinent pour le diagnostic, l’optimisation et le dimensionnement des services applicatifs.

---

## Prérequis

- Système Linux avec `/proc` monté
- Noyau exposant `/proc/<pid>/smaps` (et préférentiellement `/proc/<pid>/smaps_rollup`)
- Python ≥ 3.10
- Droits root pour une analyse complète du système
  (option `-p` utilisable sans privilèges root sur des PID accessibles)

---

## Options disponibles

### `--version`
Affiche la version du script.

### `-s, --split-args`
Sépare l’affichage par arguments complets de ligne de commande.
Les caractères de contrôle ou non ASCII sont échappés et la commande affichée
est limitée à 4 096 caractères afin de protéger les terminaux et les journaux.

### `-t, --total`
Affiche uniquement le total de mémoire utilisée (RAM).
Idéal pour les scripts automatisés, la supervision ou le monitoring.

### `-d, --discriminate-by-pid`
Affiche la consommation mémoire par PID au lieu de regrouper par programme.
Utile pour le debug avancé (ex. analyse de workers PHP individuels).

### `-S, --swap`
Affiche la consommation de Swap en plus de la RAM.
Permet de détecter rapidement un serveur qui commence à swaper.

### `-p <pid1,pid2,...>`
Limite l’analyse aux PID spécifiés.
Utile sans accès root ou pour un diagnostic ciblé.
Les PID doivent être des entiers décimaux ASCII strictement positifs ; les
doublons sont ignorés.

### `-w <N>`
Rafraîchit l’affichage toutes les `N` secondes (mode surveillance).
Idéal pour observer l’évolution mémoire en temps réel.

---

## Exemples d’utilisation

```bash
# Afficher la version du script
python3 ps_mem.py --version

# Affichage standard
python3 _mem_v4.py

# Mode surveillance (rafraîchissement toutes les 30 secondes)
python3 ps_mem.py -w 30

# Total mémoire uniquement (RAM)
python3 ps_mem.py -t

# Affichage RAM + Swap
python3 ps_mem.py -S

# Séparer l'affichage par arguments complets
python3 ps_mem.py -s

# Consommation mémoire par PID, filtrée sur PHP-FPM
python3 ps_mem.py -d | grep php-fpm

# Analyse mémoire par pool PHP-FPM
python3 ps_mem.py | grep 'php-fpm: pool'

# Analyse ciblée sur des PID spécifiques
python3 ps_mem.py -p 1234,5678

```
---

## Interprétation des résultats

Le script s’appuie sur les informations fournies par le noyau Linux via /proc/<pid>/smaps_rollup, qui expose une vue agrégée et fiable de la consommation mémoire par processus. L’analyse repose prioritairement sur le PSS (Proportional Set Size), représentant la part de mémoire réellement imputable à un processus, incluant une fraction équitable de la mémoire partagée.

La valeur RAM used correspond à Private + Shared. La mémoire Private représente la mémoire exclusivement utilisée par le processus et est calculée à partir des champs Private_Clean et Private_Dirty. La mémoire Shared correspond à la part de mémoire partagée réellement imputable au processus et est déterminée par la relation Shared = PSS − Private, ce qui évite toute double comptabilisation.

Les processus PHP-FPM sont regroupés par pool (via le process title php-fpm: pool <site>), offrant une vision mémoire précise par site applicatif. Les valeurs produites sont cohérentes avec des calculs manuels basés sur les champs Pss de smaps_rollup, ce qui rend les résultats directement exploitables pour le dimensionnement des services (PHP-FPM, conteneurs ou autres services applicatifs), là où des outils classiques comme ps ou top montrent leurs limites.

Pour éviter d'associer la mémoire d'un processus au nom d'un autre après une
réutilisation rapide de PID, le script compare le champ `starttime` de
`/proc/<pid>/stat` avant et après chaque collecte. Un PID disparu ou réutilisé
est ignoré ; lorsqu'il a été demandé avec `-p`, un diagnostic explicite est
écrit sur la sortie d'erreur.

## Licence

GNU Lesser General Public License v2.1 (LGPL-2.1)

Ce projet est une version modifiée, enrichie et modernisée de **ps_mem**
écrit à l’origine par Pádraig Brady.
https://github.com/pixelb/ps_mem

---
