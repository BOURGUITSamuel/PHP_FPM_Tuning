# ps_mem.py — Analyse mémoire Linux basée sur le PSS

`ps_mem.py` 4.7 estime la mémoire imputable aux processus Linux à partir des
données du noyau exposées dans `/proc/<pid>/smaps_rollup` ou
`/proc/<pid>/smaps`. Le calcul utilise prioritairement le **PSS**
(*Proportional Set Size*) afin de répartir la mémoire partagée et de limiter
son double comptage.

Le script est orienté vers l’exploitation d’Apache et de PHP-FPM. Il peut
regrouper les processus par programme, distinguer chaque PID et conserver les
titres de pools PHP-FPM lorsqu’ils sont exposés par les processus.

## Périmètre analysé

Sans option `-p`, le script retient uniquement les processus dont le nom court
ou le nom de l’exécutable contient l’un des mots-clés suivants :
`apache`, `httpd`, `php` ou `php-fpm`.

Avec `-p`, ce filtre est désactivé et tout PID accessible peut être analysé.
Les totaux affichés concernent donc uniquement les processus sélectionnés ;
ils ne représentent pas la mémoire totale ni le swap total du serveur.

## Prérequis

- Linux avec `/proc` monté ;
- Python 3.10 ou version ultérieure ;
- `/proc/<pid>/stat` lisible pour contrôler l’identité du processus ;
- `/proc/<pid>/smaps_rollup` ou `/proc/<pid>/smaps` lisible pour les processus
  analysés. Au moins une source de la collecte doit fournir le champ `Pss:`.

Le balayage automatique sans `-p` exige les privilèges root. Sans root, il
faut utiliser `-p` avec des PID dont les entrées `/proc` sont accessibles.

## Options

| Option | Comportement |
|---|---|
| `-h`, `--help` | Affiche l’aide et quitte. |
| `--version` | Affiche la version du script et quitte. |
| `-s`, `--split-args` | Distingue les processus selon leur ligne de commande complète. Les titres `php-fpm: ...` restent conservés pour le regroupement par pool. |
| `-t`, `--total` | Affiche uniquement le total RAM. Avec `-S`, affiche uniquement le total du swap. |
| `-d`, `--discriminate-by-pid` | Ajoute le PID au nom affiché afin de séparer les processus d’un même programme ou pool. |
| `-S`, `--swap` | Ajoute le swap au tableau. Le script utilise `SwapPss` lorsqu’il est disponible, sinon `Swap`. |
| `-p <pid1,pid2,...>` | Analyse les PID indiqués et désactive le filtre Apache/PHP. Les PID doivent être des entiers décimaux ASCII strictement positifs ; les doublons sont ignorés. |
| `-w <N>` | Répète la collecte après chaque intervalle de `N` secondes. `N` doit être un entier strictement positif ; `Ctrl+C` arrête la surveillance. |

L’intervalle du mode `-w` s’ajoute au temps nécessaire à chaque collecte.
Les relevés horodatés sont ajoutés à la sortie sans effacer les précédents.

## Exemples d’utilisation

Les commandes sans `-p` doivent être exécutées avec les privilèges root,
directement ou avec `sudo`.

```bash
# Afficher la version et l’aide
python3 ps_mem.py --version
python3 ps_mem.py --help

# Affichage standard des services Apache/PHP ciblés
sudo python3 ps_mem.py

# Total RAM des processus sélectionnés
sudo python3 ps_mem.py -t

# Détail RAM et swap
sudo python3 ps_mem.py -S

# Total du swap uniquement
sudo python3 ps_mem.py -t -S

# Regrouper selon la ligne de commande complète
sudo python3 ps_mem.py -s

# Distinguer chaque processus par PID
sudo python3 ps_mem.py -d

# Surveiller toutes les 30 secondes
sudo python3 ps_mem.py -w 30

# Analyser des PID spécifiques accessibles
python3 ps_mem.py -p 1234,5678

# Afficher uniquement les pools PHP-FPM détectés
sudo python3 ps_mem.py | grep 'php-fpm: pool'
```

Avant d’utiliser une substitution de commande avec `-p`, vérifier qu’elle a
retourné au moins un PID. Une valeur vide est volontairement rejetée.

## Sources et calculs mémoire

Pour chaque PID, le script essaie d’abord d’ouvrir `smaps_rollup`, puis se
replie sur `smaps` si le premier fichier est absent ou inaccessible. Si aucune
ligne `Pss:` n’est observée parmi l’ensemble des PID lisibles, le script refuse
d’afficher les résultats.

Les valeurs reconnues doivent être des entiers décimaux non signés exprimés
en `kB`. Une ligne malformée pendant la collecte principale entraîne
l’exclusion du PID. Pendant la passe complémentaire `Shared_Hugetlb`, elle
provoque seulement l’abandon de l’estimation précise pour ce PID ; les données
principales restent comptabilisées avec l’heuristique de repli.

Les valeurs sont regroupées par commande selon les formules suivantes :

```text
private_base =
    le champ historique Private s’il est présent,
    sinon Private_Clean + Private_Dirty

Private =
    somme(private_base) + somme(Private_Hugetlb)

RAM used =
    max(
        somme(Pss)
        + somme(Private_Hugetlb)
        + estimation de Shared_Hugetlb,
        Private
    )

Shared affiché =
    RAM used - Private
```

`Shared` est une valeur dérivée pour l’affichage. Elle ne correspond pas
directement à `Shared_Clean + Shared_Dirty` et n’est pas toujours égale à
`PSS - Private`.

### HugeTLB

Les compteurs `Private_Hugetlb` et `Shared_Hugetlb` sont traités séparément,
car le noyau ne les inclut pas dans les valeurs classiques de PSS et de
mémoire privée. Pour `Shared_Hugetlb`, le script conserve d’abord le maximum
observé par groupe, puis tente une seconde lecture de `smaps` afin de
dédupliquer les segments et d’en calculer une répartition de type PSS.

Le résultat conserve la plus grande valeur entre le maximum initial et cette
répartition. Cette heuristique limite certains doubles comptages, mais ne
garantit pas une attribution exacte entre plusieurs groupes de commandes :
elle peut sous-estimer ou surévaluer `Shared_Hugetlb` selon les mappings
disponibles. Un avertissement est émis lorsque la passe complémentaire échoue
pour certains PID.

### Swap

Pour chaque PID, `SwapPss` est utilisé lorsqu’il est disponible ; sinon le
script utilise `Swap`. Ce repli est moins précis pour les pages de swap
partagées et doit être considéré comme une approximation.

Avec `-S`, le tableau contient la RAM et le swap. Avec `-t -S`, seule la somme
du swap des processus sélectionnés est écrite.

## Regroupement PHP-FPM

Le script conserve un titre commençant par `php-fpm:` tel que
`php-fpm: pool exemple`, puis regroupe les titres identiques. Ce comportement
dépend du titre réellement exposé par PHP-FPM ; le script ne lit pas la
configuration des pools et un pool ne correspond pas nécessairement à un
site.

L’option `-s` préserve ces titres. L’option `-d` ajoute le PID et sépare donc
les processus de travail.

## Sécurité et robustesse

- Les noms de commande sont échappés avant affichage et limités à
  4 096 caractères dans tous les modes.
- Le champ `starttime` de `/proc/<pid>/stat` est comparé avant et après la
  collecte afin d’ignorer les PID disparus ou réutilisés.
- Les valeurs mémoire malformées, négatives ou exprimées dans une autre unité
  que `kB` sont rejetées.
- Les erreurs système inattendues et les erreurs de programmation ne sont pas
  masquées.
- Le script lit `/proc` sans modifier les processus analysés.

Les erreurs attendues restent limitées au PID concerné. Avec `-p`, les PID
refusés, disparus, réutilisés ou invalides sont signalés sur `stderr` lorsque
la collecte peut continuer. Les résultats peuvent donc être partiels si
certains PID ne sont pas lisibles.

## Sorties et codes de retour

Chaque collecte commence par un horodatage. Lorsque la sortie standard
(`stdout`) est redirigée, l’horodatage est envoyé sur `stderr`, ce qui permet
notamment à `-t` de conserver une valeur unique sur `stdout`.

| Code | Signification |
|---:|---|
| `0` | Exécution terminée avec succès, ou aucun processus correspondant. |
| `1` | Privilèges root absents lors d’une exécution sans `-p`. |
| `2` | Arguments invalides, candidats présents mais tous illisibles, ou PSS indisponible. |

Une erreur système inattendue ou une erreur de programmation interrompt le
script avec un code non nul. En mode `-w`, les absences temporaires, les
problèmes de lecture récupérables et l’absence de PSS provoquent une nouvelle
tentative après l’intervalle demandé.

## Limites connues

- Les résultats constituent un instantané et peuvent évoluer immédiatement
  après la collecte.
- Le repli vers `smaps` peut être plus coûteux que `smaps_rollup` sur un
  processus possédant beaucoup de mappings.
- L’heuristique `Shared_Hugetlb` peut sous-estimer ou surévaluer l’attribution
  entre groupes de commandes.
- Le regroupement PHP-FPM dépend des titres réellement publiés par les
  processus.
- Les totaux restent limités au périmètre sélectionné.

## Licence

Ce projet est distribué sous la
[GNU Lesser General Public License version 2.1 ou ultérieure](LICENSE.txt)
(`LGPL-2.1-or-later`).

Il s’agit d’une version modifiée et modernisée de
[`ps_mem`](https://github.com/pixelb/ps_mem), écrit à l’origine par
Pádraig Brady.
