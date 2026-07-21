#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ps_mem.py — Analyse optimisée de l’usage mémoire sous Linux (Ubuntu)

Auteur : jsbourguit (script original de Pádraig Brady)
Version : 4.6
Compatibilité : Python >= 3.10
Licence : LGPLv2

Description :
    Outil d’analyse permettant d’afficher la consommation mémoire réelle
    des processus Linux, regroupée par programme, par PID ou par pool PHP-FPM
    selon les options utilisées.
    Le calcul repose sur les informations fournies par /proc/<pid>/smaps*
    (prioritairement smaps_rollup lorsqu’il est disponible), en s’appuyant
    sur le PSS (Proportional Set Size) afin d’obtenir une estimation fiable
    de la RAM réellement consommée par les processus.
    L’agrégation est totalisable lorsque le PSS est disponible, garantissant
    des résultats cohérents en environnement de production.

Améliorations de cette version :
    - Alignement sur la logique du script ps_mem original :
        la colonne « RAM used » correspond à Private + Shared, avec
        une utilisation préférentielle du champ Pss lorsque le kernel
        le fournit, garantissant un total cohérent et exploitable.

    - Optimisation du calcul mémoire :
        agrégation contrôlée des HugePages (Private_Hugetlb / Shared_Hugetlb)
        afin d’éviter tout double comptage et sous-estimation.

    - Support explicite et correct de smaps_rollup :
        lecture directe des champs Pss, Private_* et HugeTLB associe,
        réduisant la charge CPU et améliorant les performances
        sur serveurs à forte volumétrie de processus.

    - Regroupement fiable des processus PHP-FPM par pool / site :
        les intitulés de type « php-fpm: pool <site> » sont conservés
        tels quels afin de fournir une vue mémoire par site applicatif,
        ce qui n’est pas possible avec les outils standards (ps, top).

    - Filtrage intelligent des processus cibles :
        limitation optionnelle à certains services (apache, httpd, php, php-fpm)
        pour une analyse orientée exploitation web.

    - Gestion robuste des processus éphémères :
        l'identité issue de /proc/<pid>/stat est contrôlée avant et après
        la collecte pour ignorer les PID disparus ou réutilisés.

    - Clarification du comportement des options :
        l’option -t -S affiche exclusivement le total du Swap,
        avec utilisation prioritaire de SwapPss lorsque disponible.

    - Meilleure gestion des permissions :
        distinction explicite entre PID inexistants, non lisibles
        et accès refusés à smaps, avec messages d’erreur clairs.

    - Code modernisé et documenté :
        annotations de types, commentaires explicatifs et
        structure lisible facilitant la maintenance et l’évolution
        future du script.
"""

import argparse
from dataclasses import dataclass
import errno
import os
import sys
import time
from typing import Dict, List, Set, Tuple

__version__ = "4.6"

OUR_PID = os.getpid()

TARGET_KEYWORDS = ("apache", "httpd", "php", "php-fpm")
MAX_COMMAND_CHARS = 4096
MAX_PROC_STAT_CHARS = 4096
PROC_STAT_STARTTIME_INDEX = 22 - 3  # Champs 3+ après la parenthèse de comm.

SegmentKey = Tuple[str, str, str, str, int]


def std_exceptions(exc_type, value, tb):
    sys.excepthook = sys.__excepthook__
    if issubclass(exc_type, (KeyboardInterrupt, BrokenPipeError)):
        return
    sys.__excepthook__(exc_type, value, tb)


sys.excepthook = std_exceptions


class Unbuffered:
    def __init__(self, stream):
        self.stream = stream

    def write(self, data: str) -> None:
        self.stream.write(data)
        self.stream.flush()

    def flush(self) -> None:
        try:
            self.stream.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        try:
            return self.stream.isatty()
        except Exception:
            return False

    def close(self) -> None:
        try:
            self.stream.flush()
        except Exception:
            pass
        try:
            self.stream.close()
        except Exception:
            pass


class ProcLookupError(LookupError):
    def __init__(self, pid: int, entry: str):
        self.pid = pid
        self.entry = entry
        super().__init__(f"/proc/{pid}/{entry}" if entry else f"/proc/{pid}")


class ProcNotFound(ProcLookupError):
    pass


class ProcAccessDenied(ProcLookupError):
    pass


class Proc:
    def __init__(self):
        self.proc = "/proc"

    def path(self, *args: str | int) -> str:
        return os.path.join(self.proc, *(str(a) for a in args))

    def open(self, *args: str | int):
        try:
            return open(
                self.path(*args),
                encoding="utf-8",
                errors="surrogateescape",
                newline="",
            )
        except OSError as e:
            if args and isinstance(args[0], int):
                pid = int(args[0])
                entry = "/".join(str(a) for a in args[1:])
                if e.errno in (errno.ENOENT, errno.ESRCH):
                    raise ProcNotFound(pid, entry) from e
                if e.errno in (errno.EPERM, errno.EACCES):
                    raise ProcAccessDenied(pid, entry) from e
            raise


proc = Proc()


@dataclass
class MemoryUsageResult:
    sorted_cmds: List[Tuple[str, int]]
    privates: Dict[str, int]
    counts: Dict[str, int]
    total_ram_used: int
    swaps: Dict[str, int]
    total_swap: int
    matched_candidates_count: int
    matched_readable_count: int
    pss_seen_any: bool
    found_candidate_pids: set[int]
    found_readable_pids: set[int]
    found_access_denied_pids: set[int]
    found_missing_runtime_pids: set[int]


def parse_options() -> Tuple[bool, List[int], int | None, bool, bool, bool]:
    parser = argparse.ArgumentParser(description="Show per-program (and PHP-FPM pool) memory usage (PSS based).")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-s", "--split-args", action="store_true", help="Separate by full command line (not used for pools).")
    parser.add_argument("-t", "--total", dest="only_total", action="store_true", help="Show only total memory.")
    parser.add_argument("-d", "--discriminate-by-pid", action="store_true", help="Show by process instead of program.")
    parser.add_argument("-S", "--swap", dest="show_swap", action="store_true", help="Show swap usage (SwapPss if available).")
    parser.add_argument("-p", dest="pids", metavar="<pid>[,pid2,...]", help="Filter by PIDs.")
    parser.add_argument("-w", dest="watch", metavar="<N>", type=int, help="Refresh every N seconds.")
    args = parser.parse_args()

    pids_to_show: List[int] = []
    if args.pids is not None:
        try:
            pid_values = [value.strip() for value in args.pids.split(",")]
            if any(not value.isascii() or not value.isdecimal() for value in pid_values):
                raise ValueError
            parsed_pids = [int(value) for value in pid_values]
            if any(pid <= 0 for pid in parsed_pids):
                raise ValueError
            pids_to_show = list(dict.fromkeys(parsed_pids))
        except ValueError:
            parser.error("PIDs must be positive integers separated by commas.")

    if args.watch is not None and args.watch <= 0:
        parser.error("Seconds must be positive!")

    return args.split_args, pids_to_show, args.watch, args.only_total, args.discriminate_by_pid, args.show_swap


def get_mem_stats(pid: int) -> Tuple[int, int, int, int, int, bool]:
    """
    Retourne (private_base_kb, pss_kb, swap_kb, huge_priv_kb, huge_shared_kb, saw_pss_line)
    - private_base_kb: somme des Private_Clean/Private_Dirty (rollup) OU Private: (smaps)
    - pss_kb: somme des Pss:
    - swap_kb: SwapPss si dispo, sinon Swap
    - huge_priv_kb: Private_Hugetlb
    - huge_shared_kb: Shared_Hugetlb
    """
    private_base_kb = 0
    private_cd_kb = 0
    saw_private_total = False
    pss_kb = 0
    swap_kb = 0
    swap_sum_kb = 0
    swappss_sum_kb = 0
    huge_priv_kb = 0
    huge_shared_kb = 0
    saw_pss_line = False
    saw_swappss_line = False

    smaps_handle = None
    smaps_file_used = ""
    last_lookup_error: ProcLookupError | None = None
    for smaps_file in ("smaps_rollup", "smaps"):
        try:
            smaps_handle = proc.open(pid, smaps_file)
            smaps_file_used = smaps_file
            break
        except ProcAccessDenied as e:
            # Cause prioritaire si aucun fallback lisible n'est possible.
            last_lookup_error = e
            continue
        except ProcNotFound as e:
            if last_lookup_error is None:
                last_lookup_error = e
            continue
        except (FileNotFoundError, ProcessLookupError, OSError):
            continue

    if smaps_handle is None:
        if last_lookup_error is not None:
            raise last_lookup_error
        raise LookupError

    try:
        with smaps_handle as f:
            for line in f:
                # Private (rollup: Private_Clean/Dirty, smaps: Private:)
                if line.startswith("Private:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        private_base_kb += int(parts[1])
                        saw_private_total = True
                elif line.startswith(("Private_Clean:", "Private_Dirty:")):
                    parts = line.split()
                    if len(parts) >= 2:
                        private_cd_kb += int(parts[1])

                # HugeTLB (hugetlbfs) est historiquement exclu de RSS/PSS,
                # donc on le traite a part pour eviter de sous-compter.
                elif line.startswith("Private_Hugetlb:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        huge_priv_kb += int(parts[1])
                elif line.startswith("Shared_Hugetlb:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        huge_shared_kb += int(parts[1])

                # PSS
                elif line.startswith("Pss:"):
                    saw_pss_line = True
                    parts = line.split()
                    if len(parts) >= 2:
                        pss_kb += int(parts[1])

                # Swap
                elif line.startswith("SwapPss:"):
                    saw_swappss_line = True
                    parts = line.split()
                    if len(parts) >= 2:
                        swappss_sum_kb += int(parts[1])

                elif line.startswith("Swap:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        swap_sum_kb += int(parts[1])
    except ProcLookupError:
        raise
    except OSError as e:
        if e.errno in (errno.ENOENT, errno.ESRCH):
            raise ProcNotFound(pid, smaps_file_used or "smaps*") from e
        if e.errno in (errno.EPERM, errno.EACCES):
            raise ProcAccessDenied(pid, smaps_file_used or "smaps*") from e
        raise LookupError

    if not saw_private_total:
        private_base_kb = private_cd_kb

    swap_kb = swappss_sum_kb if saw_swappss_line else swap_sum_kb
    return private_base_kb, pss_kb, swap_kb, huge_priv_kb, huge_shared_kb, saw_pss_line


def get_cmd_name(pid: int, split_args: bool = False, discriminate_by_pid: bool = False) -> str:
    """
    Conserve le titre PHP-FPM (pool) si présent.
    Sinon, retombe sur l'exécutable.
    """
    try:
        with proc.open(pid, "cmdline") as f:
            raw = f.read(MAX_COMMAND_CHARS + 1)

        cmdline_truncated = len(raw) > MAX_COMMAND_CHARS
        raw = raw[:MAX_COMMAND_CHARS]
        first_arg_truncated = cmdline_truncated and "\0" not in raw

        cmdline0 = ""
        cmdline_full = ""
        if raw:
            parts = [p for p in raw.split("\0") if p]
            if parts:
                cmdline0 = parts[0]
                cmdline_full = " ".join(parts)

        # PHP-FPM: on garde le title complet pour regrouper par pool
        if cmdline0.startswith("php-fpm:"):
            cmd = cmdline0
            command_was_truncated = first_arg_truncated
        elif split_args and cmdline_full:
            cmd = cmdline_full
            command_was_truncated = cmdline_truncated
        else:
            command_was_truncated = False
            try:
                exe_target = os.readlink(proc.path(pid, "exe"))
                exe_target = exe_target.split("\0")[0]
                if exe_target:
                    cmd = os.path.basename(exe_target)
                elif cmdline0:
                    cmd = os.path.basename(cmdline0)
                    command_was_truncated = first_arg_truncated
                else:
                    cmd = f"proc-{pid}"
            except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                cmd = os.path.basename(cmdline0) if cmdline0 else f"proc-{pid}"
                command_was_truncated = bool(cmdline0) and first_arg_truncated

        if command_was_truncated:
            cmd = f"[truncated pid={pid}] {cmd}"
        if discriminate_by_pid:
            cmd = f"{cmd} [{pid}]"
        return cmd

    except (LookupError, FileNotFoundError, ProcessLookupError, OSError):
        return f"proc-{pid}"
    except Exception:
        return f"proc-{pid}"


def _fast_comm_name(pid: int) -> str:
    """Nom leger via /proc/<pid>/comm (peu couteux)."""
    try:
        with proc.open(pid, "comm") as f:
            comm = f.read().strip().split("\0")[0]
            if comm:
                return comm
    except (LookupError, FileNotFoundError, ProcessLookupError, OSError):
        pass
    return ""


def _fast_exe_name(pid: int) -> str:
    """Nom de binaire via basename(/proc/<pid>/exe)."""
    try:
        exe_target = os.readlink(proc.path(pid, "exe"))
        exe_target = exe_target.split("\0")[0]
        if exe_target:
            return os.path.basename(exe_target)
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        pass

    return ""


def _matches_target_keywords_fast(pid: int) -> bool:
    # 1) Essai ultra-leger via comm.
    comm_name = _fast_comm_name(pid).lower()
    if comm_name and any(keyword in comm_name for keyword in TARGET_KEYWORDS):
        return True

    # 2) Fallback sur basename de l'exe, utile si comm est tronque.
    exe_name = _fast_exe_name(pid).lower()
    if exe_name and any(keyword in exe_name for keyword in TARGET_KEYWORDS):
        return True

    return False


def human(kb: float) -> str:
    units = ["KiB", "MiB", "GiB", "TiB"]
    v = float(kb)
    for u in units:
        if v < 1024:
            return f"{v:.1f} {u}"
        v /= 1024
    return f"{v:.1f} PiB"


def safe_command_text(command: str) -> str:
    """Retourne une représentation ASCII sûre et bornée pour l'affichage."""
    safe_command = ascii(command)[1:-1]
    if len(safe_command) > MAX_COMMAND_CHARS:
        safe_command = f"{safe_command[:MAX_COMMAND_CHARS - 3]}..."
    return safe_command


def cmd_with_count(cmd: str, count: int) -> str:
    safe_cmd = safe_command_text(cmd)
    return f"{safe_cmd} ({count})" if count > 1 else safe_cmd


def _is_smaps_mapping_header(line: str) -> bool:
    parts = line.split(None, 5)
    if len(parts) < 5:
        return False
    return parts[0].count("-") == 1


def _segment_key_from_smaps_header(line: str) -> SegmentKey:
    """
    Cle stable inter-process pour approximer un segment partage :
    (dev, inode, offset, pathname, mapping_len_kb)
    """
    parts = line.strip().split(None, 5)
    addr = parts[0]
    offset = parts[2]
    dev = parts[3]
    inode = parts[4]
    pathname = parts[5] if len(parts) >= 6 else ""
    try:
        start_hex, end_hex = addr.split("-", 1)
        mapping_len_kb = max(0, (int(end_hex, 16) - int(start_hex, 16)) // 1024)
    except Exception:
        mapping_len_kb = 0
    return dev, inode, offset, pathname, mapping_len_kb


def _record_shared_hugetlb_segment(
    segments: Dict[SegmentKey, int],
    key: SegmentKey | None,
    size_kb: int,
) -> None:
    if key is not None and size_kb > segments.get(key, 0):
        segments[key] = size_kb


def estimate_shared_hugetlb_pss_like(
    pid_to_cmd: Dict[int, str],
    pid_starttimes: Dict[int, int],
    candidate_pids: Set[int],
) -> Tuple[Dict[str, int], int]:
    """
    Estime Shared_Hugetlb par commande via une repartition "pss-like":
    - lecture de /proc/<pid>/smaps pour les seuls PID candidats
    - validation de l'identite du PID avant et apres chaque lecture
    - deduplication des segments partages via cle de segment
    - repartition de chaque segment selon le nb de mappeurs par commande

    Retourne ({cmd: kb}, failed_pid_count).
    """
    segment_sizes: Dict[SegmentKey, int] = {}
    segment_mappers: Dict[SegmentKey, Set[int]] = {}
    failed_pid_count = 0

    for pid in candidate_pids:
        expected_starttime = pid_starttimes.get(pid)
        if expected_starttime is None:
            failed_pid_count += 1
            continue

        pid_segments: Dict[SegmentKey, int] = {}
        current_key: SegmentKey | None = None
        current_shared_huge_kb = 0
        try:
            _, starttime_before = get_process_identity(pid)
            if starttime_before != expected_starttime:
                failed_pid_count += 1
                continue

            with proc.open(pid, "smaps") as f:
                for line in f:
                    if _is_smaps_mapping_header(line):
                        _record_shared_hugetlb_segment(pid_segments, current_key, current_shared_huge_kb)
                        current_key = _segment_key_from_smaps_header(line)
                        current_shared_huge_kb = 0
                    elif line.startswith("Shared_Hugetlb:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            current_shared_huge_kb = int(parts[1])
                _record_shared_hugetlb_segment(pid_segments, current_key, current_shared_huge_kb)

            _, starttime_after = get_process_identity(pid)
        except (LookupError, FileNotFoundError, ProcessLookupError, OSError):
            failed_pid_count += 1
            continue
        except Exception:
            failed_pid_count += 1
            continue

        if starttime_after != expected_starttime:
            failed_pid_count += 1
            continue

        for key, size_kb in pid_segments.items():
            segment_sizes[key] = max(segment_sizes.get(key, 0), size_kb)
            segment_mappers.setdefault(key, set()).add(pid)

    per_cmd_float: Dict[str, float] = {}
    for key, size_kb in segment_sizes.items():
        mappers = segment_mappers.get(key, set())
        if size_kb <= 0 or not mappers:
            continue

        total_mappers = len(mappers)
        if total_mappers == 0:
            continue

        cmd_mapper_counts: Dict[str, int] = {}
        for pid in mappers:
            cmd = pid_to_cmd.get(pid)
            if not cmd:
                continue
            cmd_mapper_counts[cmd] = cmd_mapper_counts.get(cmd, 0) + 1

        for cmd, mapper_count in cmd_mapper_counts.items():
            per_cmd_float[cmd] = per_cmd_float.get(cmd, 0.0) + (size_kb * mapper_count / total_mappers)

    per_cmd_kb = {cmd: int(round(val)) for cmd, val in per_cmd_float.items() if val > 0}
    return per_cmd_kb, failed_pid_count


def get_memory_usage(
    pids_to_show: List[int],
    split_args: bool,
    discriminate_by_pid: bool,
) -> MemoryUsageResult:
    """
    Retourne une structure agregee de consommation memoire.
    """
    psses: Dict[str, int] = {}
    private_bases: Dict[str, int] = {}
    huge_privs: Dict[str, int] = {}
    huge_shareds: Dict[str, int] = {}
    privates: Dict[str, int] = {}
    ram_useds: Dict[str, int] = {}
    counts: Dict[str, int] = {}
    swaps: Dict[str, int] = {}
    matched_candidates_count = 0
    matched_readable_count = 0
    pss_seen_any = False
    found_candidate_pids: set[int] = set()
    found_readable_pids: set[int] = set()
    found_access_denied_pids: set[int] = set()
    found_missing_runtime_pids: set[int] = set()
    pid_to_cmd_readable: Dict[int, str] = {}
    pid_starttimes: Dict[int, int] = {}
    shared_hugetlb_candidate_pids: Set[int] = set()
    pid_filter = set(pids_to_show)

    for pid_str in os.listdir(proc.path("")):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)

        if pid_filter and pid not in pid_filter:
            continue
        if pid == OUR_PID:
            continue

        # RUN : Si -p est utilise, on respecte les PIDs explicites et on saute
        # le filtrage TARGET_KEYWORDS.
        # Sinon, pre-filtrage leger via /proc/<pid>/comm (fallback exe) pour
        # eviter le cout de get_cmd_name() sur la majorite des processus.
        if not pids_to_show:
            if not _matches_target_keywords_fast(pid):
                continue
        if pids_to_show:
            found_candidate_pids.add(pid)
            matched_candidates_count += 1

        try:
            comm_name, starttime_before = get_process_identity(pid)

            # Sans -p, le nom comm deja lu sert au pre-filtrage (fallback exe).
            if not pids_to_show:
                if not _matches_target_keywords_fast(pid, comm_name):
                    continue
                matched_candidates_count += 1

            private_base_kb, pss_kb, swap_kb, huge_priv_kb, huge_shared_kb, saw_pss_line = get_mem_stats(pid)
        except ProcAccessDenied:
            if pids_to_show:
                found_access_denied_pids.add(pid)
            continue
        except ProcNotFound:
            if pids_to_show:
                found_missing_runtime_pids.add(pid)
            continue
        except LookupError:
            continue
        except Exception as e:
            print(f"[WARN] Failed to read PID {pid}: {e}", file=sys.stderr)
            continue

        # On ne calcule le nom "complet" qu'apres validation du candidat et
        # lecture memoire reussie.
        cmd = get_cmd_name(pid, split_args, discriminate_by_pid)
        matched_readable_count += 1
        if pids_to_show:
            found_readable_pids.add(pid)
        pid_to_cmd_readable[pid] = cmd
        pid_starttimes[pid] = starttime_after
        if huge_shared_kb > 0:
            shared_hugetlb_candidate_pids.add(pid)
        pss_seen_any = pss_seen_any or saw_pss_line

        # PSS totalisable : somme directe
        psses[cmd] = psses.get(cmd, 0) + pss_kb

        # Private base totalisable : somme directe (hors huge)
        private_bases[cmd] = private_bases.get(cmd, 0) + private_base_kb

        # Huge private totalisable : somme directe
        huge_privs[cmd] = huge_privs.get(cmd, 0) + huge_priv_kb

        # Huge shared : aggregation par MAX pour eviter le double comptage
        if cmd in huge_shareds:
            if huge_shareds[cmd] < huge_shared_kb:
                huge_shareds[cmd] = huge_shared_kb
        else:
            huge_shareds[cmd] = huge_shared_kb

        # Swap totalisable si SwapPss dispo, sinon c'est une approximation (comme original)
        swaps[cmd] = swaps.get(cmd, 0) + swap_kb

        counts[cmd] = counts.get(cmd, 0) + 1

    if shared_hugetlb_candidate_pids:
        pss_like_shared_hugetlb, failed_pid_count = estimate_shared_hugetlb_pss_like(
            pid_to_cmd=pid_to_cmd_readable,
            pid_starttimes=pid_starttimes,
            candidate_pids=shared_hugetlb_candidate_pids,
        )
        # max reste une borne basse de securite; on prend la meilleure estimation.
        for cmd, pss_like_kb in pss_like_shared_hugetlb.items():
            if huge_shareds.get(cmd, 0) < pss_like_kb:
                huge_shareds[cmd] = pss_like_kb
        if failed_pid_count:
            print(
                f"[WARN] Shared_Hugetlb precise pass skipped {failed_pid_count} PID(s); "
                "kept max-based conservative floor (possible underestimation).",
                file=sys.stderr,
            )

    for cmd in psses:
        private_base_total = private_bases.get(cmd, 0)
        huge_priv_total = huge_privs.get(cmd, 0)
        huge_shared_total = huge_shareds.get(cmd, 0)
        privates[cmd] = private_base_total + huge_priv_total
        ram_useds[cmd] = psses.get(cmd, 0) + huge_priv_total + huge_shared_total
        if ram_useds[cmd] < privates[cmd]:
            ram_useds[cmd] = privates[cmd]

    total_ram_used = sum(ram_useds.values())
    total_swap = sum(swaps.values())
    sorted_cmds = sorted(ram_useds.items(), key=lambda x: x[1], reverse=True)

    return MemoryUsageResult(
        sorted_cmds=sorted_cmds,
        privates=privates,
        counts=counts,
        total_ram_used=total_ram_used,
        swaps=swaps,
        total_swap=total_swap,
        matched_candidates_count=matched_candidates_count,
        matched_readable_count=matched_readable_count,
        pss_seen_any=pss_seen_any,
        found_candidate_pids=found_candidate_pids,
        found_readable_pids=found_readable_pids,
        found_access_denied_pids=found_access_denied_pids,
        found_missing_runtime_pids=found_missing_runtime_pids,
    )


def print_header(show_swap: bool) -> None:
    hdr = f"{'Private':>9} + {'Shared':>9} = {'RAM used':>9}"
    if show_swap:
        hdr += f"   {'Swap used':>9}"
    print(f"{hdr}\tProgram\n{'-' * 60}")


def print_timestamp() -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    stream = sys.stdout if sys.stdout.isatty() else sys.stderr
    print(f"Timestamp: {stamp}", file=stream)


def print_memory_usage(sorted_cmds, privates, counts, total_ram_used, swaps, total_swap, show_swap: bool) -> None:
    for cmd, ram_used in sorted_cmds:
        private = privates.get(cmd, 0)
        # Shared "proportionnel" pour que Private + Shared = RAM used
        shared = ram_used - private

        line = f"{human(private):>9} + {human(shared):>9} = {human(ram_used):>9}"
        if show_swap:
            line += f"   {human(swaps.get(cmd, 0)):>9}"
        print(f"{line}\t{cmd_with_count(cmd, counts[cmd])}")

    # RUN : Le pied de page inclut le Swap uniquement si -S/--swap est demande.
    if show_swap:
        print(f"\n{'-' * 45}\n{'Total:':>30} {human(total_ram_used)} RAM, {human(total_swap)} Swap\n")
    else:
        print(f"\n{'-' * 45}\n{'Total:':>30} {human(total_ram_used)} RAM\n")


def _pid_issue_sets(result: MemoryUsageResult, requested_pids: List[int]) -> Tuple[set[int], set[int], set[int], set[int]]:
    missing_from_proc = set(requested_pids) - result.found_candidate_pids
    access_denied = result.found_access_denied_pids
    disappeared_runtime = result.found_missing_runtime_pids
    unreadable_other = (
        result.found_candidate_pids
        - result.found_readable_pids
        - access_denied
        - disappeared_runtime
    )
    return missing_from_proc, access_denied, disappeared_runtime, unreadable_other


def _print_pid_issue_messages(result: MemoryUsageResult, requested_pids: List[int], level: str) -> bool:
    missing_from_proc, access_denied, disappeared_runtime, unreadable_other = _pid_issue_sets(result, requested_pids)
    emitted = False
    prefix = f"{level}: "

    if access_denied:
        print(
            prefix + "Access denied reading smaps* for PID(s): "
            f"{', '.join(str(pid) for pid in sorted(access_denied))}.",
            file=sys.stderr,
        )
        emitted = True
    if disappeared_runtime:
        print(
            prefix + "PID(s) disappeared during collection: "
            f"{', '.join(str(pid) for pid in sorted(disappeared_runtime))}.",
            file=sys.stderr,
        )
        emitted = True
    if missing_from_proc:
        print(
            prefix + "Specified PIDs missing from /proc: "
            f"{', '.join(str(pid) for pid in sorted(missing_from_proc))}.",
            file=sys.stderr,
        )
        emitted = True
    if unreadable_other:
        print(
            prefix + "Specified PIDs present but unreadable via smaps* (unknown cause): "
            f"{', '.join(str(pid) for pid in sorted(unreadable_other))}.",
            file=sys.stderr,
        )
        emitted = True

    return emitted


def main() -> None:
    sys.stdout = Unbuffered(sys.stdout)
    sys.stderr = Unbuffered(sys.stderr)

    split_args, pids_to_show, watch, only_total, discriminate_by_pid, show_swap = parse_options()

    if os.geteuid() != 0 and not pids_to_show:
        print("Root permissions required or specify PIDs with -p", file=sys.stderr)
        sys.exit(1)

    while True:
        # RUN : On distingue PIDs candidats vs lisibles pour eviter un faux
        # "PSS absent" quand un process disparait ou que smaps est illisible.
        # En mode watch, on continue la surveillance (continue) au lieu de sortir.
        # SwapPss est prefere a Swap quand present pour eviter un melange de modes.
        print_timestamp()
        result = get_memory_usage(
            pids_to_show=pids_to_show,
            split_args=split_args,
            discriminate_by_pid=discriminate_by_pid,
        )

        if result.matched_candidates_count == 0:
            if only_total:
                print(human(0))
            else:
                if pids_to_show:
                    print(f"No processes found for specified PIDs (not present in /proc): {', '.join(str(pid) for pid in pids_to_show)}")
                else:
                    print(f"No matching processes for keywords: {', '.join(TARGET_KEYWORDS)}")
            if watch is None:
                sys.exit(0)
            time.sleep(watch)
            continue

        if result.matched_readable_count == 0:
            if pids_to_show:
                emitted = _print_pid_issue_messages(result, pids_to_show, level="ERROR")
                if not emitted:
                    print(
                        "ERROR: Specified PIDs found but none readable "
                        "(stat/smaps access, process exit or PID reuse).",
                        file=sys.stderr,
                    )
            else:
                print(
                    "ERROR: Matching processes found but none readable "
                    "(stat/smaps access, process exit or PID reuse).",
                    file=sys.stderr,
                )
            if watch is None:
                sys.exit(2)
            time.sleep(watch)
            continue

        # En mode -p, avertir aussi en cas d'erreurs partielles (si au moins un
        # PID est lisible, on continue mais on n'ignore pas silencieusement les
        # PID refuses/disparus/manquants).
        if pids_to_show:
            _print_pid_issue_messages(result, pids_to_show, level="WARN")

        # On echoue rapidement si PSS est absent pour eviter d'afficher des zeros trompeurs.
        if not result.pss_seen_any:
            print(
                "ERROR: PSS not available/readable (no 'Pss:' lines found in smaps/smaps_rollup). Results would be unreliable.",
                file=sys.stderr,
            )
            if watch is None:
                sys.exit(2)
            time.sleep(watch)
            continue

        if not only_total:
            print_header(show_swap)

        if only_total:
            print(human(result.total_swap if show_swap else result.total_ram_used))
        else:
            print_memory_usage(
                result.sorted_cmds,
                result.privates,
                result.counts,
                result.total_ram_used,
                result.swaps,
                result.total_swap,
                show_swap,
            )

        if watch is None:
            break
        time.sleep(watch)


if __name__ == "__main__":
    main()
