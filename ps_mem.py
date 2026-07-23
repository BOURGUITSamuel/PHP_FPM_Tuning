#!/usr/bin/env python3

"""
Estime la mémoire imputable aux processus Linux à partir du PSS.

Sans -p, l'analyse se limite aux processus dont le nom court ou celui de
l'exécutable contient apache, httpd, php ou php-fpm. Avec -p, tout PID
accessible peut être ciblé. Les résultats sont regroupés par programme et
les titres PHP-FPM sont conservés afin de distinguer les pools.

Les mesures sont lues dans /proc/<pid>/smaps_rollup, avec repli sur smaps.
La mémoire HugeTLB est traitée séparément. La part Shared_Hugetlb repose sur
une heuristique et peut donc être sous-estimée ou surévaluée.

Les totaux concernent uniquement les processus sélectionnés.

Adaptation : jsbourguit, à partir du script original de Pádraig Brady.
Licence : LGPL-2.1-or-later.
"""

import argparse
from dataclasses import dataclass
import errno
import os
import sys
import time
from typing import Dict, List, NoReturn, Set, Tuple

__version__ = "4.7"

OUR_PID = os.getpid()

TARGET_KEYWORDS = ("apache", "httpd", "php", "php-fpm")
MAX_COMMAND_CHARS = 4096
MAX_PROC_STAT_CHARS = 4096
PROC_STAT_STARTTIME_INDEX = 22 - 3  # stat_fields commence au champ 3 de /proc/<pid>/stat.

SegmentKey = Tuple[str, str, str, str, int]
PROC_NOT_FOUND_ERRNOS = frozenset((errno.ENOENT, errno.ESRCH))
PROC_ACCESS_DENIED_ERRNOS = frozenset((errno.EPERM, errno.EACCES))
SMAPS_FIELDS = frozenset(
    (
        "Private",
        "Private_Clean",
        "Private_Dirty",
        "Pss",
        "Swap",
        "SwapPss",
        "Private_Hugetlb",
        "Shared_Hugetlb",
    )
)


def std_exceptions(exc_type, value, tb):
    """Ignore les interruptions normales et délègue les autres exceptions à Python."""
    sys.excepthook = sys.__excepthook__
    if issubclass(exc_type, (KeyboardInterrupt, BrokenPipeError)):
        return
    sys.__excepthook__(exc_type, value, tb)


sys.excepthook = std_exceptions


class Unbuffered:
    def __init__(self, stream):
        """Associe le wrapper au flux à vider après chaque écriture."""
        self.stream = stream

    def write(self, data: str) -> None:
        """Écrit les données puis vide immédiatement le tampon du flux."""
        self.stream.write(data)
        self.stream.flush()

    def flush(self) -> None:
        """Vide le tampon sans propager les erreurs attendues d'un flux fermé."""
        try:
            self.stream.flush()
        except (BrokenPipeError, ValueError):
            pass

    def isatty(self) -> bool:
        """Indique si le flux est relié à un terminal encore utilisable."""
        try:
            return self.stream.isatty()
        except (OSError, ValueError):
            return False

    def close(self) -> None:
        """Ferme le flux sans propager les erreurs de fermeture attendues."""
        try:
            self.stream.close()
        except (BrokenPipeError, ValueError):
            pass


class ProcLookupError(LookupError):
    def __init__(self, pid: int, entry: str):
        """Mémorise le PID et l'entrée /proc à l'origine de l'erreur."""
        self.pid = pid
        self.entry = entry
        super().__init__(f"/proc/{pid}/{entry}" if entry else f"/proc/{pid}")


class ProcNotFound(ProcLookupError):
    pass


class ProcAccessDenied(ProcLookupError):
    pass


class ProcInvalidData(ProcLookupError):
    pass


def _parse_smaps_kb_value(pid: int, entry: str, value_and_unit: str) -> int:
    """Valide puis convertit une valeur smaps de la forme « <nombre> kB »."""
    parts = value_and_unit.split()
    if len(parts) != 2 or parts[1] != "kB":
        raise ProcInvalidData(pid, entry)

    value_text = parts[0]
    if not value_text.isascii() or not value_text.isdecimal():
        raise ProcInvalidData(pid, entry)

    try:
        return int(value_text, 10)
    except ValueError as e:
        raise ProcInvalidData(pid, entry) from e


def _raise_proc_os_error(pid: int, entry: str, error: OSError) -> NoReturn:
    """Traduit les erreurs /proc attendues et propage les autres."""
    if error.errno in PROC_NOT_FOUND_ERRNOS:
        raise ProcNotFound(pid, entry) from error
    if error.errno in PROC_ACCESS_DENIED_ERRNOS:
        raise ProcAccessDenied(pid, entry) from error
    raise error


def _is_expected_proc_os_error(error: OSError) -> bool:
    """Reconnaît une erreur due à un PID absent ou inaccessible."""
    return error.errno in PROC_NOT_FOUND_ERRNOS or error.errno in PROC_ACCESS_DENIED_ERRNOS


class Proc:
    def __init__(self):
        """Définit la racine utilisée pour lire les informations des processus."""
        self.proc = "/proc"

    def path(self, *args: str | int) -> str:
        """Construit un chemin sous /proc à partir de ses composants."""
        return os.path.join(self.proc, *(str(a) for a in args))

    def open(self, *args: str | int):
        """Ouvre une entrée /proc en traduisant les erreurs liées au PID."""
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
                _raise_proc_os_error(pid, entry, e)
            raise

    def readlink(self, *args: str | int) -> str:
        """Lit un lien /proc en traduisant les erreurs liées au PID."""
        try:
            return os.readlink(self.path(*args))
        except OSError as e:
            if args and isinstance(args[0], int):
                pid = int(args[0])
                entry = "/".join(str(a) for a in args[1:])
                _raise_proc_os_error(pid, entry, e)
            raise


proc = Proc()


@dataclass
class CommandUsage:
    pss_kb: int = 0
    private_base_kb: int = 0
    huge_private_kb: int = 0
    huge_shared_kb: int = 0
    swap_kb: int = 0
    count: int = 0


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
    found_reused_pids: set[int]
    found_invalid_data_pids: set[int]


def parse_options() -> Tuple[bool, List[int], int | None, bool, bool, bool]:
    """Analyse et valide les options de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description=(
            "Show PSS-based memory usage for Apache/HTTPd/PHP processes, "
            "grouped by program or PHP-FPM pool. Use -p to select specific PIDs."
        )
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "-s",
        "--split-args",
        action="store_true",
        help="Use the full command line as the label (PHP-FPM pool titles are preserved).",
    )
    parser.add_argument(
        "-t",
        "--total",
        dest="only_total",
        action="store_true",
        help="Show only the RAM total, or the swap total when combined with -S.",
    )
    parser.add_argument(
        "-d",
        "--discriminate-by-pid",
        action="store_true",
        help="Keep each PID separate instead of grouping by program.",
    )
    parser.add_argument(
        "-S",
        "--swap",
        dest="show_swap",
        action="store_true",
        help="Show swap usage (SwapPss if available).",
    )
    parser.add_argument(
        "-p",
        dest="pids",
        metavar="<pid>[,pid2,...]",
        help="Analyze only the listed PIDs; bypasses the default name filter.",
    )
    parser.add_argument("-w", dest="watch", metavar="<N>", type=int, help="Repeat the collection after N seconds.")
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
        parser.error("Refresh interval must be a positive integer.")

    return args.split_args, pids_to_show, args.watch, args.only_total, args.discriminate_by_pid, args.show_swap


def get_mem_stats(pid: int) -> Tuple[int, int, int, int, int, bool]:
    """Lit les compteurs mémoire du PID.

    Retourne en KiB la mémoire privée hors HugeTLB, le PSS, le swap, la part
    HugeTLB privée, la part HugeTLB partagée, puis la présence du champ Pss.
    SwapPss est utilisé lorsqu'il est disponible, sinon Swap.
    """
    totals = {field: 0 for field in SMAPS_FIELDS}
    seen_fields: Set[str] = set()

    smaps_handle = None
    smaps_file_used = ""
    last_lookup_error: ProcLookupError | None = None
    for smaps_file in ("smaps_rollup", "smaps"):
        try:
            smaps_handle = proc.open(pid, smaps_file)
            smaps_file_used = smaps_file
            break
        except ProcAccessDenied as e:
            # Un refus d'accès reste l'erreur la plus utile si les deux lectures échouent.
            last_lookup_error = e
            continue
        except ProcNotFound as e:
            if last_lookup_error is None:
                last_lookup_error = e
            continue

    if smaps_handle is None:
        if last_lookup_error is not None:
            raise last_lookup_error
        raise ProcNotFound(pid, "smaps*")

    try:
        with smaps_handle as f:
            for line in f:
                field, separator, value_and_unit = line.partition(":")
                if not separator or field not in SMAPS_FIELDS:
                    continue

                totals[field] += _parse_smaps_kb_value(
                    pid,
                    smaps_file_used or "smaps*",
                    value_and_unit,
                )
                # La présence du champ compte, même si sa valeur est nulle.
                if field in ("Private", "Pss", "SwapPss"):
                    seen_fields.add(field)
    except OSError as e:
        _raise_proc_os_error(pid, smaps_file_used or "smaps*", e)

    private_base_kb = (
        totals["Private"]
        if "Private" in seen_fields
        else totals["Private_Clean"] + totals["Private_Dirty"]
    )
    swap_kb = totals["SwapPss"] if "SwapPss" in seen_fields else totals["Swap"]
    return (
        private_base_kb,
        totals["Pss"],
        swap_kb,
        totals["Private_Hugetlb"],
        totals["Shared_Hugetlb"],
        "Pss" in seen_fields,
    )


def get_cmd_name(pid: int, split_args: bool = False, discriminate_by_pid: bool = False) -> str:
    """Construit le libellé utilisé pour l'affichage et le regroupement.

    Les titres PHP-FPM sont conservés. Pour les autres processus, split_args
    utilise la ligne de commande complète et discriminate_by_pid ajoute le PID.
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

        if cmdline0.startswith("php-fpm:"):
            cmd = cmdline0
            command_was_truncated = first_arg_truncated
        elif split_args and cmdline_full:
            cmd = cmdline_full
            command_was_truncated = cmdline_truncated
        else:
            command_was_truncated = False
            try:
                exe_target = proc.readlink(pid, "exe")
                exe_target = exe_target.split("\0")[0]
                if exe_target:
                    cmd = os.path.basename(exe_target)
                elif cmdline0:
                    cmd = os.path.basename(cmdline0)
                    command_was_truncated = first_arg_truncated
                else:
                    cmd = f"proc-{pid}"
            except ProcLookupError:
                cmd = os.path.basename(cmdline0) if cmdline0 else f"proc-{pid}"
                command_was_truncated = bool(cmdline0) and first_arg_truncated

        if command_was_truncated:
            cmd = f"[truncated pid={pid}] {cmd}"
        if discriminate_by_pid:
            cmd = f"{cmd} [{pid}]"
        return cmd

    except ProcLookupError:
        return f"proc-{pid}"
    except OSError as e:
        if _is_expected_proc_os_error(e):
            return f"proc-{pid}"
        raise


def get_process_identity(pid: int) -> Tuple[str, int]:
    """Lit le nom (comm) et le champ starttime dans /proc/<pid>/stat."""
    try:
        with proc.open(pid, "stat") as f:
            stat_line = f.read(MAX_PROC_STAT_CHARS)
    except OSError as e:
        _raise_proc_os_error(pid, "stat", e)

    if not stat_line:
        raise ProcNotFound(pid, "stat")

    comm_start = stat_line.find("(")
    comm_end = stat_line.rfind(")")
    if comm_start < 0 or comm_end <= comm_start:
        raise ProcInvalidData(pid, "stat")

    stat_fields = stat_line[comm_end + 1:].split()
    if len(stat_fields) <= PROC_STAT_STARTTIME_INDEX:
        raise ProcInvalidData(pid, "stat")

    try:
        starttime = int(stat_fields[PROC_STAT_STARTTIME_INDEX])
    except ValueError as e:
        raise ProcInvalidData(pid, "stat") from e

    return stat_line[comm_start + 1:comm_end], starttime


def _fast_exe_name(pid: int) -> str:
    """Retourne le nom du binaire pointé par /proc/<pid>/exe s'il est lisible."""
    try:
        exe_target = proc.readlink(pid, "exe")
        exe_target = exe_target.split("\0")[0]
        if exe_target:
            return os.path.basename(exe_target)
    except ProcLookupError:
        pass

    return ""


def _matches_target_keywords_fast(pid: int, comm_name: str) -> bool:
    """Vérifie si le PID appartient au périmètre Apache/PHP par défaut."""
    comm_name = comm_name.lower()
    if comm_name and any(keyword in comm_name for keyword in TARGET_KEYWORDS):
        return True

    # comm peut être tronqué par le noyau ; vérifier aussi le nom de l'exécutable.
    exe_name = _fast_exe_name(pid).lower()
    if exe_name and any(keyword in exe_name for keyword in TARGET_KEYWORDS):
        return True

    return False


def human(kb: float) -> str:
    """Formate une quantité en KiB avec l'unité binaire adaptée."""
    units = ["KiB", "MiB", "GiB", "TiB"]
    v = float(kb)
    for u in units:
        if v < 1024:
            return f"{v:.1f} {u}"
        v /= 1024
    return f"{v:.1f} PiB"


def safe_command_text(command: str) -> str:
    """Échappe les caractères non ASCII ou de contrôle et limite la longueur affichée."""
    safe_command = ascii(command)[1:-1]
    if len(safe_command) > MAX_COMMAND_CHARS:
        safe_command = f"{safe_command[:MAX_COMMAND_CHARS - 3]}..."
    return safe_command


def cmd_with_count(cmd: str, count: int) -> str:
    """Ajoute le nombre de processus lorsqu'un même libellé est regroupé."""
    safe_cmd = safe_command_text(cmd)
    return f"{safe_cmd} ({count})" if count > 1 else safe_cmd


def _is_smaps_mapping_header(line: str) -> bool:
    """Indique si une ligne marque le début d'un mapping dans smaps."""
    parts = line.split(None, 5)
    if len(parts) < 5:
        return False
    return parts[0].count("-") == 1


def _segment_key_from_smaps_header(line: str) -> SegmentKey:
    """Construit la clé utilisée pour reconnaître un mapping entre processus."""
    parts = line.strip().split(None, 5)
    addr = parts[0]
    offset = parts[2]
    dev = parts[3]
    inode = parts[4]
    pathname = parts[5] if len(parts) >= 6 else ""
    start_hex, end_hex = addr.split("-", 1)
    mapping_len_kb = max(0, (int(end_hex, 16) - int(start_hex, 16)) // 1024)
    return dev, inode, offset, pathname, mapping_len_kb


def _record_shared_hugetlb_segment(
    segments: Dict[SegmentKey, int],
    key: SegmentKey | None,
    size_kb: int,
) -> None:
    """Conserve la plus grande valeur Shared_Hugetlb observée pour un mapping."""
    if key is not None and size_kb > segments.get(key, 0):
        segments[key] = size_kb


def estimate_shared_hugetlb_pss_like(
    pid_to_cmd: Dict[int, str],
    pid_starttimes: Dict[int, int],
    candidate_pids: Set[int],
) -> Tuple[Dict[str, int], int]:
    """Répartit approximativement Shared_Hugetlb entre les commandes.

    Les mappings sont dédupliqués, puis chaque segment est réparti entre les
    processus qui le référencent. Les PID devenus illisibles ou dont l'identité
    change pendant la lecture sont écartés.

    Retourne les valeurs par commande et le nombre de PID écartés.
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
                        current_shared_huge_kb = _parse_smaps_kb_value(
                            pid,
                            "smaps",
                            line.partition(":")[2],
                        )
                _record_shared_hugetlb_segment(pid_segments, current_key, current_shared_huge_kb)

            _, starttime_after = get_process_identity(pid)
        except (ProcLookupError, ValueError):
            failed_pid_count += 1
            continue
        except OSError as e:
            if not _is_expected_proc_os_error(e):
                raise
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
    """Collecte les PID retenus et agrège leurs mesures par libellé."""
    usage_by_cmd: Dict[str, CommandUsage] = {}
    matched_candidates_count = 0
    matched_readable_count = 0
    pss_seen_any = False
    found_candidate_pids: set[int] = set()
    found_readable_pids: set[int] = set()
    found_access_denied_pids: set[int] = set()
    found_missing_runtime_pids: set[int] = set()
    found_reused_pids: set[int] = set()
    found_invalid_data_pids: set[int] = set()
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

        if pids_to_show:
            found_candidate_pids.add(pid)
            matched_candidates_count += 1

        try:
            comm_name, starttime_before = get_process_identity(pid)

            if not pids_to_show:
                # Éviter la lecture coûteuse de smaps pour les processus hors périmètre.
                if not _matches_target_keywords_fast(pid, comm_name):
                    continue
                matched_candidates_count += 1

            private_base_kb, pss_kb, swap_kb, huge_priv_kb, huge_shared_kb, saw_pss_line = get_mem_stats(pid)
            cmd = get_cmd_name(pid, split_args, discriminate_by_pid)
            _, starttime_after = get_process_identity(pid)
        except ProcAccessDenied:
            if pids_to_show:
                found_access_denied_pids.add(pid)
            continue
        except ProcNotFound:
            if pids_to_show:
                found_missing_runtime_pids.add(pid)
            continue
        except ProcInvalidData as e:
            if pids_to_show:
                found_invalid_data_pids.add(pid)
            else:
                print(f"[WARN] Invalid data in {e}; PID skipped.", file=sys.stderr)
            continue

        if starttime_before != starttime_after:
            found_reused_pids.add(pid)
            continue

        matched_readable_count += 1
        if pids_to_show:
            found_readable_pids.add(pid)
        pid_to_cmd_readable[pid] = cmd
        pid_starttimes[pid] = starttime_after
        if huge_shared_kb > 0:
            shared_hugetlb_candidate_pids.add(pid)
        pss_seen_any = pss_seen_any or saw_pss_line

        usage = usage_by_cmd.get(cmd)
        if usage is None:
            usage = CommandUsage(huge_shared_kb=huge_shared_kb)
            usage_by_cmd[cmd] = usage
        else:
            # Repli : conserver la plus grande valeur partagée observée dans le groupe.
            usage.huge_shared_kb = max(usage.huge_shared_kb, huge_shared_kb)

        usage.pss_kb += pss_kb
        usage.private_base_kb += private_base_kb
        usage.huge_private_kb += huge_priv_kb
        usage.swap_kb += swap_kb
        usage.count += 1

    if shared_hugetlb_candidate_pids:
        pss_like_shared_hugetlb, failed_pid_count = estimate_shared_hugetlb_pss_like(
            pid_to_cmd=pid_to_cmd_readable,
            pid_starttimes=pid_starttimes,
            candidate_pids=shared_hugetlb_candidate_pids,
        )
        # La valeur la plus élevée limite la sous-estimation, mais peut aussi surestimer.
        for cmd, pss_like_kb in pss_like_shared_hugetlb.items():
            usage = usage_by_cmd.get(cmd)
            if usage is not None:
                usage.huge_shared_kb = max(usage.huge_shared_kb, pss_like_kb)
        if failed_pid_count:
            print(
                f"[WARN] Shared_Hugetlb refinement could not inspect {failed_pid_count} PID(s); "
                "fallback values were kept, so the result may be under- or overestimated.",
                file=sys.stderr,
            )

    privates: Dict[str, int] = {}
    ram_useds: Dict[str, int] = {}
    for cmd, usage in usage_by_cmd.items():
        private_kb = usage.private_base_kb + usage.huge_private_kb
        privates[cmd] = private_kb
        ram_useds[cmd] = max(
            usage.pss_kb + usage.huge_private_kb + usage.huge_shared_kb,
            private_kb,
        )

    counts = {cmd: usage.count for cmd, usage in usage_by_cmd.items()}
    swaps = {cmd: usage.swap_kb for cmd, usage in usage_by_cmd.items()}

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
        found_reused_pids=found_reused_pids,
        found_invalid_data_pids=found_invalid_data_pids,
    )


def print_header(show_swap: bool) -> None:
    """Affiche l'en-tête des colonnes de mémoire et, si demandé, du swap."""
    hdr = f"{'Private':>9} + {'Shared':>9} = {'RAM used':>9}"
    if show_swap:
        hdr += f"   {'Swap used':>9}"
    print(f"{hdr}\tProgram\n{'-' * 60}")


def print_timestamp() -> None:
    """Affiche l'horodatage sur le flux adapté au mode de sortie."""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    stream = sys.stdout if sys.stdout.isatty() else sys.stderr
    print(f"Timestamp: {stamp}", file=stream)


def print_memory_usage(sorted_cmds, privates, counts, total_ram_used, swaps, total_swap, show_swap: bool) -> None:
    """Affiche le détail par commande et les totaux de la collecte."""
    for cmd, ram_used in sorted_cmds:
        private = privates.get(cmd, 0)
        # Shared est déduit du total afin que Private + Shared = RAM used.
        shared = ram_used - private

        line = f"{human(private):>9} + {human(shared):>9} = {human(ram_used):>9}"
        if show_swap:
            line += f"   {human(swaps.get(cmd, 0)):>9}"
        print(f"{line}\t{cmd_with_count(cmd, counts[cmd])}")

    if show_swap:
        print(f"\n{'-' * 45}\n{'Total:':>30} {human(total_ram_used)} RAM, {human(total_swap)} Swap\n")
    else:
        print(f"\n{'-' * 45}\n{'Total:':>30} {human(total_ram_used)} RAM\n")


def _pid_issue_sets(
    result: MemoryUsageResult,
    requested_pids: List[int],
) -> Tuple[set[int], set[int], set[int], set[int], set[int], set[int]]:
    """Classe les PID demandés selon la cause de leur absence des résultats."""
    missing_from_proc = set(requested_pids) - result.found_candidate_pids
    access_denied = result.found_access_denied_pids
    disappeared_runtime = result.found_missing_runtime_pids
    reused = result.found_reused_pids
    invalid_data = result.found_invalid_data_pids
    unreadable_other = (
        result.found_candidate_pids
        - result.found_readable_pids
        - access_denied
        - disappeared_runtime
        - reused
        - invalid_data
    )
    return missing_from_proc, access_denied, disappeared_runtime, reused, invalid_data, unreadable_other


def _print_pid_issue_messages(result: MemoryUsageResult, requested_pids: List[int], level: str) -> bool:
    """Signale les PID ignorés et indique si un message a été émis."""
    (
        missing_from_proc,
        access_denied,
        disappeared_runtime,
        reused,
        invalid_data,
        unreadable_other,
    ) = _pid_issue_sets(result, requested_pids)
    emitted = False
    prefix = f"{level}: "

    if access_denied:
        print(
            prefix + "Access denied reading stat or smaps* for PID(s): "
            f"{', '.join(str(pid) for pid in sorted(access_denied))}.",
            file=sys.stderr,
        )
        emitted = True
    if reused:
        print(
            prefix + "PID(s) reused during collection (identity changed): "
            f"{', '.join(str(pid) for pid in sorted(reused))}.",
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
    if invalid_data:
        print(
            prefix + "Invalid data read from stat/smaps* for PID(s): "
            f"{', '.join(str(pid) for pid in sorted(invalid_data))}.",
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
            prefix + "Specified PIDs present but unreadable via stat/smaps* (unknown cause): "
            f"{', '.join(str(pid) for pid in sorted(unreadable_other))}.",
            file=sys.stderr,
        )
        emitted = True

    return emitted


def main() -> None:
    """Exécute une collecte unique ou répétée selon les options."""
    sys.stdout = Unbuffered(sys.stdout)
    sys.stderr = Unbuffered(sys.stderr)

    split_args, pids_to_show, watch, only_total, discriminate_by_pid, show_swap = parse_options()

    if os.geteuid() != 0 and not pids_to_show:
        print("Root permissions required or specify PIDs with -p", file=sys.stderr)
        sys.exit(1)

    while True:
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
                    print(
                        "No processes found for specified PIDs (not present in /proc): "
                        f"{', '.join(str(pid) for pid in pids_to_show)}"
                    )
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
                        "(stat/smaps unavailable or invalid, process exit or PID reuse).",
                        file=sys.stderr,
                    )
            else:
                print(
                    "ERROR: Matching processes found but none readable "
                    "(stat/smaps unavailable or invalid, process exit or PID reuse).",
                    file=sys.stderr,
                )
            if watch is None:
                sys.exit(2)
            time.sleep(watch)
            continue

        # Signaler les erreurs partielles sans perdre les résultats des PID lisibles.
        if pids_to_show:
            _print_pid_issue_messages(result, pids_to_show, level="WARN")

        # Sans champ Pss, les totaux seraient trompeurs : ne pas les afficher.
        if not result.pss_seen_any:
            print(
                "ERROR: PSS not available/readable "
                "(no 'Pss:' lines found in smaps/smaps_rollup). "
                "Results would be unreliable.",
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
