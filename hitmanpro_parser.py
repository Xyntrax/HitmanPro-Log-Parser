from __future__ import annotations

import re
import sys
from pathlib import Path


SUPPORTED_EXTENSIONS = {".txt", ".log"}

SECTION_NAMES = (
    "Malware",
    "Suspicious files",
    "Potential Unwanted Programs",
    "Cookies",
)

WINDOWS_PATH_RE = re.compile(
    r"""(?<![\w])((?:\\\\\?\\)?[A-Za-z]:\\[^\r\n\t"<>|]*|\\\\[^\\/\r\n]+\\[^\\/\r\n]+\\[^\r\n\t"<>|]*)"""
)

SHA256_RE = re.compile(
    r"SHA\s*[- ]?\s*256\b\s*(?:[.: ]|\.)*\s*:\s*([0-9a-fA-F]{64})",
    re.IGNORECASE,
)
SHA256_FALLBACK_RE = re.compile(
    r"SHA\s*[- ]?\s*256\b.*?([0-9a-fA-F]{64})",
    re.IGNORECASE,
)


FORENSIC_CLUSTER_RE = re.compile(r"^\s*Forensic\s+Cluster\s*:?\s*$", re.IGNORECASE)

CLUSTER_LINE_RE = re.compile(r"^\s+[-+]?\d+(?:\.\d+)?\s*[a-zA-Z]{1,2}\s+(\S.*?)\s*$")

MAX_ENTRY_INDENT = 5

KEEP_CLUSTER_TIMESTAMPS = False

HEADER_WIDTH = 77


def make_header(name: str) -> str:
    prefix = f"{name} "
    return prefix + "_" * max(4, HEADER_WIDTH - len(prefix))


def detect_section_header(line: str) -> str | None:
    candidate = line.strip()
    for name in SECTION_NAMES:
        if re.match(rf"^{re.escape(name)}\b", candidate, re.IGNORECASE):
            remainder = candidate[len(name):]
            if not remainder.strip(" _\t.-=:"):
                return name
    return None


def is_powershell_header(line: str) -> bool:
    return bool(
        re.match(
            r"^\s*=+\s*powershell\s*:\s*=+\s*$",
            line,
            re.IGNORECASE,
        )
    )


def remove_powershell_blocks(lines: list[str]) -> list[str]:
    cleaned: list[str] = []
    for line in lines:
        if is_powershell_header(line):
            continue
        if line.strip().casefold() in {"[code]", "[/code]"}:
            continue
        cleaned.append(line)
    return cleaned

def normalize_path_line(line: str) -> str | None:
    match = WINDOWS_PATH_RE.search(line)
    if not match:
        return None

    path = match.group(1).strip()
    path = path.rstrip(" .")
    return path or None

class Entry:

    def __init__(self, path: str) -> None:
        self.path = path
        self.digest: str | None = None
        self.cluster: list[str] = []
        self.has_cluster = False

def parse_section(lines: list[str]) -> list[Entry]:
    entries: list[Entry] = []
    current: Entry | None = None
    in_cluster = False

    for line in lines:
        if not line.strip():
            in_cluster = False
            continue

        if FORENSIC_CLUSTER_RE.match(line):
            if current is not None:
                current.has_cluster = True
                in_cluster = True
            continue

        if in_cluster and current is not None:
            cm = CLUSTER_LINE_RE.match(line)
            if cm:
                if KEEP_CLUSTER_TIMESTAMPS:
                    current.cluster.append(line.strip())
                else:
                    current.cluster.append(cm.group(1))
                continue
            in_cluster = False

        indent = len(line) - len(line.lstrip(" "))
        if indent <= MAX_ENTRY_INDENT:
            path = normalize_path_line(line)
            if path:
                current = Entry(line.strip().rstrip(" ."))
                entries.append(current)
                in_cluster = False
                continue

        if current is not None and current.digest is None:
            if "sha" in line.lower() and "256" in line:
                match = SHA256_RE.search(line) or SHA256_FALLBACK_RE.search(line)
                if match:
                    current.digest = match.group(1).lower()

    return entries

def parse_log(text: str, include_cluster: bool = False) -> str:
    lines = remove_powershell_blocks(text.splitlines())
    while lines and not lines[0].strip():
        lines.pop(0)

    section_positions: list[tuple[int, str]] = []

    for index, line in enumerate(lines):
        name = detect_section_header(line)
        if name:
            section_positions.append((index, name))

    if not section_positions:
        raise ValueError(
            "No Malware, Suspicious files, Potential Unwanted Programs, or "
            "Cookies section headers were found."
        )

    output_lines = lines[:section_positions[0][0]]
    if output_lines and output_lines[-1].strip():
        output_lines.append("")

    for position_index, (start, section_name) in enumerate(section_positions):
        end = (
            section_positions[position_index + 1][0]
            if position_index + 1 < len(section_positions)
            else len(lines)
        )
        original_header = lines[start].rstrip()
        section_lines = lines[start + 1:end]

        output_lines.append(original_header)
        output_lines.append("")

        if section_name.casefold() == "cookies":
            output_lines.extend(line.strip() for line in section_lines if line.strip())
        else:
            for entry in parse_section(section_lines):
                output_lines.append(entry.path)
                if entry.digest:
                    output_lines.append(f"SHA-256  . . . . . : {entry.digest}")
                show_cluster = include_cluster and entry.has_cluster and entry.cluster
                if show_cluster:
                    output_lines.append("")
                    output_lines.append(make_header("Forensic Cluster"))
                    output_lines.append("")
                    output_lines.extend(entry.cluster)
                if entry.digest or show_cluster:
                    output_lines.append("")

        while output_lines and output_lines[-1] == "":
            output_lines.pop()
        if position_index < len(section_positions) - 1:
            output_lines.append("")

    return "\n".join(output_lines).rstrip() + "\n"


def output_path_for(source: Path) -> Path:
    return source.with_name(f"{source.stem}_parsed{source.suffix}")


def parse_file(source: Path, include_cluster: bool = False) -> bool:
    if not source.exists():
        print(f"Error: file not found: {source}", file=sys.stderr)
        return False
    if not source.is_file():
        print(f"Error: not a file: {source}", file=sys.stderr)
        return False
    if source.suffix.lower() not in SUPPORTED_EXTENSIONS:
        print(f"Error: expected a .txt or .log file: {source}", file=sys.stderr)
        return False

    try:
        raw_text = source.read_text(encoding="utf-8-sig", errors="replace")
        parsed_text = parse_log(raw_text, include_cluster)
    except OSError as exc:
        print(f"Error reading {source}: {exc}", file=sys.stderr)
        return False
    except ValueError as exc:
        print(f"Error parsing {source}: {exc}", file=sys.stderr)
        return False

    destination = output_path_for(source)
    try:
        destination.write_text(parsed_text, encoding="utf-8", newline="\n")
    except OSError as exc:
        print(f"Error writing {destination}: {exc}", file=sys.stderr)
        return False

    print(f"Parsed: {source} -> {destination}")
    return True


def scan_current_directory(include_cluster: bool = False) -> int:
    matches = sorted(
        (
            item for item in Path.cwd().iterdir()
            if item.is_file()
            and item.suffix.lower() in SUPPORTED_EXTENSIONS
            and item.stem.casefold() == "hitmanpro"
        ),
        key=lambda item: item.name.casefold(),
    )

    if not matches:
        print(
            "No HitmanPro.txt or HitmanPro.log file found in the current "
            "directory (filename matching is case-insensitive).",
            file=sys.stderr,
        )
        return 1

    failures = 0
    for source in matches:
        if not parse_file(source, include_cluster):
            failures += 1
    return 1 if failures else 0


USAGE = (
    "Usage:\n"
    "  python hitmanpro_parser.py scan\n"
    "  python hitmanpro_parser.py targetname.txt\n"
    "  python hitmanpro_parser.py targetname.log\n"
    "\n"
    "Add -fc before the command to include the Forensic Cluster sections:\n"
    "  python hitmanpro_parser.py -fc scan\n"
    "  python hitmanpro_parser.py -fc targetname.txt\n"
    "  python hitmanpro_parser.py -fc targetname.log"
)


def main(argv: list[str]) -> int:
    include_cluster = False
    positional: list[str] = []

    for arg in argv[1:]:
        if arg.casefold() == "-fc":
            include_cluster = True
        elif arg.startswith("-") and len(arg) > 1:
            print(f"Error: unknown option: {arg}\n\n{USAGE}", file=sys.stderr)
            return 2
        else:
            positional.append(arg)

    if len(positional) != 1:
        print(USAGE, file=sys.stderr)
        return 2

    argument = positional[0]
    if argument.casefold() == "scan":
        return scan_current_directory(include_cluster)

    source = Path(argument).expanduser()
    if not source.is_absolute():
        source = Path.cwd() / source
    return 0 if parse_file(source, include_cluster) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
