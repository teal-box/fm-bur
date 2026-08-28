#!/usr/bin/env python3
import re
import argparse
from datetime import datetime
from pathlib import Path


def process_file(in_path: Path, out_path: Path):
    lines = in_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

    start_idx = None
    for i, line in enumerate(lines):
        if "config firewall policy" in line.lower():
            start_idx = i
            break

    if start_idx is None:
        raise SystemExit(f"No 'config firewall policy' section found in {in_path}")

    # collect until next 'end' line (exclusive)
    collected = []
    for line in lines[start_idx:]:
        if line.strip().lower() == "end":
            break
        collected.append(line)

    processed = []
    edit_re = re.compile(r'^(?P<indent>\s*)edit\s+(?P<num>\d{10})(?P<rest>.*)$')
    for line in collected:
        stripped = line.lstrip()
        if stripped.lower().startswith("set uuid"):
            processed.append("# " + line)
            continue
        if stripped.lower().startswith("set online"):
            processed.append("# " + line)
            continue
        m = edit_re.match(line)
        if m:
            indent = m.group('indent') or ''
            rest = m.group('rest') or ''
            processed.append(f"{indent}edit 0{rest}\n")
            continue
        processed.append(line)

    out_path.write_text(''.join(processed), encoding="utf-8")
    return out_path


def main():
    p = argparse.ArgumentParser(description="Extract and sanitize 'config firewall policy' from a FortiGate-like .conf file")
    p.add_argument('input', help='Path to input .conf')
    p.add_argument('-o', '--output', help='Path to output file (optional)')
    args = p.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise SystemExit(f"Input file not found: {in_path}")

    if args.output:
        out_path = Path(args.output)
    else:
        stamp = datetime.now().strftime('%Y%m%d')
        out_path = in_path.with_name(f"{in_path.stem}_{stamp}.conf")

    saved = process_file(in_path, out_path)
    print(f"Wrote extracted policy to: {saved}")


if __name__ == '__main__':
    main()
