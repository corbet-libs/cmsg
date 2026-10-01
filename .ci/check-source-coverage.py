#!/usr/bin/env python3
"""Require every emitted LLVM source line and branch; no production exclusions.

LCOV is exported from the same execution as the retained JSON diagnostic. This
measures source coverage, not separate coverage of every generic instantiation.
"""
import sys
from pathlib import Path


def check(text):
    source = None
    lines, branches = {}, {}
    for record in text.splitlines():
        if record.startswith('SF:'):
            source = record[3:]
            if not source:
                raise ValueError('Missing source filename')
        elif record.startswith('DA:'):
            line, count = map(int, record[3:].split(',')[:2])
            key = (source, line)
            if not source or line <= 0 or count < 0 or key in lines:
                raise ValueError('Invalid or duplicated source line')
            lines[key] = count
        elif record.startswith('BRDA:'):
            line, block, branch, count = record[5:].split(',')
            key = (source, int(line), block, branch)
            count = 0 if count == '-' else int(count)
            if not source or int(line) <= 0 or count < 0 or key in branches:
                raise ValueError('Invalid or duplicated source branch')
            branches[key] = count
        elif record == 'end_of_record':
            source = None
    if not lines:
        raise ValueError('Empty coverage cannot pass')
    misses = [str(key) for rows in (lines, branches) for key, count in rows.items() if count == 0]
    print(f'lines: {sum(n > 0 for n in lines.values())}/{len(lines)}')
    print(f'branches: {sum(n > 0 for n in branches.values())}/{len(branches)}')
    if misses:
        raise ValueError('Uncovered: ' + '; '.join(misses))


if __name__ == '__main__':
    try:
        check(Path(sys.argv[1]).read_text())
    except (ValueError, IndexError, OSError) as error:
        sys.exit(f'Coverage gate: {error}')
