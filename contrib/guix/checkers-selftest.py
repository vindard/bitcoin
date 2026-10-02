#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Characterization self-test for the release-binary checkers.

Compiles a small hardened baseline executable, then variants that each
differ from the baseline by exactly one hardening property, and asserts
which named checks each variant fails in security-check.py. This pins the
checker's current verdicts so that a future port of the checkers off LIEF
can be verified to preserve behavior exactly.

The fixtures are built with the host toolchain, run nothing, and only need
to be parseable by the checker. Requires a C compiler ($CC, default cc)
and a Python environment with lief installed (as in ci/lint/requirements.txt).

Example usage:

    python3 contrib/guix/checkers-selftest.py
'''

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

CHECKER = Path(__file__).resolve().parent / 'security-check.py'

# Baseline flags satisfy every ELF check in security-check.py on x86_64.
# Each negative fixture below appends flags that override exactly one of
# them; both the compiler and the linker apply the last occurrence of a
# repeated option, so append-only deltas are well-defined.
BASELINE_CFLAGS = [
    '-O2',
    '-D_FORTIFY_SOURCE=2',
    '-fstack-protector-strong',
    '-fcf-protection=full',
    '-fPIE',
    '-pie',
    '-Wl,-z,relro,-z,now,-z,separate-code',
]

C_SOURCE = r'''
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buf[64];
    /* Becomes __snprintf_chk under _FORTIFY_SOURCE, satisfying FORTIFY. */
    snprintf(buf, sizeof(buf), "%d", 42);
    return (int)strlen(buf) - 2;
}
'''

@dataclass
class Fixture:
    name: str
    extra_cflags: list[str] = field(default_factory=list)
    source: str = C_SOURCE

@dataclass
class Case:
    fixture: str
    expected_failed: set[str]  # exact set of named checks that must fail

SECURITY_CASES = [
    Case('baseline', set()),
    Case('no-relro', {'RELRO'}),                 # -Wl,-z,norelro drops PT_GNU_RELRO
    Case('lazy-binding', {'RELRO'}),             # -Wl,-z,lazy drops DF_BIND_NOW
    Case('no-canary', {'CANARY'}),
    Case('no-separate-code', {'SEPARATE_CODE'}),
    Case('no-pie', {'PIE'}),
    Case('no-fortify', {'FORTIFY'}),             # no __*_chk imports left
    Case('execstack', {'NX'}),
    Case('no-cf-protection', {'CONTROL_FLOW'}),  # main does not start with endbr64
]

FIXTURES = [
    Fixture('no-relro', ['-Wl,-z,norelro']),
    Fixture('lazy-binding', ['-Wl,-z,lazy']),
    Fixture('no-canary', ['-fno-stack-protector']),
    Fixture('no-separate-code', ['-Wl,-z,noseparate-code']),
    Fixture('no-pie', ['-no-pie']),
    Fixture('no-fortify', ['-U_FORTIFY_SOURCE']),
    Fixture('execstack', ['-Wl,-z,execstack']),
    Fixture('no-cf-protection', ['-fcf-protection=none']),
]

FAILED_RE = re.compile(r'^\S+: failed (.*)$')

def run_checker(binary: Path) -> tuple[int, set[str]]:
    proc = subprocess.run(
        [sys.executable, str(CHECKER), str(binary)],
        capture_output=True, text=True, check=False)
    failed: set[str] = set()
    for line in proc.stdout.splitlines():
        match = FAILED_RE.match(line)
        if match:
            failed = set(match.group(1).split())
    return proc.returncode, failed

def compile_fixture(cc: str, fixture: Fixture, srcdir: Path) -> Path | None:
    src = srcdir / f'{fixture.name}.c'
    out = srcdir / fixture.name
    src.write_text(fixture.source)
    cmd = [cc] + BASELINE_CFLAGS + fixture.extra_cflags + [str(src), '-o', str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(f'skip {fixture.name}: host compiler rejected fixture flags')
        print(proc.stderr)
        return None
    return out

def main() -> int:
    if not check_lief():
        return 1
    cc = os.environ.get('CC', 'cc')
    failures = 0
    with tempfile.TemporaryDirectory(prefix='checker-selftest-') as tmp:
        srcdir = Path(tmp)
        binaries: dict[str, Path] = {}
        base_src = srcdir / 'baseline.c'
        base_src.write_text(C_SOURCE)
        proc = subprocess.run(
            [cc] + BASELINE_CFLAGS + [str(base_src), '-o', str(srcdir / 'baseline')],
            capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            print('error: host compiler cannot build the hardened baseline')
            print(proc.stderr)
            return 1
        binaries['baseline'] = srcdir / 'baseline'
        for fixture in FIXTURES:
            built = compile_fixture(cc, fixture, srcdir)
            if built is not None:
                binaries[fixture.name] = built

        for case in SECURITY_CASES:
            binary = binaries.get(case.fixture)
            if binary is None:
                continue
            rc, failed = run_checker(binary)
            expected_rc = 1 if case.expected_failed else 0
            if rc != expected_rc or failed != case.expected_failed:
                failures += 1
                print(f'FAIL security-check {case.fixture}: '
                      f'exit={rc} failed={sorted(failed)} '
                      f'expected exit={expected_rc} failed={sorted(case.expected_failed)}')
            else:
                print(f'ok security-check {case.fixture}: {sorted(failed)}')
    return 1 if failures else 0

def check_lief() -> bool:
    try:
        import lief  # noqa: F401
    except ImportError:
        print('error: lief is not installed for the running interpreter; '
              'see ci/lint/requirements.txt')
        return False
    return True

if __name__ == '__main__':
    sys.exit(main())
