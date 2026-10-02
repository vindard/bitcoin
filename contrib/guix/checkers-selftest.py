#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Characterization self-test for the release-binary checkers.

Compiles a small hardened baseline executable, then variants that each
differ from the baseline by exactly one property, and asserts which named
checks each variant fails in security-check.py and symbol-check.py. This
pins the checkers' current verdicts so that a future port of the checkers
off LIEF can be verified to preserve behavior exactly.

The fixtures are built with the host toolchain, run nothing, and only need
to be parseable by the checkers. Requires a C compiler ($CC, default cc)
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

REPO = Path(__file__).resolve().parent
CHECKERS = {
    'security-check': REPO / 'security-check.py',
    'symbol-check': REPO / 'symbol-check.py',
}

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
    checker: str
    fixture: str
    expected_failed: set[str]

SECURITY_CASES = [
    Case('security-check', 'baseline', set()),
    Case('security-check', 'no-relro', {'RELRO'}),                 # drops PT_GNU_RELRO
    Case('security-check', 'lazy-binding', {'RELRO'}),             # drops DF_BIND_NOW
    Case('security-check', 'no-canary', {'CANARY'}),
    Case('security-check', 'no-separate-code', {'SEPARATE_CODE'}),
    Case('security-check', 'no-pie', {'PIE'}),
    Case('security-check', 'no-fortify', {'FORTIFY'}),             # no __*_chk imports left
    Case('security-check', 'execstack', {'NX'}),
    Case('security-check', 'no-cf-protection', {'CONTROL_FLOW'}),  # no endbr64 at main
]

# symbol-check cases are expressed relative to the baseline probe: some
# checks (GLIBC version ceiling, GNU ABI tag) legitimately fail for host-
# built fixtures on modern hosts, and those baseline failures must carry
# over unchanged while exactly the named check is newly failed.
SYMBOL_CASES = [
    Case('symbol-check', 'exported-symbols', {'EXPORTED_SYMBOLS'}),
    Case('symbol-check', 'disallowed-library', {'LIBRARY_DEPENDENCIES'}),
    Case('symbol-check', 'nonstandard-interpreter', {'INTERPRETER_NAME'}),
]

EXPORTED_C_SOURCE = C_SOURCE + '''
int checker_selftest_extra_fn(void)
{
    return 1;
}
'''

FIXTURES = [
    Fixture('no-relro', ['-Wl,-z,norelro']),
    Fixture('lazy-binding', ['-Wl,-z,lazy']),
    Fixture('no-canary', ['-fno-stack-protector']),
    Fixture('no-separate-code', ['-Wl,-z,noseparate-code']),
    Fixture('no-pie', ['-no-pie']),
    Fixture('no-fortify', ['-U_FORTIFY_SOURCE']),
    Fixture('execstack', ['-Wl,-z,execstack']),
    Fixture('no-cf-protection', ['-fcf-protection=none']),
    Fixture('exported-symbols', ['-rdynamic'], source=EXPORTED_C_SOURCE),
    # libcrypt is not in ELF_ALLOWED_LIBRARIES; the crypt() call keeps the
    # NEEDED entry alive under --as-needed.
    Fixture('disallowed-library', ['-lcrypt'], source=C_SOURCE + '''
#include <crypt.h>

int checker_selftest_uses_crypt(void)
{
    return crypt("x", "y") != 0;
}
'''),
    Fixture('nonstandard-interpreter', ['-Wl,--dynamic-linker=/nonstandard-loader.so']),
    # A RUNPATH currently makes symbol-check.py die on an assert instead of
    # reporting a named failure; pin only that it fails the binary.
    Fixture('runpath', ['-Wl,-rpath,/tmp']),
]

FAILED_RE = re.compile(r'^\S+: failed (.*)$')

def run_checker(checker: str, binary: Path) -> tuple[int, set[str]]:
    proc = subprocess.run(
        [sys.executable, str(CHECKERS[checker]), str(binary)],
        capture_output=True, text=True, check=False)
    failed: set[str] = set()
    for line in proc.stdout.splitlines():
        match = FAILED_RE.match(line)
        if match:
            failed = set(match.group(1).split())
    return proc.returncode, failed

def compile_c(cc: str, source: str, cflags: list[str], srcdir: Path,
              name: str) -> Path | None:
    src = srcdir / f'{name}.c'
    out = srcdir / name
    src.write_text(source)
    cmd = [cc] + cflags + [str(src), '-o', str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(f'skip {name}: host compiler rejected fixture flags')
        print(proc.stderr)
        return None
    return out

def build_fixtures(cc: str, srcdir: Path) -> dict[str, Path]:
    binaries: dict[str, Path] = {}
    base = compile_c(cc, C_SOURCE, BASELINE_CFLAGS, srcdir, 'baseline')
    if base is None:
        print('error: host compiler cannot build the hardened baseline')
        return {}
    binaries['baseline'] = base
    for fixture in FIXTURES:
        built = compile_c(cc, fixture.source,
                          BASELINE_CFLAGS + fixture.extra_cflags,
                          srcdir, fixture.name)
        if built is not None:
            binaries[fixture.name] = built
    return binaries

def check_case(case: Case, binaries: dict[str, Path], want_failed: set[str]) -> int:
    binary = binaries.get(case.fixture)
    if binary is None:
        return 0
    rc, failed = run_checker(case.checker, binary)
    want_rc = 1 if want_failed else 0
    if rc != want_rc or failed != want_failed:
        print(f'FAIL {case.checker} {case.fixture}: '
              f'exit={rc} failed={sorted(failed)} '
              f'expected exit={want_rc} failed={sorted(want_failed)}')
        return 1
    print(f'ok {case.checker} {case.fixture}: {sorted(failed)}')
    return 0

def check_lief() -> bool:
    try:
        import lief  # noqa: F401
    except ImportError:
        print('error: lief is not installed for the running interpreter; '
              'see ci/lint/requirements.txt')
        return False
    return True

def main() -> int:
    if not check_lief():
        return 1
    cc = os.environ.get('CC', 'cc')
    failures = 0
    with tempfile.TemporaryDirectory(prefix='checker-selftest-') as tmp:
        srcdir = Path(tmp)
        binaries = build_fixtures(cc, srcdir)
        if 'baseline' not in binaries:
            return 1

        for case in SECURITY_CASES:
            failures += check_case(case, binaries, set(case.expected_failed))

        # symbol-check: probe the baseline to learn which checks fail for
        # host-built fixtures (GLIBC ceiling, ABI tag), then require each
        # negative fixture to fail exactly the probe set plus its own check.
        base_rc, base_failed = run_checker('symbol-check', binaries['baseline'])
        if base_rc not in (0, 1):
            print(f'FAIL symbol-check baseline: unexpected exit {base_rc}')
            return 1
        if base_failed:
            print(f'note: host baseline fails symbol-check {sorted(base_failed)} '
                  '(expected on hosts newer than the release targets)')
        print(f'ok symbol-check baseline: {sorted(base_failed)}')
        for case in SYMBOL_CASES:
            failures += check_case(case, binaries,
                                   base_failed | case.expected_failed)

        # A RUNPATH currently aborts symbol-check.py on an assert instead of
        # reporting a named failure; pin only that the binary is rejected.
        if 'runpath' in binaries:
            rc, _ = run_checker('symbol-check', binaries['runpath'])
            if rc == 0:
                failures += 1
                print('FAIL symbol-check runpath: accepted a binary with RUNPATH')
            else:
                print('ok symbol-check runpath: rejected')
    return 1 if failures else 0

if __name__ == '__main__':
    sys.exit(main())
