# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

NSS uses GYP + Ninja as its primary build system, driven by `build.sh` (or the `mach` wrapper):

```sh
./build.sh          # debug build → ../dist/Debug/
./build.sh -o       # optimized build → ../dist/Release/
./build.sh -c       # clean + build
./mach build        # equivalent wrapper
```

Common flags:
- `--asan` / `--msan` / `--ubsan` — sanitizer builds
- `--fuzz` / `--fuzz=tls` — fuzzing builds
- `--enable-fips` — FIPS-140 mode
- `--disable-tests` — skip building test binaries
- `-t <arch>` — cross-compile (x64, ia32, aarch64, …)

Output lands in `out/[Debug|Release]/` (build artifacts) and `../dist/[Debug|Release]/` (headers, libs, binaries).

A legacy Make-based build (`make nss_build_all`) also exists via `coreconf/` but GYP is preferred for new work.

## Tests

```sh
cd tests && ./all.sh                          # full test suite
NSS_TESTS=ssl_gtests ./all.sh                 # single suite
NSS_TESTS=ssl_gtests NSS_CYCLES=standard ./all.sh  # skip stress cycles
./mach tests ssl_gtests                       # mach wrapper
```

Available suites: `cipher`, `ssl`, `ssl_gtests`, `gtests`, `cert`, `smime`, `fips`, `ec`, `bogo`, `interop`, `policy`, and others. See `tests/all.sh` for the full list.

GTest binaries require a certificate database. Helper scripts create one and then invoke the binary:
```sh
# SSL gtests
./tests/ssl_gtests/ssl_gtest_db.sh ./ssl_gtest_certdb ../dist/Debug/bin/certutil
../dist/Debug/bin/ssl_gtests -d ./ssl_gtest_certdb

# Other gtests
./tests/gtests/gtest_db.sh ./gtest_certdb ../dist/Debug/bin/certutil
../dist/Debug/bin/pkcs11testmodule_gtest -d ./gtest_certdb   # example
```

## Code formatting and linting

```sh
./mach clang-format                # format changed files
./mach clang-format path/to/file.c # format specific file
./mach clang-tidy                  # static analysis
./mach clang-tidy --fix            # auto-fix where possible
```

## Architecture

NSS is a layered cryptographic library. The dependency flows roughly bottom-up:

**`lib/freebl/`** — standalone cryptographic primitives (ciphers, hashes, RNG, EC). No NSS dependencies; can be linked independently. Hardware acceleration (AES-NI, CLMUL, AVX, etc.) is selected at this layer.

**`lib/softoken/`** — software PKCS#11 token built on freebl. This is the default cryptographic "device" NSS uses. Legacy database support is in `lib/softoken/legacydb/`.

**`lib/pk11wrap/`** — PKCS#11 abstraction layer. All cryptographic operations above freebl go through here, allowing hardware tokens and HSMs to be swapped in transparently.

**`lib/certdb/` + `lib/certhigh/`** — certificate database (SQLite via `lib/sqlite/`, or legacy DBM via `lib/dbm/`) and high-level certificate operations.

**`lib/cryptohi/`** — high-level signing, verification, and hashing APIs layered over pk11wrap.

**`lib/ssl/`** — TLS 1.2, TLS 1.3, and DTLS implementation. Depends on cryptohi, certdb, and pk11wrap.

**`lib/nss/`** — top-level initialization and the public NSS API surface.

**`lib/smime/`, `lib/pkcs7/`, `lib/pkcs12/`** — higher-level protocol/format support built on the certificate and crypto layers.

**`lib/mozpkix/`** — Mozilla's standalone C++ PKIX certificate chain validation library (also used by Firefox directly).

**`lib/ckfw/`** — Cryptoki Framework: infrastructure for building PKCS#11 modules.

The `cmd/` directory contains command-line tools (`certutil`, `modutil`, `bltest`, etc.) that exercise the public API and are also used by the test suite.

GTests live in `gtests/` (unit tests per module) and `tests/ssl_gtests/` (SSL integration gtests). Shell-based integration tests are in `tests/`.

## mach

`./mach` is a Python 3 script that wraps common tasks:

```sh
./mach commands          # list all available commands
./mach coverage ssl_gtests   # source coverage report for a suite
./mach fuzz-coverage     # coverage for fuzzing targets
```

## Bugzilla and Phabricator

NSS tracks bugs in Bugzilla and uses Phabricator for code review. The `moz` MCP server gives direct access to both. The server is defined in `.mcp.json`; to enable it, create `.claude/settings.local.json` if it doesn't exist:

```json
{
  "enableAllProjectMcpServers": true,
  "enabledMcpjsonServers": ["moz"]
}
```

- `@moz:bugzilla://bug/{bug_id}` — retrieve a bug and its comments
- `@moz:phabricator://revision/D{revision_id}` — retrieve a Phabricator revision and its review comments

To find the Phabricator revision ID for a local commit, look for a `Differential Revision: https://phabricator.services.mozilla.com/D<N>` line in the commit message:
```sh
git log -v -l 10   # git
hg log -l 10       # mercurial
```

Never submit or update a Phabricator revision without explicit user approval.

## NSPR

NSS depends on NSPR (Netscape Portable Runtime) for OS abstraction. By default the build looks for it at `../nspr/`. Alternatives:
- `--system-nspr` — use the system-installed NSPR
- `--with-nspr=<path>` — specify a path explicitly
