#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Run clang-tidy on NSS source files using compile_commands.json."""

import argparse
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}

DEFAULT_EXCLUDES = {
    "gtests/google_test",
    "lib/sqlite",
    "lib/zlib",
    "lib/freebl/verified",
}


def find_compile_commands(repo_root):
    """Locate compile_commands.json in common build output locations."""
    candidates = [
        os.path.join(repo_root, "out", "Debug", "compile_commands.json"),
        os.path.join(repo_root, "out", "Release", "compile_commands.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def ensure_compile_commands(repo_root):
    """Build NSS and generate compile_commands.json if missing.

    Returns the path to compile_commands.json, or None on failure.
    """
    cc_path = find_compile_commands(repo_root)
    if cc_path:
        return cc_path

    target_dir = os.path.join(repo_root, "out", "Debug")
    cc_path = os.path.join(target_dir, "compile_commands.json")

    print("compile_commands.json not found — building NSS...", file=sys.stderr)
    result = subprocess.run([os.path.join(repo_root, "build.sh")], cwd=repo_root)
    if result.returncode != 0:
        print("error: build.sh failed", file=sys.stderr)
        return None

    print("Generating compile_commands.json...", file=sys.stderr)
    with open(cc_path, "w") as f:
        result = subprocess.run(
            ["ninja", "-C", target_dir, "-t", "compdb"], stdout=f, cwd=repo_root
        )
    if result.returncode != 0:
        print("error: ninja compdb failed", file=sys.stderr)
        return None

    return cc_path


def load_translation_units(
    compile_commands_path, repo_root, include_paths=None, exclude_paths=None, files=None
):
    """Load and filter translation units from compile_commands.json.

    Args:
        compile_commands_path: Path to compile_commands.json.
        repo_root: Repository root for computing relative paths.
        include_paths: If set, only include files under these prefixes.
        exclude_paths: Exclude files matching these prefixes.
        files: If set, only include these specific files.

    Returns:
        List of (file, directory, command) tuples.
    """
    with open(compile_commands_path) as f:
        entries = json.load(f)
    excludes = DEFAULT_EXCLUDES | set(exclude_paths or [])

    units = []
    seen = set()
    for entry in entries:
        src = entry.get("file", "")
        directory = entry.get("directory", "")
        # Resolve to repo-relative path for filtering.
        if os.path.isabs(src):
            abs_src = src
        else:
            abs_src = os.path.normpath(os.path.join(directory, src))
        rel = os.path.relpath(abs_src, repo_root)

        ext = os.path.splitext(rel)[1]
        if ext not in EXTENSIONS:
            continue

        if any(rel.startswith(ex) for ex in excludes):
            continue

        if include_paths and not any(rel.startswith(p) for p in include_paths):
            continue

        if files is not None:
            # Match against both absolute and relative paths.
            if rel not in files and abs_src not in files and src not in files:
                continue

        # Deduplicate: a file may appear multiple times in
        # compile_commands.json (e.g. compiled for different targets).
        # Only analyse each source file once.
        if rel in seen:
            continue
        seen.add(rel)

        units.append((src, directory, entry))

    return units


def parse_diff(diff_text):
    """Parse unified diff output into a dict of {file: [[start, end], ...]}.

    Only tracks added/modified line ranges (the ``+`` side of the diff) so
    that we can tell clang-tidy which lines are "interesting".
    """
    file_lines = {}
    current_file = None
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in diff_text.splitlines():
        # Detect the destination filename.
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("+++ "):
            # hg-style: +++ b/path or +++ path
            current_file = line[4:].lstrip("b/")
            continue

        m = hunk_re.match(line)
        if m and current_file is not None:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count == 0:
                # Pure deletion hunk — no new lines.
                continue
            end = start + count - 1
            file_lines.setdefault(current_file, []).append([start, end])

    return file_lines


def build_line_filter(changed_lines, repo_root, compile_commands_path):
    """Build a clang-tidy --line-filter JSON string from *changed_lines*.

    *changed_lines* is the dict returned by :func:`parse_diff`.
    *compile_commands_path* is used to determine the build directory so
    that paths in the filter match the ``file`` entries that clang-tidy
    sees from compile_commands.json.
    Returns a JSON string suitable for ``--line-filter=...``, or *None*
    if there are no entries.
    """
    if not changed_lines:
        return None
    # clang-tidy matches --line-filter names against the "file" field in
    # compile_commands.json.  For NSS those are typically relative to the
    # build directory (e.g. "../../lib/foo/bar.c").  Construct the same
    # relative paths so the filter actually matches.
    build_dir = os.path.dirname(os.path.abspath(compile_commands_path))
    entries = []
    for path, ranges in changed_lines.items():
        abs_path = os.path.normpath(os.path.join(repo_root, path))
        rel_path = os.path.relpath(abs_path, build_dir)
        entries.append({"name": rel_path, "lines": ranges})
    return json.dumps(entries, separators=(",", ":"))


def get_diff(repo_root, base_rev=None):
    """Obtain a unified diff from the VCS in *repo_root*.

    If *base_rev* is given it is used as the base revision; otherwise the
    working-directory changes are diffed.
    """
    if os.path.isdir(os.path.join(repo_root, ".hg")):
        cmd = ["hg", "diff", "-U0"]
        if base_rev:
            cmd += ["--rev", base_rev]
    elif os.path.isdir(os.path.join(repo_root, ".git")):
        if base_rev:
            cmd = ["git", "diff", "-U0", base_rev]
        else:
            cmd = ["git", "diff", "-U0", "HEAD"]
    else:
        return None

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_root)
    if result.returncode != 0:
        return None
    return result.stdout


def run_one(
    clang_tidy, src, directory, entry, checks, fix, fail_on_warnings, line_filter=None
):
    """Run clang-tidy on a single translation unit."""
    cmd = [clang_tidy, "-p", directory]

    if checks:
        cmd += ["--checks=" + checks]

    if fix:
        cmd += ["--fix"]

    if fail_on_warnings:
        cmd += ["--warnings-as-errors=*"]

    if line_filter:
        cmd += ["--line-filter=" + line_filter]

    cmd.append(src)

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=directory)
    return src, result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run clang-tidy on NSS source files")
    parser.add_argument(
        "-p",
        "--compile-commands",
        help="Path to compile_commands.json (auto-detected if omitted)",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=os.cpu_count(),
        help="Number of parallel jobs (default: CPU count)",
    )
    parser.add_argument(
        "--clang-tidy", default="clang-tidy", help="Path to clang-tidy binary"
    )
    parser.add_argument(
        "--checks", help="Override checks (passed to clang-tidy --checks)"
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        help="Only analyse files under these path prefixes",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude files under these path prefixes",
    )
    parser.add_argument(
        "--fail-on-warnings", action="store_true", help="Treat all warnings as errors"
    )
    parser.add_argument(
        "--fix", action="store_true", help="Apply suggested fixes in-place"
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build NSS and generate compile_commands.json if missing",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Only report diagnostics on changed lines (uses VCS diff)",
    )
    parser.add_argument(
        "--diff-base",
        help="Base revision for --diff (default: working-directory changes)",
    )
    parser.add_argument(
        "files", nargs="*", help="Specific files to check (default: all matching files)"
    )

    args = parser.parse_args(argv)

    # Locate repo root (parent of automation/).
    repo_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    # Find compile_commands.json.
    if args.compile_commands:
        cc_path = args.compile_commands
    elif args.build:
        cc_path = ensure_compile_commands(repo_root)
    else:
        cc_path = find_compile_commands(repo_root)

    if not cc_path or not os.path.isfile(cc_path):
        print(
            "error: compile_commands.json not found.  "
            "Build first with: ./build.sh (or pass --build)",
            file=sys.stderr,
        )
        return 1

    # Build a line filter when --diff is requested, and restrict the
    # file set to only files that appear in the diff.
    line_filter = None
    diff_files = None
    if args.diff or args.diff_base:
        diff_text = get_diff(repo_root, args.diff_base)
        if diff_text is None:
            print("error: could not obtain diff from VCS", file=sys.stderr)
            return 1
        changed_lines = parse_diff(diff_text)
        line_filter = build_line_filter(changed_lines, repo_root, cc_path)
        diff_files = set(os.path.normpath(f) for f in changed_lines)

    include_paths = args.include or None
    file_set = set(os.path.normpath(f) for f in args.files) if args.files else None

    # When diffing, restrict to changed files (intersect with any
    # explicit file list if one was provided).
    if diff_files is not None:
        if file_set is not None:
            file_set = file_set & diff_files
        else:
            file_set = diff_files

    units = load_translation_units(
        cc_path,
        repo_root,
        include_paths=include_paths,
        exclude_paths=args.exclude,
        files=file_set,
    )

    if not units:
        if file_set:
            print("No matching translation units for the given files.", file=sys.stderr)
            return 0
        print("No translation units found.", file=sys.stderr)
        return 1

    print("Running clang-tidy on {} file(s)...".format(len(units)), file=sys.stderr)

    jobs = args.jobs

    failures = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(
                run_one,
                args.clang_tidy,
                src,
                directory,
                entry,
                args.checks,
                args.fix,
                args.fail_on_warnings,
                line_filter,
            ): src
            for src, directory, entry in units
        }

        for future in as_completed(futures):
            src, result = future.result()
            # Print any output (diagnostics) from clang-tidy.
            if result.stdout:
                print(result.stdout, end="")
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)
            if result.returncode != 0:
                failures.append(src)

    if failures:
        print(
            "\nclang-tidy found issues in {} file(s):".format(len(failures)),
            file=sys.stderr,
        )
        for f in sorted(failures):
            print("  {}".format(f), file=sys.stderr)
        return 1

    print("clang-tidy: no issues found.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
