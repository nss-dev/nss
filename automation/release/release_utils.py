#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re
import sys
from subprocess import check_output


def exit_with_failure(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def version_string_to_underscore(version_string):
    """Convert version string like '3.118' to '3_118'."""
    return version_string.replace(".", "_")


def version_string_to_RTM_tag(version_string):
    """Convert version string like '3.118' to 'NSS_3_118_RTM'."""
    parts = version_string.split(".")
    return "NSS_" + "_".join(parts) + "_RTM"


def get_nspr_version(rev=None):
    """Read the NSPR version from automation/release/nspr-version.txt.

    If rev is given, reads the file at that hg revision; otherwise reads the
    working-directory copy.
    """
    nspr_version_file = "automation/release/nspr-version.txt"
    if rev is not None:
        try:
            content = check_output(["hg", "cat", "-r", rev, nspr_version_file]).decode()
            return content.splitlines()[0].strip()
        except Exception as e:
            exit_with_failure(
                f"Could not read {nspr_version_file} at revision {rev}: {e}"
            )
    try:
        with open(nspr_version_file, "r") as f:
            return f.readline().strip()
    except FileNotFoundError:
        exit_with_failure(
            f"Could not find {nspr_version_file}. Are you running from the NSS root directory?"
        )


def get_rtm_tag_date(rtm_tag):
    """Return the date of the RTM tag as a formatted string, or None if tag doesn't exist."""
    try:
        raw = (
            check_output(["hg", "log", "-r", rtm_tag, "--template", "{date|shortdate}"])
            .decode()
            .strip()
        )
        from datetime import datetime

        dt = datetime.strptime(raw, "%Y-%m-%d")
        return dt.strftime("%-d %B %Y")
    except Exception:
        return None


def tag_exists(tag):
    """Return True if the given Mercurial tag resolves in the current repo."""
    try:
        check_output(["hg", "log", "-r", tag, "--template", "x"])
        return True
    except Exception:
        return False


def default_branch_has_version(major, minor):
    """Return True if lib/nss/nss.h on the default branch tip has NSS_VMAJOR/VMINOR set to major.minor."""
    try:
        content = check_output(["hg", "cat", "-r", "default", "lib/nss/nss.h"]).decode()
        return re.search(
            rf"#define\s+NSS_VMAJOR\s+{re.escape(major)}\b", content
        ) and re.search(rf"#define\s+NSS_VMINOR\s+{re.escape(minor)}\b", content)
    except Exception:
        return False


def node_set(revset):
    """Return the set of short hashes matching revset."""
    try:
        result = (
            check_output(["hg", "log", "-r", revset, "--template", "{node|short}\\n"])
            .decode()
            .strip()
        )
    except Exception:
        return set()
    return set(result.split()) if result else set()


def graft_sources_on_branch(branch):
    """Return short hashes of default-branch commits grafted onto branch.

    These are the source= values recorded by hg graft, truncated to 12 chars
    to match the {node|short} format used elsewhere.
    """
    try:
        extras = check_output(
            ["hg", "log", "-r", f"::'{branch}'", "--template", "{extras}\\n"]
        ).decode()
    except Exception:
        return set()
    return {h[:12] for h in re.findall(r"(?<![a-z_])source=([0-9a-f]+)", extras)}


def find_beta_bump_commit(upper, prev_branch, major, minor):
    """Find the commit that first set lib/nss/nss.h to version {major}.{minor} Beta.

    Only searches commits reachable from upper but not from prev_branch, so it
    returns quickly when no beta bump was made.

    Returns the short hash of the commit, or None if not found.
    """
    try:
        cmd = [
            "hg",
            "log",
            "-r",
            f"filelog('lib/nss/nss.h') and ::'{upper}' and not ::'{prev_branch}'",
            "--template",
            "{node|short}\\n",
        ]
        result = check_output(cmd).decode().strip()
    except Exception as e:
        exit_with_failure(f"Failed to get nss.h history: {e}")

    if not result:
        return None

    commits = [c for c in result.split("\n") if c]  # hg log output is newest first

    # Search from oldest to newest to find the first commit showing this version as beta
    for commit in reversed(commits):
        try:
            content = check_output(
                ["hg", "cat", "-r", commit, "lib/nss/nss.h"]
            ).decode()
        except Exception:
            continue
        if (
            re.search(rf"#define\s+NSS_VMAJOR\s+{re.escape(major)}\b", content)
            and re.search(rf"#define\s+NSS_VMINOR\s+{re.escape(minor)}\b", content)
            and re.search(r"#define\s+NSS_BETA\s+PR_TRUE", content)
        ):
            return commit

    return None


def extract_bug_ids(bug_lines):
    """Extract integer bug IDs from formatted 'Bug N - description.' lines."""
    seen = set()
    ids = []
    for line in bug_lines:
        m = re.match(r"Bug\s+(\d+)", line, re.IGNORECASE)
        if m:
            bid = int(m.group(1))
            if bid not in seen:
                seen.add(bid)
                ids.append(bid)
    return ids


def get_bug_list_for_version(version):
    """Extract bug changes from Mercurial log for the given release version.

    For point releases (a.b.c), uses the previous RTM tag (NSS_A_B_RTM for
    3.x.1, NSS_A_B_{C-1}_RTM for later point releases) as the base.

    For regular releases (a.b), finds the commit that bumped lib/nss/nss.h to
    version a.b Beta and collects all commits after it on the release branch.
    Falls back to comparing with NSS_A_(B-1)_BRANCH if no beta bump is found.
    """
    parts = version.split(".")
    if len(parts) < 2:
        exit_with_failure(f"Invalid version format: {version}")

    major, minor = parts[0], parts[1]
    branch_name = f"NSS_{major}_{minor}_BRANCH"

    rtm_tag = version_string_to_RTM_tag(version)
    if tag_exists(rtm_tag):
        upper = rtm_tag
    elif tag_exists(branch_name):
        upper = branch_name
    elif default_branch_has_version(major, minor):
        print(f"Branch {branch_name} not yet created; using default branch.")
        upper = "default"
    else:
        exit_with_failure(
            f"Cannot find branch {branch_name} and default does not contain NSS {version}."
        )

    if len(parts) == 3:
        patch = int(parts[2])
        prev_version = (
            f"{major}.{minor}" if patch == 1 else f"{major}.{minor}.{patch - 1}"
        )
        prev_tag = version_string_to_RTM_tag(prev_version)
        print(f"Point release: collecting commits after {prev_tag} on {upper}.")
        revset = f"descendants('{prev_tag}') and ::'{upper}' and not '{prev_tag}'"
        grafted_away = set()
    else:
        prev_branch = f"NSS_{major}_{int(minor) - 1}_BRANCH"
        revset = f"::'{upper}' and not ::'{prev_branch}'"

        beta_bump = find_beta_bump_commit(upper, prev_branch, major, minor)
        if beta_bump:
            print(f"Found {version} beta version bump at {beta_bump}.")
            # Commits before the beta bump may have been grafted to the previous
            # branch for a point release; those belong to the previous version.
            grafted_to_prev = graft_sources_on_branch(prev_branch)
            pre_bump_nodes = node_set(
                f"::'{beta_bump}' and not ::'{prev_branch}' and not '{beta_bump}'"
            )
            grafted_away = pre_bump_nodes & grafted_to_prev
        else:
            print(f"Warning: No {version} beta version bump found in lib/nss/nss.h.")
            grafted_away = set()

    try:
        command = [
            "hg",
            "log",
            "-r",
            revset,
            "--template",
            "{node|short}\\t{desc|firstline}\\n",
        ]
        log_output = check_output(command).decode("utf-8")
    except Exception as e:
        exit_with_failure(f"Failed to get hg log: {e}")

    commits = []
    for line in log_output.split("\n"):
        if "\t" in line:
            node, title = line.split("\t", 1)
            commits.append((node.strip(), title.strip()))

    # Collect hashes that were backed out within this range
    backed_out = set()
    for _node, title in commits:
        m = re.search(r"\bBacked out changeset ([0-9a-f]+)\b", title, re.IGNORECASE)
        if m:
            backed_out.add(m.group(1))

    bug_lines = []
    for node, title in commits:
        if node in backed_out:
            continue  # this commit was backed out; skip it
        if re.search(r"\bBacked out changeset\b", title, re.IGNORECASE):
            continue  # this is a backout commit; skip it
        if node in grafted_away:
            continue  # pre-bump commit grafted to previous branch; belongs to previous version

        if not re.match(r"bug\s+\d+", title, re.IGNORECASE):
            continue

        line = title
        # Remove reviewer info from tail: r=, r?, or r! (with optional leading comma)
        line = re.sub(r",?\s+r[=?!]\S+$", "", line).strip()

        # Normalize "Bug N:" to "Bug N -"
        line = re.sub(r"(Bug\s+\d+):", r"\1 -", line, flags=re.IGNORECASE)

        # Ensure "Bug N - description" format (add dash if missing)
        line = re.sub(r"(Bug\s+\d+)\s+([^-])", r"\1 - \2", line, flags=re.IGNORECASE)

        line = line.rstrip(",").strip()

        if line and not line.endswith("."):
            line = line + "."

        if line and line not in bug_lines:
            bug_lines.append(line)

    return list(reversed(bug_lines))
