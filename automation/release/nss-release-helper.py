#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import sys
import shutil
import re
import tempfile
from optparse import OptionParser
from subprocess import check_call
from subprocess import check_output

nssutil_h = "lib/util/nssutil.h"
softkver_h = "lib/softoken/softkver.h"
nss_h = "lib/nss/nss.h"
nssckbi_h = "lib/ckfw/builtins/nssckbi.h"
abi_base_version_file = "automation/abi-check/previous-nss-release"

abi_report_files = ['automation/abi-check/expected-report-libfreebl3.so.txt',
                    'automation/abi-check/expected-report-libfreeblpriv3.so.txt',
                    'automation/abi-check/expected-report-libnspr4.so.txt',
                    'automation/abi-check/expected-report-libnss3.so.txt',
                    'automation/abi-check/expected-report-libnssckbi.so.txt',
                    'automation/abi-check/expected-report-libnssdbm3.so.txt',
                    'automation/abi-check/expected-report-libnsssysinit.so.txt',
                    'automation/abi-check/expected-report-libnssutil3.so.txt',
                    'automation/abi-check/expected-report-libplc4.so.txt',
                    'automation/abi-check/expected-report-libplds4.so.txt',
                    'automation/abi-check/expected-report-libsmime3.so.txt',
                    'automation/abi-check/expected-report-libsoftokn3.so.txt',
                    'automation/abi-check/expected-report-libssl3.so.txt']


def check_call_noisy(cmd, *args, **kwargs):
    print("Executing command: {}".format(cmd))
    check_call(cmd, *args, **kwargs)


def print_separator():
    print("=" * 70)


def exit_with_failure(what):
    print("failure: {}".format(what))
    sys.exit(2)


def check_files_exist():
    if (not os.path.exists(nssutil_h) or not os.path.exists(softkver_h)
            or not os.path.exists(nss_h) or not os.path.exists(nssckbi_h)):
        exit_with_failure("cannot find expected header files, must run from inside NSS hg directory")


class Replacement():
    def __init__(self, regex="", repl=""):
        self.regex = regex
        self.repl = repl
        self.matcher = re.compile(self.regex)

    def replace(self, line):
        return self.matcher.sub(self.repl, line)


def inplace_replace(replacements=[], filename=""):
    for r in replacements:
        if not isinstance(r, Replacement):
            raise TypeError("Expecting a list of Replacement objects")

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        with open(filename) as in_file:
            for line in in_file:
                for r in replacements:
                    line = r.replace(line)
                tmp_file.write(line)
        tmp_file.flush()

        shutil.copystat(filename, tmp_file.name)
        shutil.move(tmp_file.name, filename)
        os.utime(filename, None)


def toggle_beta_status(is_beta):
    check_files_exist()
    if (is_beta):
        print("adding Beta status to version numbers")
        inplace_replace(filename=nssutil_h, replacements=[
            Replacement(regex=r'^(#define *NSSUTIL_VERSION *\"[0-9.]+)\" *$',
                        repl=r'\g<1> Beta"'),
            Replacement(regex=r'^(#define *NSSUTIL_BETA *)PR_FALSE *$',
                        repl=r'\g<1>PR_TRUE')])
        inplace_replace(filename=softkver_h, replacements=[
            Replacement(regex=r'^(#define *SOFTOKEN_VERSION *\"[0-9.]+\" *SOFTOKEN_ECC_STRING) *$',
                        repl=r'\g<1> " Beta"'),
            Replacement(regex=r'^(#define *SOFTOKEN_BETA *)PR_FALSE *$',
                        repl=r'\g<1>PR_TRUE')])
        inplace_replace(filename=nss_h, replacements=[
            Replacement(regex=r'^(#define *NSS_VERSION *\"[0-9.]+\" *_NSS_CUSTOMIZED) *$',
                        repl=r'\g<1> " Beta"'),
            Replacement(regex=r'^(#define *NSS_BETA *)PR_FALSE *$',
                        repl=r'\g<1>PR_TRUE')])
    else:
        print("removing Beta status from version numbers")
        inplace_replace(filename=nssutil_h, replacements=[
            Replacement(regex=r'^(#define *NSSUTIL_VERSION *\"[0-9.]+) *Beta\" *$',
                        repl=r'\g<1>"'),
            Replacement(regex=r'^(#define *NSSUTIL_BETA *)PR_TRUE *$',
                        repl=r'\g<1>PR_FALSE')])
        inplace_replace(filename=softkver_h, replacements=[
            Replacement(regex=r'^(#define *SOFTOKEN_VERSION *\"[0-9.]+\" *SOFTOKEN_ECC_STRING) *\" *Beta\" *$',
                        repl=r'\g<1>'),
            Replacement(regex=r'^(#define *SOFTOKEN_BETA *)PR_TRUE *$',
                        repl=r'\g<1>PR_FALSE')])
        inplace_replace(filename=nss_h, replacements=[
            Replacement(regex=r'^(#define *NSS_VERSION *\"[0-9.]+\" *_NSS_CUSTOMIZED) *\" *Beta\" *$',
                        repl=r'\g<1>'),
            Replacement(regex=r'^(#define *NSS_BETA *)PR_TRUE *$',
                        repl=r'\g<1>PR_FALSE')])

    print("please run 'hg stat' and 'hg diff' to verify the files have been verified correctly")


def print_beta_versions():
    check_call_noisy(["egrep", "#define *NSSUTIL_VERSION|#define *NSSUTIL_BETA", nssutil_h])
    check_call_noisy(["egrep", "#define *SOFTOKEN_VERSION|#define *SOFTOKEN_BETA", softkver_h])
    check_call_noisy(["egrep", "#define *NSS_VERSION|#define *NSS_BETA", nss_h])


def remove_beta_status():
    print("--- removing beta flags. Existing versions were:")
    print_beta_versions()
    toggle_beta_status(False)
    print("=" * 70)
    print("--- finished modifications, new versions are:")
    print("=" * 70)
    print_beta_versions()


def set_beta_status():
    print("--- adding beta flags. Existing versions were:")
    print_beta_versions()
    toggle_beta_status(True)
    print("--- finished modifications, new versions are:")
    print_beta_versions()


def print_library_versions():
    check_files_exist()
    check_call_noisy(["egrep", "#define *NSSUTIL_VERSION|#define NSSUTIL_VMAJOR|#define *NSSUTIL_VMINOR|#define *NSSUTIL_VPATCH|#define *NSSUTIL_VBUILD|#define *NSSUTIL_BETA", nssutil_h])
    check_call_noisy(["egrep", "#define *SOFTOKEN_VERSION|#define SOFTOKEN_VMAJOR|#define *SOFTOKEN_VMINOR|#define *SOFTOKEN_VPATCH|#define *SOFTOKEN_VBUILD|#define *SOFTOKEN_BETA", softkver_h])
    check_call_noisy(["egrep", "#define *NSS_VERSION|#define NSS_VMAJOR|#define *NSS_VMINOR|#define *NSS_VPATCH|#define *NSS_VBUILD|#define *NSS_BETA", nss_h])


def print_root_ca_version():
    check_files_exist()
    check_call_noisy(["grep", "define *NSS_BUILTINS_LIBRARY_VERSION", nssckbi_h])


def ensure_arguments_count(args, how_many, usage):
    if (len(args) != how_many):
        exit_with_failure("incorrect number of arguments, expected parameters are:\n" + usage)


def set_major_versions(major):
    for name, file in [["NSSUTIL_VMAJOR", nssutil_h],
                       ["SOFTOKEN_VMAJOR", softkver_h],
                       ["NSS_VMAJOR", nss_h]]:
        inplace_replace(filename=file, replacements=[
            Replacement(regex=r'^(#define *{} ?).*$'.format(name),
                        repl=r'\g<1>{}'.format(major))])


def set_minor_versions(minor):
    for name, file in [["NSSUTIL_VMINOR", nssutil_h],
                       ["SOFTOKEN_VMINOR", softkver_h],
                       ["NSS_VMINOR", nss_h]]:
        inplace_replace(filename=file, replacements=[
            Replacement(regex=r'^(#define *{} ?).*$'.format(name),
                        repl=r'\g<1>{}'.format(minor))])


def set_patch_versions(patch):
    for name, file in [["NSSUTIL_VPATCH", nssutil_h],
                       ["SOFTOKEN_VPATCH", softkver_h],
                       ["NSS_VPATCH", nss_h]]:
        inplace_replace(filename=file, replacements=[
            Replacement(regex=r'^(#define *{} ?).*$'.format(name),
                        repl=r'\g<1>{}'.format(patch))])


def set_build_versions(build):
    for name, file in [["NSSUTIL_VBUILD", nssutil_h],
                       ["SOFTOKEN_VBUILD", softkver_h],
                       ["NSS_VBUILD", nss_h]]:
        inplace_replace(filename=file, replacements=[
            Replacement(regex=r'^(#define *{} ?).*$'.format(name),
                        repl=r'\g<1>{}'.format(build))])


def set_full_lib_versions(version):
    for name, file in [["NSSUTIL_VERSION", nssutil_h],
                       ["SOFTOKEN_VERSION", softkver_h],
                       ["NSS_VERSION", nss_h]]:
        inplace_replace(filename=file, replacements=[
            Replacement(regex=r'^(#define *{} *\")([0-9.]+)(.*)$'.format(name),
                        repl=r'\g<1>{}\g<3>'.format(version))])


def set_root_ca_version(args):
    ensure_arguments_count(args, 2, "major_version  minor_version")
    major = args[0].strip()
    minor = args[1].strip()
    version = major + '.' + minor

    inplace_replace(filename=nssckbi_h, replacements=[
        Replacement(regex=r'^(#define *NSS_BUILTINS_LIBRARY_VERSION *\").*$',
                    repl=r'\g<1>{}"'.format(version)),
        Replacement(regex=r'^(#define *NSS_BUILTINS_LIBRARY_VERSION_MAJOR ?).*$',
                    repl=r'\g<1>{}'.format(major)),
        Replacement(regex=r'^(#define *NSS_BUILTINS_LIBRARY_VERSION_MINOR ?).*$',
                    repl=r'\g<1>{}'.format(minor))])


def set_all_lib_versions(version, major, minor, patch, build):
    grep_major = check_output(['grep', 'define.*NSS_VMAJOR', nss_h])
    grep_minor = check_output(['grep', 'define.*NSS_VMINOR', nss_h])

    old_major = int(grep_major.split()[2])
    old_minor = int(grep_minor.split()[2])

    new_major = int(major)
    new_minor = int(minor)

    if (old_major < new_major or (old_major == new_major and old_minor < new_minor)):
        print("You're increasing the minor (or major) version:")
        print("- erasing ABI comparison expectations")
        new_branch = "NSS_" + str(old_major) + "_" + str(old_minor) + "_BRANCH"
        print("- setting reference branch to the branch of the previous version: " + new_branch)
        with open(abi_base_version_file, "w") as abi_base:
            abi_base.write("%s\n" % new_branch)
        for report_file in abi_report_files:
            with open(report_file, "w") as report_file_handle:
                report_file_handle.truncate()

    set_full_lib_versions(version)
    set_major_versions(major)
    set_minor_versions(minor)
    set_patch_versions(patch)
    set_build_versions(build)


def set_version_to_minor_release(args):
    ensure_arguments_count(args, 2, "major_version  minor_version")
    major = args[0].strip()
    minor = args[1].strip()
    version = major + '.' + minor
    patch = "0"
    build = "0"
    set_all_lib_versions(version, major, minor, patch, build)


def set_version_to_patch_release(args):
    ensure_arguments_count(args, 3, "major_version  minor_version  patch_release")
    major = args[0].strip()
    minor = args[1].strip()
    patch = args[2].strip()
    version = major + '.' + minor + '.' + patch
    build = "0"
    set_all_lib_versions(version, major, minor, patch, build)


def set_release_candidate_number(args):
    ensure_arguments_count(args, 1, "release_candidate_number")
    build = args[0].strip()
    set_build_versions(build)


def set_4_digit_release_number(args):
    ensure_arguments_count(args, 4, "major_version  minor_version  patch_release  4th_digit_release_number")
    major = args[0].strip()
    minor = args[1].strip()
    patch = args[2].strip()
    build = args[3].strip()
    version = major + '.' + minor + '.' + patch + '.' + build
    set_all_lib_versions(version, major, minor, patch, build)


def make_release_branch(args):
    ensure_arguments_count(args, 2, "version_string remote")
    version_string = args[0].strip()
    remote = args[1].strip()

    major, minor, patch = parse_version_string(version_string)
    if patch is not None:
        exit_with_failure("make_release_branch expects a minor version (e.g., '3.117'), not a patch version.")

    version = f"{major}.{minor}"
    branch_name = f"NSS_{major}_{minor}_BRANCH"
    tag_name = f"NSS_{major}_{minor}_BETA1"

    print_separator()
    print("MAKE RELEASE BRANCH")
    print_separator()
    print(f"Version: {version}")
    print(f"Remote: {remote}")
    print_separator()

    response = input('Are these parameters correct? [yN]: ')
    if 'y' not in response.lower():
        print("Aborted.")
        sys.exit(0)
    print_separator()

    # Step 1: Update local repo
    print("Step 1: Updating local repository...")
    check_call_noisy(["hg", "pull"])
    check_call_noisy(["hg", "checkout", "default"])
    print_separator()

    print("Step 2: Checking working directory is clean")
    hg_status = check_output(["hg", "status"]).decode('utf-8').strip()
    if hg_status:
        print()
        print("ERROR: Working directory is not clean")
        print(hg_status)
        print()
        exit_with_failure("Please commit or revert changes then run this command again. You can reset your working directory with 'hg update -C' and 'hg purge if you want to discard all local changes.")

    branches = check_output(["hg", "branches"]).decode('utf-8').strip()
    if branch_name in branches:
        exit_with_failure(f"Branch {branch_name} already exists.")
    print_separator()

    # Step 2: Verify version numbers are correct
    print("Step 2: Verifying version numbers are correct...")
    set_version_to_minor_release([major, minor])
    print("=" * 70)
    set_beta_status()
    print("=" * 70)
    # Check if there are any uncommitted changes
    hg_status = check_output(["hg", "status"]).decode('utf-8').strip()
    if hg_status:
        print()
        print("ERROR: Version numbers are not correctly set")
        print()
        print()
        exit_with_failure("Please check the correct version to freeze, or update the version numbers then run this command again.")

    print("Version numbers verified - no changes needed.")
    print_separator()

    # Step 3: Create branch
    print(f"Step 3: Creating branch {branch_name}...")
    check_call_noisy(["hg", "branch", branch_name])
    print_separator()

    # Step 4: Create tag
    print(f"Step 4: Creating tag {tag_name}...")
    check_call_noisy(["hg", "tag", tag_name])
    print_separator()

    # Step 5: Show outgoing changes
    response = input('Display outgoing changes? [yN]: ')
    if 'y' in response.lower():
        print()
        check_call_noisy(["hg", "outgoing", "-p", remote])
    print_separator()

    # Step 6: Prompt user and push if confirmed
    response = input('Push this branch and tag to the NSS repository? [yN]: ')
    if 'y' in response.lower():
        print("Pushing branch and tag...")
        check_call_noisy(["hg", "push", "--new-branch", remote])
        print_separator()
        print("SUCCESS: Branch and tag have been pushed!")
        print_separator()
        print()
        print("NEXT STEPS:")
        print(f"1. Wait for the changes to sync to Github: https://github.com/nss-dev/nss/tree/{branch_name}")
        print("2. In your mozilla-unified repository, run:")
        print(f"   ./mach nss-uplift {tag_name}")
        print()
    else:
        print("Branch and tag have NOT been pushed to the repository.")
        print("The local branch and tag remain in your working directory.")
        print_separator()


def parse_version_string(version_string):
    """Parse a version string like '3.117' or '3.117.1' and return (major, minor, patch)

    For versions like '3.117', patch will be None.
    Returns: tuple of (major, minor, patch) where patch can be None
    """
    parts = version_string.split('.')
    if len(parts) < 2:
        exit_with_failure(f"Invalid version string '{version_string}'. Expected format: 'major.minor' or 'major.minor.patch'")

    major = parts[0].strip()
    minor = parts[1].strip()
    patch = parts[2].strip() if len(parts) >= 3 else None

    # Validate that they're numbers
    try:
        int(major)
        int(minor)
        if patch is not None:
            int(patch)
    except ValueError:
        exit_with_failure(f"Invalid version string '{version_string}'. Version components must be numbers.")

    return major, minor, patch


def version_string_to_RTM_tag(version_string):
    parts = version_string.split('.')
    return "NSS_" + "_".join(parts) + "_RTM"

def version_string_to_underscore(version_string):
    return version_string.replace('.', '_')


def generate_release_note(args):
    ensure_arguments_count(args, 3, "this_release_version_string revision_or_tag previous_release_version_string ")

    version = args[0].strip()
    this_tag = args[1].strip() # Typically going to be .
    version_underscore = version_string_to_underscore(version)
    prev_tag = version_string_to_RTM_tag(args[2].strip())

    # Get the NSPR version
    nspr_version = check_output(['hg', 'cat', '-r', this_tag, 'automation/release/nspr-version.txt']).decode('utf-8').split("\n")[0].strip()

    # Get the current date
    from datetime import datetime
    current_date = datetime.now().strftime("%-d %B %Y")

    # Get the list of bugs from hg log
    # Get log entries between previous tag and current HEAD
    command = ["hg", "log", "-r", f"{prev_tag}:{this_tag}", "--template", "{desc|firstline}\\n"]
    log_output = check_output(command).decode('utf-8')

    # Extract bug numbers and descriptions
    bug_lines = []
    for line in reversed(log_output.split('\n')):
        if 'Bug' in line or 'bug' in line:
            line = line.strip()
            line = line.split("r=")[0].strip()

            # Match patterns like "Bug 1234567 Something" and convert to "Bug 1234567 - Something"
            line = re.sub(r'(Bug\s+\d+)\s+([^-])', r'\1 - \2', line, flags=re.IGNORECASE)

            # Add a full stop at the end if there isn't one
            if line:
                line =  line.rstrip(',')

            if line and not line.endswith('.'):
                line = line + '.'

            if line and line not in bug_lines:
                bug_lines.append(line)

    changes_text = "\n".join([f"   - {line}" for line in bug_lines])

    # Create the release notes content
    rst_content = f""".. _mozilla_projects_nss_nss_{version_underscore}_release_notes:

NSS {version} release notes
========================

`Introduction <#introduction>`__
--------------------------------

.. container::

   Network Security Services (NSS) {version} was released on *{current_date}**.

`Distribution Information <#distribution_information>`__
--------------------------------------------------------

.. container::

   The HG tag is NSS_{version_underscore}_RTM. NSS {version} requires NSPR {nspr_version} or newer.

   NSS {version} source distributions are available on ftp.mozilla.org for secure HTTPS download:

   -  Source tarballs:
      https://ftp.mozilla.org/pub/mozilla.org/security/nss/releases/NSS_{version_underscore}_RTM/src/

   Other releases are available :ref:`mozilla_projects_nss_releases`.

.. _changes_in_nss_{version}:

`Changes in NSS {version} <#changes_in_nss_{version}>`__
------------------------------------------------------------------

.. container::

{changes_text}

"""
    return rst_content


def generate_release_notes_index(args):
    ensure_arguments_count(args, 2, "latest_release_version  latest_esr_version")
    latest_version = args[0].strip()  # e.g. 3.116
    esr_version = args[1].strip()  # e.g. 3.112.1

    latest_underscore = version_string_to_underscore(latest_version)
    esr_underscore = version_string_to_underscore(esr_version)

    # Read all release note files from doc/rst/releases/
    release_dir = "doc/rst/releases"
    if not os.path.exists(release_dir):
        exit_with_failure(f"Release notes directory not found: {release_dir}")

    # Get all nss_*.rst files (excluding index.rst)
    release_files = []
    for filename in os.listdir(release_dir):
        if filename.startswith("nss_") and filename.endswith(".rst") and filename != "index.rst":
            release_files.append(filename)

    # Sort release files in reverse order (newest first)
    # Extract version numbers for proper sorting
    def version_key(filename):
        # Extract version parts from filename like nss_3_116.rst
        parts = filename.replace("nss_", "").replace(".rst", "").split("_")
        # Convert to integers for proper numerical sorting
        return [int(p) for p in parts]

    release_files.sort(key=version_key, reverse=True)

    # Build the toctree content
    toctree_lines = "\n".join([f"   {f}" for f in release_files])

    # Create the index.rst content
    index_content = f""".. _mozilla_projects_nss_releases:

Release Notes
=============

.. toctree::
   :maxdepth: 0
   :glob:
   :hidden:

{toctree_lines}

.. note::

   **NSS {latest_version}** is the latest version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_{latest_underscore}_release_notes`

   **NSS {esr_version} (ESR)** is the latest ESR version of NSS.
   Complete release notes are available here: :ref:`mozilla_projects_nss_nss_{esr_underscore}_release_notes`

"""

    index_file = os.path.join(release_dir, "index.rst")
    with open(index_file, "w") as f:
        f.write(index_content)

    print(f"Generated {index_file}")
    print()
    print("=" * 70)
    print("Content:")
    print("=" * 70)
    print(index_content)


def release_nss(args):
    ensure_arguments_count(args, 4, "version_string  previous_version  esr_version  remote")
    version_string = args[0].strip()
    previous_version = args[1].strip()
    esr_version = args[2].strip()
    remote = args[3].strip()

    major, minor, patch = parse_version_string(version_string)

    # Build version string and related names
    version = version_string
    version_underscore = version_string_to_underscore(version_string)
    branch_name = f"NSS_{major}_{minor}_BRANCH"
    rtm_tag = f"NSS_{version_underscore}_RTM"
    release_note_file = f"doc/rst/releases/nss_{version_underscore}.rst"

    print_separator()
    print("RELEASE NSS")
    print_separator()
    print(f"Release version: {version}")
    print(f"Previous version: {previous_version}")
    print(f"ESR version: {esr_version}")
    print(f"Remote: {remote}")
    print_separator()

    response = input('Are these parameters correct? [yN]: ')
    if 'y' not in response.lower():
        print("Aborted.")
        sys.exit(0)
    print_separator()

    print("=" * 70)
    print(f"Starting NSS {version} release process")
    print("=" * 70)
    print()

    # Step 1: Update local repo
    print("Step 1: Updating local repository...")
    check_call_noisy(["hg", "pull"])
    print_separator()

    # Step 2: Checking working directory is clean
    print("Step 2: Checking working directory is clean...")
    hg_status = check_output(["hg", "status"]).decode('utf-8').strip()
    if hg_status:
        print()
        print("ERROR: Working directory is not clean")
        print(hg_status)
        print()
        exit_with_failure("Please commit or revert changes then run this command again. You can reset your working directory with 'hg update -C' and 'hg purge if you want to discard all local changes.")
    print_separator()

    # Step 3: Make sure we're on the appropriate branch
    print(f"Step 3: Checking out branch {branch_name}...")
    try:
        check_call_noisy(["hg", "checkout", branch_name])
    except Exception as e:
        exit_with_failure(f"Failed to checkout branch {branch_name}. Does it exist?")
    print_separator()

    # Step 4: Check for any existing commits or tags
    print("Step 4: Checking for existing release commits or tags...")

    # Check if RTM tag already exists
    tags_output = check_output(["hg", "tags"]).decode('utf-8')
    if rtm_tag in tags_output:
        exit_with_failure(f"Tag {rtm_tag} already exists. Has this release already been made?")

    # Check for recent commits with the same commit messages we're about to make
    version_commit_message = f"Set version numbers to {version} final"
    release_notes_commit_message = f"Release notes for NSS {version}"

    recent_log = check_output(["hg", "log", "-l", "5", "--template", "{desc|firstline}\\n"]).decode('utf-8')

    if version_commit_message in recent_log:
        exit_with_failure(f"Found recent commit with message '{version_commit_message}'. Has this release already been started?")

    if release_notes_commit_message in recent_log:
        exit_with_failure(f"Found recent commit with message '{release_notes_commit_message}'. Has this release already been started?")

    print("No existing release commits or tags found.")
    print_separator()

    # Step 5: Update the NSS version numbers (remove beta)
    print("Step 5: Removing beta status from version numbers...")
    if patch:
        set_version_to_patch_release([major, minor, patch])
    else:
        set_version_to_minor_release([major, minor])
    remove_beta_status()

    print_separator()



    # Step 6: Commit the change
    print("Step 6: Committing version number changes...")
    check_call_noisy(["hg", "commit", "-m", version_commit_message])
    print_separator()

    # Step 7: Generate release note
    print("Step 7: Generating release notes...")
    release_note_content = generate_release_note([version, ".", previous_version])

    # Write release note to file
    with open(release_note_file, "w") as f:
        f.write(release_note_content)
    print(f"Release note written to {release_note_file}")
    print_separator()

    # Step 8: Generate new release note index
    print("Step 8: Generating release notes index...")
    generate_release_notes_index([version, esr_version])
    print_separator()

    input("Are you making an ESR release? If so, please manually edit doc/rst/releases/index.rst to adjust the ESR / main version note. Press enter when done.")

    # Step 9: Commit the release notes
    print("Step 9: Committing release notes...")
    check_call_noisy(["hg", "add", release_note_file])
    check_call_noisy(["hg", "commit", "-m", release_notes_commit_message])

    # Get the commit hash
    docs_commit = check_output(["hg", "log", "-r", ".", "--template", "{node|short}"]).decode('utf-8').strip()
    print(f"Release notes committed. Commit hash: {docs_commit}")
    print_separator()

    # Step 10: Tag the release version
    print(f"Step 10: Tagging release version {rtm_tag}...")
    check_call_noisy(["hg", "tag", rtm_tag])
    print_separator()

    # Step 11: Switch to default branch and graft the release notes
    print("Step 11: Switching to default branch and grafting release notes...")
    check_call_noisy(["hg", "checkout", "default"])
    check_call_noisy(["hg", "graft", "-r", docs_commit])
    print_separator()

    response = input('Display the outgoing changes? [yN]: ')
    if 'y' in response.lower():
        check_call_noisy(["hg", "outgoing", "--graph", "-b", "default", "-b", branch_name, remote])
    print_separator()

    # Step 12: Push changes
    response = input('Push these changes to the NSS repository? [yN]: ')
    if 'y' in response.lower():
        print("Pushing changes to default branch...")
        check_call_noisy(["hg", "push", "-b", "default", remote])
        print(f"Pushing changes to {branch_name} branch...")
        check_call_noisy(["hg", "push", "-b", branch_name, remote])
        print_separator()
        print("SUCCESS: NSS release process completed!")
        print_separator()
        print()
        print("NEXT STEPS:")
        print(f"1. Wait for the changes to sync to Github")
        print("2. In your mozilla-unified repository, run:")
        print(f"   ./mach nss-uplift {rtm_tag}")
        print()
    else:
        print("Changes have NOT been pushed to the repository.")
        print("The local commits remain in your working directory.")
        print_separator()


def create_nss_release_archive(args):
    ensure_arguments_count(args, 2, "nss_release_version  path_to_stage_directory")
    nssrel = args[0].strip()  # e.g. 3.19.3
    stagedir = args[1].strip()  # e.g. ../stage

    # Determine which tar command to use (prefer gtar if available)
    tar_cmd = "gtar"
    try:
        check_call(["which", "gtar"], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
    except:
        tar_cmd = "tar"

    # Generate the release tag from the version
    nssreltag = version_string_to_RTM_tag(nssrel)

    print_separator()
    print("CREATE NSS RELEASE ARCHIVE")
    print_separator()
    print(f"NSS release version: {nssrel}")
    print(f"Stage directory: {stagedir}")
    print_separator()

    response = input('Are these parameters correct? [yN]: ')
    if 'y' not in response.lower():
        print("Aborted.")
        sys.exit(0)
    print_separator()

    with open('automation/release/nspr-version.txt') as nspr_version_file:
        nsprrel = next(nspr_version_file).strip()

    nspr_tar = "nspr-" + nsprrel + ".tar.gz"
    nspr_dir = stagedir + "/v" + nsprrel + "/src/"
    nsprtar_with_path = nspr_dir + nspr_tar

    nspr_releases_url = "https://ftp.mozilla.org/pub/nspr/releases"
    if (not os.path.exists(nsprtar_with_path)):
        os.makedirs(nspr_dir,exist_ok=True)
        check_call_noisy(['wget', f"{nspr_releases_url}/v{nsprrel}/src/nspr-{nsprrel}.tar.gz",
                          f'--output-document={nsprtar_with_path}'])

    if (not os.path.exists(nsprtar_with_path)):
        exit_with_failure("cannot find nspr archive at expected location " + nsprtar_with_path)

    nss_stagedir = stagedir + "/" + nssreltag + "/src"
    if (os.path.exists(nss_stagedir)):
        exit_with_failure("nss stage directory already exists: " + nss_stagedir)

    nss_tar = "nss-" + nssrel + ".tar.gz"

    check_call_noisy(["mkdir", "-p", nss_stagedir])
    check_call_noisy(["hg", "archive", "-r", nssreltag, "--prefix=nss-" + nssrel + "/nss",
                      stagedir + "/" + nssreltag + "/src/" + nss_tar, "-X", ".hgtags"])
    check_call_noisy([tar_cmd, "-xz", "-C", nss_stagedir, "-f", nsprtar_with_path])
    print("changing to directory " + nss_stagedir)
    os.chdir(nss_stagedir)
    check_call_noisy([tar_cmd, "-xz", "-f", nss_tar])
    check_call_noisy(["mv", "-i", "nspr-" + nsprrel + "/nspr", "nss-" + nssrel + "/"])
    check_call_noisy(["rmdir", "nspr-" + nsprrel])

    nss_nspr_tar = "nss-" + nssrel + "-with-nspr-" + nsprrel + ".tar.gz"

    check_call_noisy([tar_cmd, "-cz", "--remove-files", "-f", nss_nspr_tar, "nss-" + nssrel])
    check_call("sha1sum " + nss_tar + " " + nss_nspr_tar + " > SHA1SUMS", shell=True)
    check_call("sha256sum " + nss_tar + " " + nss_nspr_tar + " > SHA256SUMS", shell=True)
    print("created directory " + nss_stagedir + " with files:")
    check_call_noisy(["ls", "-l"])

    if 'y' not in input('Upload release tarball?[yN]'):
        print("Release tarballs have NOT been uploaded")
        exit(0)
    os.chdir("../..")
    gcp_proj="moz-fx-productdelivery-pr-38b5"
    check_call_noisy(["gcloud", "auth", "login"])
    check_call_noisy(
        [
            "gcloud",
            "--project",
            gcp_proj,
            f"--impersonate-service-account=nss-team-prod@{gcp_proj}.iam.gserviceaccount.com",
            "storage",
            "cp",
            "--recursive",
            "--no-clobber",
            nssreltag,
            f"gs://{gcp_proj}-productdelivery/pub/security/nss/releases/",
        ]
    )
    print_separator()
    print(f"Release tarballs have been uploaded to Google Cloud Storage. You can find them at https://ftp.mozilla.org/pub/security/nss/releases/{nssreltag}/")
    print_separator()


o = OptionParser(usage="client.py [options] " + " | ".join([
    "remove_beta", "set_beta", "print_library_versions", "print_root_ca_version",
    "set_root_ca_version", "set_version_to_minor_release",
    "set_version_to_patch_release", "set_release_candidate_number",
    "set_4_digit_release_number", "make_release_branch", "create_nss_release_archive",
    "generate_release_note", "generate_release_notes_index"]))

try:
    options, args = o.parse_args()
    action = args[0]
    action_args = args[1:]  # Get all arguments after the action
except IndexError:
    o.print_help()
    sys.exit(2)

if action in ('remove_beta'):
    remove_beta_status()

elif action in ('set_beta'):
    set_beta_status()

elif action in ('print_library_versions'):
    print_library_versions()

elif action in ('print_root_ca_version'):
    print_root_ca_version()

elif action in ('set_root_ca_version'):
    set_root_ca_version(action_args)

# x.y version number - 2 parameters
elif action in ('set_version_to_minor_release'):
    set_version_to_minor_release(action_args)

# x.y.z version number - 3 parameters
elif action in ('set_version_to_patch_release'):
    set_version_to_patch_release(action_args)

# change the release candidate number, usually increased by one,
# usually if previous release candiate had a bug
# 1 parameter
elif action in ('set_release_candidate_number'):
    set_release_candidate_number(action_args)

# use the build/release candiate number in the identifying version number
# 4 parameters
elif action in ('set_4_digit_release_number'):
    set_4_digit_release_number(action_args)

# create a freeze branch and beta tag for a new release
# 2 parameters
elif action in ('make_release_branch'):
    make_release_branch(action_args)

elif action in ('create_nss_release_archive'):
    create_nss_release_archive(action_args)

elif action in ('generate_release_note'):
    print(generate_release_note(action_args))

elif action in ('generate_release_notes_index'):
    generate_release_notes_index(action_args)


elif action in ('release_nss'):
    release_nss(action_args)

else:
    o.print_help()
    sys.exit(2)

sys.exit(0)
