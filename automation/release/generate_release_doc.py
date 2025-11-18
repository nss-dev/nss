#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Generate NSS release documentation (RST file) based on version number.

Usage: python3 generate_release_doc.py <version> <previous_version> [output_file]

Example:
  python3 generate_release_doc.py 3.118 3.117
  python3 generate_release_doc.py 3.118.1 3.118 doc/rst/releases/nss_3_118_1.rst
"""

import os
import re
import sys
from datetime import datetime
from subprocess import check_output


def exit_with_failure(message):
    """Exit the script with an error message."""
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def version_string_to_underscore(version_string):
    """Convert version string like '3.118' to '3_118'."""
    return version_string.replace('.', '_')


def version_string_to_RTM_tag(version_string):
    """Convert version string like '3.118' to 'NSS_3_118_RTM'."""
    parts = version_string.split('.')
    return "NSS_" + "_".join(parts) + "_RTM"


def get_nspr_version():
    """Read the NSPR version from automation/release/nspr-version.txt."""
    nspr_version_file = "automation/release/nspr-version.txt"
    try:
        with open(nspr_version_file, 'r') as f:
            return f.readline().strip()
    except FileNotFoundError:
        exit_with_failure(f"Could not find {nspr_version_file}. Are you running from the NSS root directory?")


def get_changes_from_hg(current_tag, previous_tag):
    """Extract bug changes from Mercurial log between two tags."""
    try:
        # Get log entries between previous tag and current tag
        command = ["hg", "log", "-r", f"{previous_tag}:{current_tag}", "--template", "{desc|firstline}\\n"]
        log_output = check_output(command).decode('utf-8')
    except Exception as e:
        exit_with_failure(f"Failed to get hg log: {e}")

    # Extract bug numbers and descriptions
    bug_lines = []
    for line in reversed(log_output.split('\n')):
        if 'Bug' in line or 'bug' in line:
            line = line.strip()
            # Remove reviewer information
            line = line.split("r=")[0].strip()

            # Match patterns like "Bug 1234567 Something" and convert to "Bug 1234567 - Something"
            line = re.sub(r'(Bug\s+\d+)\s+([^-])', r'\1 - \2', line, flags=re.IGNORECASE)

            # Clean up punctuation
            if line:
                line = line.rstrip(',')

            # Add a full stop at the end if there isn't one
            if line and not line.endswith('.'):
                line = line + '.'

            if line and line not in bug_lines:
                bug_lines.append(line)

    return bug_lines


def generate_rst_content(version, nspr_version, bug_lines, release_date):
    """Generate the RST content for the release notes."""
    version_underscore = version_string_to_underscore(version)
    changes_text = "\n".join([f"   - {line}" for line in bug_lines])

    rst_content = f""".. _mozilla_projects_nss_nss_{version_underscore}_release_notes:

NSS {version} release notes
========================

`Introduction <#introduction>`__
--------------------------------

.. container::

   Network Security Services (NSS) {version} was released on *{release_date}**.

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


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    version = sys.argv[1].strip()
    previous_version = sys.argv[2].strip()

    # Determine output file
    if len(sys.argv) >= 4:
        output_file = sys.argv[3].strip()
    else:
        version_underscore = version_string_to_underscore(version)
        output_file = f"doc/rst/releases/nss_{version_underscore}.rst"

    # Get current date
    current_date = datetime.now().strftime("%-d %B %Y")

    # Get NSPR version
    nspr_version = get_nspr_version()

    # Convert versions to tags
    current_tag = version_string_to_RTM_tag(version)
    previous_tag = version_string_to_RTM_tag(previous_version)

    print(f"Generating release documentation for NSS {version}")
    print(f"Previous version: {previous_version}")
    print(f"Current tag: {current_tag}")
    print(f"Previous tag: {previous_tag}")
    print(f"NSPR version: {nspr_version}")
    print(f"Release date: {current_date}")
    print()

    # Get changes from Mercurial
    print("Extracting changes from Mercurial...")
    bug_lines = get_changes_from_hg(current_tag, previous_tag)
    print(f"Found {len(bug_lines)} bug entries")
    print()

    # Generate RST content
    rst_content = generate_rst_content(version, nspr_version, bug_lines, current_date)

    # Write to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        f.write(rst_content)

    print(f"Release documentation written to: {output_file}")
    print()
    print("=" * 70)
    print("Preview:")
    print("=" * 70)
    print(rst_content)


if __name__ == "__main__":
    main()

