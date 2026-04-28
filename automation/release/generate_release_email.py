#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Generate NSS release email text based on version number.

Usage: python3 generate_release_email.py <version> [output_file]

Example:
  python3 generate_release_email.py 3.118
  python3 generate_release_email.py 3.118.1 release_email_3.118.1.txt
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from release_utils import (
    exit_with_failure,
    get_nspr_version,
    get_bug_list_for_version,
    version_string_to_underscore,
    version_string_to_RTM_tag,
    get_rtm_tag_date,
)


def generate_email_content(version, nspr_version, bug_lines, release_date):
    """Generate the email content for the release announcement."""
    version_underscore = version_string_to_underscore(version)
    changes_text = "\n\n".join([f"    {line}" for line in bug_lines])

    email_content = f"""Network Security Services (NSS) {version} was released on {release_date}.



The HG tag is NSS_{version_underscore}_RTM. This version of NSS requires NSPR {nspr_version} or newer. The latest version of NSPR is {nspr_version}.

NSS {version} source distributions are available on ftp.mozilla.org for secure HTTPS download:

<https://ftp.mozilla.org/pub/security/nss/releases/NSS_{version_underscore}_RTM/src/>

Changes:

{changes_text}

NSS {version} shared libraries are backwards-compatible with all older NSS 3.x shared libraries. A program linked with older NSS 3.x shared libraries will work with this new version of the shared libraries without recompiling or relinking. Furthermore, applications that restrict their use of NSS APIs to the functions listed in NSS Public Functions will remain compatible with future versions of the NSS shared libraries.

Bugs discovered should be reported by filing a bug report at <https://bugzilla.mozilla.org/enter_bug.cgi?product=NSS>

Release notes are available at <https://firefox-source-docs.mozilla.org/security/nss/releases/index.html>.
"""
    return email_content


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    version = sys.argv[1].strip()

    # Determine output file (optional)
    output_file = None
    if len(sys.argv) >= 3:
        output_file = sys.argv[2].strip()

    rtm_tag = version_string_to_RTM_tag(version)
    rtm_date = get_rtm_tag_date(rtm_tag)
    current_date = rtm_date or datetime.now().strftime("%-d %B %Y")

    # Get NSPR version from the RTM tag revision if it exists
    nspr_version = get_nspr_version(rtm_tag if rtm_date else None)

    print(f"Generating release email for NSS {version}")
    print(f"NSPR version: {nspr_version}")
    print(f"Release date: {current_date}")
    print()

    # Get changes from Mercurial
    print("Extracting changes from Mercurial...")
    bug_lines = get_bug_list_for_version(version)
    print(f"Found {len(bug_lines)} bug entries")
    print()

    # Generate email content
    email_content = generate_email_content(
        version, nspr_version, bug_lines, current_date
    )

    # Write to file if specified, otherwise print to stdout
    if output_file:
        with open(output_file, "w") as f:
            f.write(email_content)
        print(f"Release email written to: {output_file}")
        print()

    print("=" * 70)
    print("Email Content:")
    print("=" * 70)
    print(email_content)


if __name__ == "__main__":
    main()
