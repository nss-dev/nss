#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Generate NSS release documentation (RST file) based on version number.

Usage: python3 generate_release_doc.py <version> [output_file]

Example:
  python3 generate_release_doc.py 3.118
  python3 generate_release_doc.py 3.118.1 doc/rst/releases/nss_3_118_1.rst
"""

import os
import sys
from datetime import datetime
from subprocess import call, check_call

sys.path.insert(0, os.path.dirname(__file__))
from release_utils import (
    exit_with_failure,
    get_nspr_version,
    get_bug_list_for_version,
    version_string_to_underscore,
    version_string_to_RTM_tag,
    get_rtm_tag_date,
)


def generate_rst_content(version, nspr_version, bug_lines, release_date):
    """Generate the RST content for the release notes."""
    version_underscore = version_string_to_underscore(version)
    changes_text = "\n".join([f"   - {line}" for line in bug_lines])

    rst_content = f""".. _mozilla_projects_nss_nss_{version_underscore}_release_notes:

NSS {version} release notes
{"=" * len(f"NSS {version} release notes")}

`Introduction <#introduction>`__
--------------------------------

.. container::

   Network Security Services (NSS) {version} was released on *{release_date}*.

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
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    version = sys.argv[1].strip()

    # Determine output file
    if len(sys.argv) >= 3:
        output_file = sys.argv[2].strip()
    else:
        version_underscore = version_string_to_underscore(version)
        output_file = f"doc/rst/releases/nss_{version_underscore}.rst"

    rtm_tag = version_string_to_RTM_tag(version)
    rtm_date = get_rtm_tag_date(rtm_tag)
    current_date = rtm_date or datetime.now().strftime("%-d %B %Y")

    # Get NSPR version from the RTM tag revision if it exists
    nspr_version = get_nspr_version(rtm_tag if rtm_date else None)

    print(f"Generating release documentation for NSS {version}")
    print(f"NSPR version: {nspr_version}")
    print(f"Release date: {current_date}")
    print()

    # Get changes from Mercurial
    print("Extracting changes from Mercurial...")
    bug_lines = get_bug_list_for_version(version)
    print(f"Found {len(bug_lines)} bug entries")
    print()

    # Generate RST content
    rst_content = generate_rst_content(version, nspr_version, bug_lines, current_date)

    # Write to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write(rst_content)

    print(f"Release documentation written to: {output_file}")
    print()
    print("Running doc-lint...")
    rc = call(["./mach", "doc-lint"])
    if rc != 0:
        exit_with_failure(f"doc-lint failed with exit status {rc}")
    print()
    print("=" * 70)
    print("Preview:")
    print("=" * 70)
    print(rst_content)


if __name__ == "__main__":
    main()
