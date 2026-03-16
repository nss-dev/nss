# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

project = "NSS"
extensions = []
root_doc = "index"

# Suppress cross-reference warnings for labels outside the NSS standalone
# build (e.g. :ref: to Firefox-managed docs).
suppress_warnings = ["ref.ref"]

exclude_patterns = []
