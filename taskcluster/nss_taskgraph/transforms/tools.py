# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from taskgraph.transforms.base import TransformSequence

transforms = TransformSequence()


@transforms.add
def add_base_rev(config, tasks):
    """Inject NSS_BASE_REV into coverage tasks so they can generate
    diff coverage reports against the base revision."""
    for task in tasks:
        if task["name"] in ("test-coverage", "fuzz-coverage"):
            base_rev = config.params.get("base_rev", "")
            if base_rev:
                env = task["worker"].setdefault("env", {})
                env["NSS_BASE_REV"] = base_rev
        yield task
