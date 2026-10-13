# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from taskgraph.transforms.base import TransformSequence

transforms = TransformSequence()

#: Worker types whose image has no Y: drive. b-win2022 has one, so the default
#: works there; the win11-a64-25h2 images ronin_puppet builds do not.
NO_HG_DRIVE = ("b-win-aarch64", "t-win-aarch64")

#: The Azure Windows pools no longer have a D: drive: fxci-config moved them to
#: NVMe sizes with all task storage on C: (RELOPS-2583). ronin_puppet's
#: mozbuild_post_boostrap creates hg-shared on C: when there is no D:.
HG_STORE = "C:/hg-shared"


@transforms.add
def relocate_hg_store(config, tasks):
    """Point HG_STORE_PATH somewhere the worker actually has.

    taskgraph.transforms.run hardcodes y:/hg-shared for every Windows worker,
    which is a gecko convention rather than a Taskcluster one. run-task creates
    that directory unconditionally for an hg checkout, so on a worker without
    the drive the task dies before it runs anything.

    It can't go in the checkout cache either: robustcheckout hardlinks from the
    share pool into the working copy, and generic-worker refuses to re-ACL a
    hardlink when it hands the cache to the next task, so the *second* task to
    reuse the cache fails to mount it. Hence a path outside the task directory,
    which also lets the store survive between tasks.

    Must run after taskgraph.transforms.run, which is why the kinds using this
    list their transforms explicitly instead of relying on the default loader.
    """
    for task in tasks:
        if task.get("worker-type") in NO_HG_DRIVE:
            env = task.setdefault("worker", {}).setdefault("env", {})
            env["HG_STORE_PATH"] = HG_STORE
        yield task
