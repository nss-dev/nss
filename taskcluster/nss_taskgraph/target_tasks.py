# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from taskgraph.target_tasks import register_target_task, target_tasks_default


def filter_build_type(build_types, task):
    if "o" in build_types and "opt" in task.attributes["build_type"]:
        return True
    if "d" in build_types and "debug" in task.attributes["build_type"]:
        return True


# Build platforms are named `<os>-<arch>`: linux/win/mac × x86/x64/aarch64
# (e.g. linux-x64, win-x86, mac-x64, linux-aarch64), optionally with a variant
# suffix that is part of the platform itself (e.g. linux-x64-asan). Those names
# are also the try-syntax selectors, matched directly.
#
# A build *variant* that lives in the build_type rather than the platform name
# (make / fips / fuzz / tsan) is selected with a `<platform>-<variant>` token,
# which maps back to its underlying platform here and is then narrowed by the
# matching attribute in filter_platform below. (Kept as an explicit literal so
# `./mach try` can scrape these selectors for its --help output.)
PLATFORM_ALIASES = {
    "linux-x86-make": "linux-x86",
    "linux-x64-make": "linux-x64",
    "linux-aarch64-make": "linux-aarch64",
    "win-x86-make": "win-x86",
    "win-x64-make": "win-x64",
    "mac-x64-make": "mac-x64",
    "linux-x64-fips": "linux-x64",
    "linux-aarch64-fips": "linux-aarch64",
    "linux-x86-fuzz": "linux-x86",
    "linux-x64-fuzz": "linux-x64",
    "linux-x64-tsan": "linux-x64",
}

# build attribute that must be truthy for each `-<variant>` selector suffix.
_VARIANT_ATTR = {"make": "make", "fips": "make-fips", "fuzz": "fuzz", "tsan": "tsan"}


def filter_platform(platform, task):
    if "build_platform" not in task.attributes:
        return False
    if platform == "all":
        return True
    task_platform = task.attributes["build_platform"]
    # Check the platform name.
    keep = task_platform == PLATFORM_ALIASES.get(platform, platform)
    # A `<platform>-<variant>` selector shares its platform name with the plain
    # build, so narrow to the variant by its attribute.
    if platform in PLATFORM_ALIASES:
        keep &= task.attributes[_VARIANT_ATTR[platform.rsplit("-", 1)[1]]]
    return keep


def filter_try_syntax(options, task):
    symbol = task.task["extra"]["treeherder"]["symbol"].lower()
    group = task.task["extra"]["treeherder"].get("groupSymbol", "").lower()

    # Filter tools. We can immediately return here as those
    # are not affected by platform or build type selectors.
    if task.kind == "tools":
        return any(t in options["tools"] for t in ["all", symbol])

    # Filter unit tests. A test is selected by its own symbol, or by its group
    # symbol for the grouped suites (so e.g. `-u cipher` picks up every
    # Cipher(...) variant). On the FIPS build the group is rewritten to "fips",
    # but the inner symbol is preserved, so e.g. FIPS(Gtest) still matches
    # `-u gtest`.
    if task.kind == "test":
        tests = {"all", symbol}
        if group in ("cipher", "ssl", "gtest"):
            tests.add(group)
        if not any(t in options["unittests"] for t in tests):
            return False

    # Filter fuzz tasks. Fuzzing runs are opt-in on try (`-u fuzz`, or `-u all`)
    # because every target burns a worker for its whole MAX_FUZZ_TIME. Once
    # selected they are narrowed by platform and build type like anything else.
    if task.kind == "fuzz" and not any(
        t in options["unittests"] for t in ("all", "fuzz")
    ):
        return False

    # Filter extra builds.
    if group == "builds" and not options["extra"]:
        return False

    # Filter by platform.
    if not any(filter_platform(platform, task) for platform in options["platforms"]):
        return False

    # Finally, filter by build type.
    return filter_build_type(options["builds"], task)


@register_target_task("nss_try_tasks")
def target_tasks_try(full_task_graph, parameters, graph_config):
    if not parameters["try_options"]:
        return target_tasks_default(full_task_graph, parameters, graph_config)
    return [
        t.label
        for t in full_task_graph
        if filter_try_syntax(parameters["try_options"], t)
    ]
