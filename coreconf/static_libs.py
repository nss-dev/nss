#!/usr/bin/env python3
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Print the linker flags for a static link against this build of NSS, in
# dependency order, for build.sh to substitute into nss-static.pc.
#
# The list is derived rather than written down: gyp's dump_dependency_json
# generator emits the dependency graph for the configuration that was just
# built, with all conditions resolved, and this walks that graph from the
# libraries that make up NSS's public interface. Anything the internals pull
# in comes along, so moving code between gyp targets - as freebl did with
# kyber.c and ml_dsa.c - doesn't leave consumers with a stale list.

from __future__ import print_function

import json
import os
import sys

# The static counterpart of the 'Libs:' line in nss.pc. Every other archive
# is reached from these through the dependency graph.
ROOTS = [
    'ssl',
    'smime',
    'nss_static',
    'pk11wrap_static',
    'cryptohi',
    'certhi',
    'certdb',
    'nsspki',
    'nssdev',
    'nssb',
    'sqlite',
    'nssutil',
]

def target_name(qualified):
    """Reduce '/path/to/freebl.gyp:freebl_static#target' to 'freebl_static'."""
    return qualified.rsplit(':', 1)[-1].split('#', 1)[0]

def load_graph(dump):
    with open(dump) as f:
        edges = json.load(f)
    return dict((target_name(target), [target_name(d) for d in deps])
                for target, deps in edges.items())

def link_order(edges):
    """The roots and everything they depend on, dependents before dependencies."""
    ordered = []
    seen = set()

    def visit(target, out):
        if target in seen:
            return
        seen.add(target)
        for dep in edges.get(target, []):
            visit(dep, out)
        out.append(target)

    for root in ROOTS:
        subtree = []
        visit(root, subtree)
        # A post-order walk lists dependencies first; a link wants them last.
        subtree.reverse()
        ordered.extend(subtree)
    return ordered

def is_built(lib_dir, target):
    """Whether this build produced an archive for a target.

    Targets that are for another architecture, that a --disable- flag turned
    off, or that aren't libraries at all are filtered out this way, so that
    the walk above doesn't have to reason about any of that.
    """
    return any(os.path.exists(os.path.join(lib_dir, name))
               for name in ('lib%s.a' % target, '%s.lib' % target))

def main():
    dump, lib_dir = sys.argv[1], sys.argv[2]
    edges = load_graph(dump)
    libs = [t for t in link_order(edges) if is_built(lib_dir, t)]
    if not libs:
        raise SystemExit('%s: no static libraries found in %s' % (sys.argv[0], lib_dir))
    print(' '.join('-l' + lib for lib in libs))

if __name__ == '__main__':
    main()
