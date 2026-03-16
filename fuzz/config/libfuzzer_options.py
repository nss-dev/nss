#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import sys
import tomllib


def main():
    with open(sys.argv[1], "rb") as f:
        data = tomllib.load(f)

    for key, value in data["libfuzzer"].items():
        print(f"-{key}={value}")


if __name__ == "__main__":
    main()
