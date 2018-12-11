#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import json
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
source_file = os.path.join(script_dir, 'testvectors/aes_gcm_test.json')
base_file = os.path.join(script_dir, 'header_bases/gcm-vectors.h')
target_file = os.path.join(script_dir, '../gcm-vectors.h')

# Imports a JSON testvector file.
def import_testvector(file):
    
    with open(file) as f:
        vectors = json.loads(f.read())
    return vectors

# Writes one testvector into C-header format. (Not clang-format conform)
def format_testcase(vector):
    result = "{{ {},\n".format(vector["tcId"])
    result += " \"{}\",\n".format(vector["key"])
    result += " \"{}\",\n".format(vector["msg"])
    result += " \"{}\",\n".format(vector["aad"])
    result += " \"{}\",\n".format(vector["iv"])
    result += " \"\",\n"
    result += " \"{}\",\n".format(vector["tag"])
    result += " \"{}\",\n".format(vector["ct"] + vector["tag"])
    result += " {},\n".format(str(vector["result"] == "invalid").lower())
    result += " {}}},\n\n".format(str("ZeroLengthIv" in vector["flags"]).lower())


    return result

def generate_aes_gcm():
    cases = import_testvector(source_file)

    with open(base_file) as base:
        header = base.read()

    header = header[:-27]

    header += "\n\n// Testvectors from project wycheproof\n"
    header += "// <https://github.com/google/wycheproof>\n"
    header += "const gcm_kat_value kGcmWycheproofVectors[] = {\n"

    for group in cases["testGroups"]:
        for test in group["tests"]:
            header += format_testcase(test)

    header = header[:-3] + "};\n\n"

    header += "#endif  // gcm_vectors_h__\n"

    with open(target_file, 'w') as target:
        target.write(header)


def main():
    generate_aes_gcm()


if __name__ == '__main__':
    main()
