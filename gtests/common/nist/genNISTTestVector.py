#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import subprocess
import hashlib

script_dir = os.path.dirname(os.path.abspath(__file__))

# Imports a JSON testvector file.
def import_testvector(file):
    """Import a JSON testvector file and return an array of the contained objects."""
    with open(file) as f:
        vectors = json.loads(f.read())
    return vectors

# Convert a test data string to a hex array.
def string_to_hex(string):
    """Convert a string of hex chars to a string representing a C-format array of hex bytes."""
    b = bytearray.fromhex(string)
    result = ', '.join("{:#04x}".format(x) for x in b)
    return result

def digest(string):
    b = bytearray.fromhex(string)
    h = hashlib.sha3_256()
    h.update(b)
    return h.hexdigest()

#now split them into readable lines
def string_line_split(string, group_len, count, spaces):
    result=''
    lstring = string;
    while (len(lstring) > count*group_len):
        result += lstring[:count*group_len].rjust(spaces);
        result += '\n'
        lstring=lstring[count*group_len:];
    result += lstring.rjust(spaces)
    return result

# put it together
def string_to_hex_array(string):
    result="{\n"
    result += string_line_split(' '+string_to_hex(string), 6, 12, 4)
    result += '}'
    return result


mlkem_freebl_param={
    "ML-KEM-512": "params_ml_kem512",
    "ML-KEM-768": "params_ml_kem768",
    "ML-KEM-1024": "params_ml_kem1024",
}

mlkem_freebl_test_param={
    "ML-KEM-512": "params_ml_kem512_test_mode",
    "ML-KEM-768": "params_ml_kem768_test_mode",
    "ML-KEM-1024": "params_ml_kem1024_test_mode",
}

mlkem_prefix={
    "ML-KEM-512": "MlKem512",
    "ML-KEM-768": "MlKem768",
    "ML-KEM-1024": "MlKem1024",
}

class MLKEM_KEYGEN():
    def init_global(self, group, group_result, out_defs):
        paramSet= group['parameterSet']
        self.paramSet = paramSet
        return paramSet in mlkem_freebl_param
    def format_testcase(self, testcase, testcase_result, out_defs):
        seed=testcase['d']+testcase['z']
        pubk=testcase_result['ek']
        privk=testcase_result['dk']
        pubkDigest=digest(pubk)
        privkDigest=digest(privk)
        result = '\n// {}\n'.format(self.paramSet)
        result = '// tcID: {}\n'.format(testcase['tcId'])
        result += '{{{},\n'.format(testcase['tcId'])
        result += '{},\n'.format(mlkem_freebl_param[self.paramSet])
        result += '//seed\n{},\n'.format(string_to_hex_array(seed))
        result += '//publicKeyDigest\n{},\n'.format(string_to_hex_array(pubkDigest))
        result += '//privateKeyDigest\n{}}},\n'.format(string_to_hex_array(privkDigest))
        display = 'tcID {}: {} '.format(testcase['tcId'],self.paramSet)
        display += 'seed({}) pubk({}) '.format(len(seed)/2,len(pubk)/2)
        display += 'privk({})'.format(len(privk)/2)
        print(display)
        return result

class MLKEM_ENCAP():
    key_name=''
    has_name=False
    def init_global(self, group, group_result, out_defs):
        paramSet= group['parameterSet']
        self.paramSet=paramSet
        if not paramSet in mlkem_freebl_test_param:
            return False
        if  group['function'] != 'encapsulation':
            return False
        return True
    def format_testcase(self, testcase, testcase_result, out_defs):
        key=testcase['ek']
        result = '\n// {}\n'.format(self.paramSet)
        result = '// tcID: {}\n'.format(testcase['tcId'])
        result += '{{{},\n'.format(testcase['tcId'])
        result += '{},\n'.format(mlkem_freebl_test_param[self.paramSet])
        result += '// entropy\n{},\n'.format(string_to_hex_array(testcase['m']))
        result += '// publicKey\n{},\n'.format(string_to_hex_array(testcase['ek']))
        cipherTextDigest=digest(testcase_result['c'])
        result += '// cipherTextDigest\n{},\n'.format(string_to_hex_array(cipherTextDigest))
        result += '// secret\n{},\ntrue}},\n'.format(string_to_hex_array(testcase_result['k']))
        display = 'tcID {}: {} '.format(testcase['tcId'],self.paramSet)
        display += 'key({}) encapsulate'.format(len(key)/2)
        print(display)
        return result

class MLKEM_DECAP():
    key_name=''
    has_name=False
    def init_global(self, group, group_result, out_defs):
        paramSet= group['parameterSet']
        self.paramSet=paramSet
        if not paramSet in mlkem_freebl_test_param:
            return False
        if  group['function'] != 'decapsulation':
            return False
        return True
    def format_testcase(self, testcase, testcase_result, out_defs):
        result = '\n// {}\n'.format(self.paramSet)
        result = '// tcID: {}\n'.format(testcase['tcId'])
        result += '{{{},\n'.format(testcase['tcId'])
        result += '{},\n'.format(mlkem_freebl_test_param[self.paramSet])
        result += '// privateKey\n{},\n'.format(string_to_hex_array(testcase['dk']))
        result += '// ciphertext\n{},\n'.format(string_to_hex_array(testcase['c']))
        result += '// secret\n{},\ntrue}},\n'.format(string_to_hex_array(testcase_result['k']))
        display = 'tcID {}: {} decapsulate'.format(testcase['tcId'],self.paramSet)
        print(display)
        return result

def matchID(_id, source, target):
    for i in target:
        if i[_id] == source[_id]:
            return i
    return {}

def generate_vectors_file(params):
    """
    Generate and store a .h-file with test vectors for one test.

    params -- Dictionary with parameters for test vector generation for the desired test.
    """

    cases = import_testvector(os.path.join(script_dir, params['source_dir'] + params['prompt_file']))
    result = import_testvector(os.path.join(script_dir, params['source_dir'] + params['result_file']))

    header = standard_params['license']
    header += "\n"
    header += standard_params['top_comment']
    header += "\n"
    header += "#ifndef " + params['section'] + "\n"
    header += "#define " + params['section'] + "\n"
    header += "\n"

    for include in standard_params['includes']:
        header += "#include " + include + "\n"

    header += "\n"

    if 'includes' in params:
        for include in params['includes']:
            header += "#include " + include + "\n"
        header += "\n"

    shared_defs = []
    vectors_file = params['array_init']

    for group in cases['testGroups']:
        group_result = matchID('tgId', group, result['testGroups']);
        if (not params['formatter'].init_global(group, group_result, shared_defs)):
            continue;
        for test in group['tests']:
            test_result = matchID('tcId', test, group_result['tests']);
            vectors_file += params['formatter'].format_testcase(test, test_result, shared_defs)

    vectors_file = vectors_file[:params['crop_size_end']] + '\n};\n\n'
    vectors_file += "#endif // " + params['section'] + '\n'

    with open(os.path.join(script_dir, params['target']), 'w') as target:
        target.write(header)
        for definition in shared_defs:
            target.write(definition)
        target.write(vectors_file)


standard_params = {
    'includes': ['"testvectors_base/test-structs.h"'],
    'license':
"""/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */
 """,

    'top_comment':
"""/* This file is generated from sources in nss/gtests/common/nist
 * automatically and should not be touched manually.
 * Generation is triggered by calling python3 genNISTTestVector.py */
 """
}

# Parameters that describe the generation of a testvector file for each supoorted test.
# source_dir -- relative path to the directory holding the ACVP JSON files.
# test_name -- name of the ACVP-Server test whose files are downloaded.
# tag -- ACVP-Server release tag to download from.
# prompt_file -- file name for the downloaded prompt.json.
# result_file -- file name for the downloaded expectedResults.json.
# target -- relative path to where the finished .h-file is written.
# array_init -- string to initialize the c-header style array of testvectors.
# formatter -- the test case formatter class to be used for this test.
# crop_size_end -- number of characters removed from the end of the last generated test vector to close the array definition.
# section -- name of the section
# comment -- additional comments to add to the file just before definition of the test vector array.

ml_kem_decap_params = {
    'source_dir': 'source_vectors/',
    'test_name': 'ML-KEM-encapDecap-FIPS203',
    'tag': 'v1.1.0.40',
    'prompt_file': 'ml_kem_encap_decap_prompt.json',
    'result_file': 'ml_kem_encap_decap_result.json',
    'target': '../testvectors/ml-kem-decap-vectors.h',
    'array_init': 'const std::vector<MlKemDecapTestVector> MlKemDecapTests = {\n',
    'formatter' : MLKEM_DECAP(),
    'crop_size_end': -2,
    'section': 'mlkem_decap_vectors_h__',
    'comment' : ''
}

ml_kem_encap_params = {
    'source_dir': 'source_vectors/',
    'test_name': 'ML-KEM-encapDecap-FIPS203',
    'tag': 'v1.1.0.40',
    'prompt_file': 'ml_kem_encap_decap_prompt.json',
    'result_file': 'ml_kem_encap_decap_result.json',
    'target': '../testvectors/ml-kem-encap-vectors.h',
    'array_init': 'const std::vector<MlKemEncapTestVector> MlKemEncapTests = {\n',
    'formatter' : MLKEM_ENCAP(),
    'crop_size_end': -2,
    'section': 'mlkem_encap_vectors_h__',
    'comment' : ''
}

ml_kem_keygen_params = {
    'source_dir': 'source_vectors/',
    'test_name': 'ML-KEM-keyGen-FIPS203',
    'tag': 'v1.1.0.40',
    'prompt_file': 'ml_kem_keygen_prompt.json',
    'result_file': 'ml_kem_keygen_result.json',
    'target': '../testvectors/ml-kem-keygen-vectors.h',
    'array_init': 'const std::vector<MlKemKeyGenTestVector> MlKemKeyGenTests = {\n',
    'formatter' : MLKEM_KEYGEN(),
    'crop_size_end': -2,
    'section': 'mlkem_keygen_vectors_h__',
    'comment' : ''
}


def update_tests(tests):

    remote_base = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/refs/tags/"
    for test in tests:
        remote = remote_base+test['tag']+"/gen-val/json-files/"+test['test_name']+"/"
        subprocess.check_call(['wget', remote+"/prompt.json", '-O',
                               script_dir+'/'+test['source_dir']+test['prompt_file']])
        subprocess.check_call(['wget', remote+"/expectedResults.json", '-O',
                               script_dir+'/'+test['source_dir']+test['result_file']])

def generate_test_vectors():
    """Generate C-header files for all supported tests."""
    all_tests = [ ml_kem_keygen_params, ml_kem_encap_params, ml_kem_decap_params ]
#all_tests = [ml_kem_keygen_params, ml_kem_encap_params, ml_kem_decap_params ]
    update_tests(all_tests)
    for test in all_tests:
        generate_vectors_file(test)

def main():
    generate_test_vectors()

if __name__ == '__main__':
    main()
