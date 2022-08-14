#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG
and runs YARA rules to identify what is inside
'''

import os
import pathlib
import pickle
import shutil
import sys
import re

import click
import yara

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

@click.command(short_help='run YARA rules on a BANG result directory')
@click.option('--config', '-c', required=True, help='path to configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='path to BANG result directories', type=click.Path(exists=True))
def main(config, result_directory):
    result_directory = pathlib.Path(result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        print("%s is not a directory, exiting." % result_directory, file=sys.stderr)
        sys.exit(1)

    # read the configuration file. This is in YAML format
    try:
        configuration = load(config, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    verbose = False
    if 'verbose' in configuration['general']:
        if isinstance(configuration['general']['verbose'], bool):
            verbose = configuration['general']['verbose']

    if not 'yara' in configuration:
        print("\'yara\' section missing in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    yara_error_fatal = False
    if 'error_fatal' in configuration['yara']:
        if isinstance(configuration['yara']['error_fatal'], bool):
            yara_error_fatal = configuration['yara']['error_fatal']

    if not 'compiled_rules' in configuration['yara']:
        print("\'compiled_rules\' section missing in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    string_min_cutoff = 8
    if 'string_min_cutoff' in configuration['yara']:
        if isinstance(configuration['yara']['string_min_cutoff'], int):
            string_min_cutoff = configuration['yara']['string_min_cutoff']

    string_max_cutoff = 200
    if 'string_max_cutoff' in configuration['yara']:
        if isinstance(configuration['yara']['string_max_cutoff'], int):
            string_max_cutoff = configuration['yara']['string_max_cutoff']

    identifier_cutoff = 2
    if 'identifier_cutoff' in configuration['yara']:
        if isinstance(configuration['yara']['identifier_cutoff'], int):
            identifier_cutoff = configuration['yara']['identifier_cutoff']

    ignore_weak_symbols = False
    if 'ignore_weak_symbols' in configuration['yara']:
        if isinstance(configuration['yara']['ignore_weak_symbols'], bool):
            ignore_weak_symbols = configuration['yara']['ignore_weak_symbols']

    # set up a minimal environment for yara
    yara_env = {'verbose': verbose, 'string_min_cutoff': string_min_cutoff,
            'string_max_cutoff': string_max_cutoff,
            'identifier_cutoff': identifier_cutoff,
            'ignore_weak_symbols': ignore_weak_symbols,}

    # check the compiled_rules directory
    rules_directory = pathlib.Path(configuration['yara']['compiled_rules'])

    # the result directory should exist ...
    if not rules_directory.exists():
        print("Rules directory %s does not exist, exiting." % rules_directory,
              file=sys.stderr)
        sys.exit(1)

    # ... and should be a real directory
    if not rules_directory.is_dir():
        print("%s is not a directory, exiting." % rules_directory,
              file=sys.stderr)
        sys.exit(1)

    # load the YARA rules found in the directory
    rules = []
    for result in rules_directory.glob('**/*.yarac'):
         try:
             rules.append(yara.load(str(result)))
         except yara.Error as e:
            if yara_error_fatal:
                print("Fatal YARA error:", e, file=sys.stderr)
                sys.exit(1)

    # open the top level pickle
    bang_pickle = result_directory / 'bang.pickle'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    if not (result_directory / 'unpack').exists():
        print("unpack directory not found, exiting", file=sys.stderr)
        sys.exit(1)

    bang_data = pickle.load(open(bang_pickle, 'rb'))

    # change working directory
    old_cwd = os.getcwd()
    os.chdir(result_directory / 'unpack')
    for bang_file in bang_data['scantree']:
        if 'elf' in bang_data['scantree'][bang_file]['labels']:
            # load the pickle for the ELF file
            sha256 = bang_data['scantree'][bang_file]['hash']['sha256']

            # open the result pickle
            try:
                results_data = pickle.load(open(result_directory / 'results' / ("%s.pickle" % sha256), 'rb'))
            except:
                continue
            if 'metadata' not in results_data:
                # example: statically linked binaries currently
                # have no associated metadata.
                continue

            strings = set()
            functions = set()
            variables = set()
            if results_data['metadata']['strings'] != []:
                for s in results_data['metadata']['strings']:
                    if len(s) < yara_env['string_min_cutoff']:
                        continue
                    if len(s) > yara_env['string_max_cutoff']:
                        continue
                    # ignore whitespace-only strings
                    if re.match(r'^\s+$', s) is None:
                        strings.add(s)
            if results_data['metadata']['symbols'] != []:
                for s in results_data['metadata']['symbols']:
                    if s['section_index'] == 0:
                        continue
                    if yara_env['ignore_weak_symbols']:
                        if s['binding'] == 'weak':
                            continue
                    if len(s['name']) < yara_env['identifier_cutoff']:
                        continue
                    if '@@' in s['name']:
                        identifier_name = s['name'].rsplit('@@', 1)[0]
                    elif '@' in s['name']:
                        identifier_name = s['name'].rsplit('@', 1)[0]
                    else:
                        identifier_name = s['name']
                    if s['type'] == 'func':
                        functions.add(identifier_name)
                    elif s['type'] == 'object':
                        variables.add(identifier_name)

            # concatenate the strings, functions and variables
            yara_data = "\n".join(sorted(strings))
            yara_data += "\n".join(sorted(functions))
            yara_data += "\n".join(sorted(variables))
            for r in rules:
                matches = r.match(data=yara_data)
                if matches == []:
                    continue
                for match in matches:
                    print('Rule %s matched for %s' % (match.rule, bang_file))
                    print('  number of strings matched: %d' % len(match.strings))
                    if verbose:
                        print('\n  Matched strings:\n')
                        for s in match.strings:
                            print(s[2].decode())

    os.chdir(old_cwd)

if __name__ == "__main__":
    main()
