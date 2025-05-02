#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG
and runs YARA rules to identify what is inside
'''

import collections
import pathlib
import pickle
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
@click.option('--config', '-c', required=True, help='path to configuration file',
              type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='path to BANG result directories',
              type=click.Path(exists=True))
def main(config, result_directory):
    result_directory = pathlib.Path(result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        raise click.ClickException(f"{result_directory} is not a directory.")

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
        print("Rules directory {rules_directory} does not exist.")
        sys.exit(1)

    # ... and should be a real directory
    if not rules_directory.is_dir():
        print("{rules_directory} is not a directory, exiting.", file=sys.stderr)
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
    bang_pickle = result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    # load the pickle
    bang_data = pickle.load(open(bang_pickle, 'rb'))

    # create a deque to store results in and retrieve results from
    file_deque = collections.deque()
    file_deque.append(bang_pickle)

    # walk the unpack tree recursively and grab all the ELF files
    while True:
        try:
            file_pickle = file_deque.popleft()
        except:
            break

        try:
            bang_data = pickle.load(open(file_pickle, 'rb'))
        except:
            continue

        if 'labels' in bang_data:
            if 'elf' in bang_data['labels']:
                filename = file_pickle.parent / 'pathname'
                if filename.exists():
                    # now read the contents
                    with open(filename, 'r') as pathname:
                        elf_file = pathname.read()

                        strings = set()
                        functions = set()
                        variables = set()
                        if bang_data['metadata']['strings'] != []:
                            for s in bang_data['metadata']['strings']:
                                if len(s) < yara_env['string_min_cutoff']:
                                    continue
                                if len(s) > yara_env['string_max_cutoff']:
                                    continue
                                # ignore whitespace-only strings
                                if re.match(r'^\s+$', s) is None:
                                    strings.add(s)
                        if bang_data['metadata']['symbols'] != []:
                            for s in bang_data['metadata']['symbols']:
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
                                print('---')
                                print(f'Rule {match.rule} matched for {elf_file}')
                                print(f'  number of strings matched: {len(match.strings)}')
                                if verbose:
                                    print('\n  Matched strings:\n')
                                    for s in match.strings:
                                        print(s[2].decode())
                                    print()

        # finally add the unpacked/extracted files to the queue
        if 'unpacked_relative_files' in bang_data:
            for unpacked_file in bang_data['unpacked_relative_files']:
                file_meta_directory = bang_data['unpacked_relative_files'][unpacked_file]
                file_pickle = result_directory.parent / file_meta_directory / 'info.pkl'
                file_deque.append(file_pickle)
        if 'unpacked_absolute_files' in bang_data:
            for unpacked_file in bang_data['unpacked_absolute_files']:
                file_meta_directory = bang_data['unpacked_absolute_files'][unpacked_file]
                file_pickle = result_directory.parent / file_meta_directory / 'info.pkl'
                file_deque.append(file_pickle)
        if 'extracted_files' in bang_data:
            for unpacked_file in bang_data['extracted_files']:
                file_meta_directory = bang_data['extracted_files'][unpacked_file]
                file_pickle = result_directory.parent / file_meta_directory / 'info.pkl'
                file_deque.append(file_pickle)


if __name__ == "__main__":
    main()
