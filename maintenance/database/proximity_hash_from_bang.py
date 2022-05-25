#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes a single BANG result directory and generates TLSH
hashes for a concatenated list of identifiers extracted from dynamically
linked ELF files and outputs the result as JSON for further processing.

https://www.tdcommons.org/dpubs_series/5155/
'''

import json
import os
import pathlib
import pickle
import re
import sys
import tempfile

import click
import tlsh

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


@click.command(short_help='process BANG result files and output YARA')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', help='BANG result directory', type=click.Path(exists=True), required=True)
@click.option('--identifiers', '-i', help='pickle with low quality identifiers', type=click.File('rb'))
def main(config_file, result_directory, identifiers):

    result_directory = pathlib.Path(result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        print("Error: %s is not a directory, exiting." % result_directory, file=sys.stderr)
        sys.exit(1)

    lq_identifiers = {'elf': {'functions': [], 'variables': []}}

    # read the pickle with identifiers
    if identifiers is not None:
        try:
            lq_identifiers = pickle.load(identifiers)
        except:
            pass

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    for i in ['general', 'proximity']:
        if i not in config:
            print("Invalid configuration file, section %s missing, exiting" % i,
                  file=sys.stderr)
            sys.exit(1)

    verbose = False
    if 'verbose' in config['general']:
        if isinstance(config['general']['verbose'], bool):
            verbose = config['general']['verbose']

    if 'proximity_directory' not in config['proximity']:
        print("proximity_directory not defined in configuration, exiting",
              file=sys.stderr)
        sys.exit(1)

    proximity_directory = pathlib.Path(config['proximity']['proximity_directory'])
    if not proximity_directory.exists():
        print("proximity_directory %s does not exist, exiting" % proximity_directory,
              file=sys.stderr)
        sys.exit(1)

    if not proximity_directory.is_dir():
        print("proximity_directory is not a valid directory, exiting",
              file=sys.stderr)
        sys.exit(1)

    # check if the proximity directory is writable
    try:
        temp_name = tempfile.NamedTemporaryFile(dir=proximity_directory)
        temp_name.close()
    except:
        print("proximity_directory is not writable, exiting",
              file=sys.stderr)
        sys.exit(1)

    proximity_binary_directory = proximity_directory / 'json'

    proximity_binary_directory.mkdir(exist_ok=True)

    string_min_cutoff = 8
    if 'string_min_cutoff' in config['proximity']:
        if isinstance(config['proximity']['string_min_cutoff'], int):
            string_min_cutoff = config['proximity']['string_min_cutoff']

    string_max_cutoff = 200
    if 'string_max_cutoff' in config['proximity']:
        if isinstance(config['proximity']['string_max_cutoff'], int):
            string_max_cutoff = config['proximity']['string_max_cutoff']

    identifier_cutoff = 2
    if 'identifier_cutoff' in config['proximity']:
        if isinstance(config['proximity']['identifier_cutoff'], int):
            identifier_cutoff = config['proximity']['identifier_cutoff']

    # ignore object files (regular and GHC specific)
    ignored_suffixes = ['.o', '.p_o']

    ignore_weak_symbols = False
    if 'ignore_weak_symbols' in config['proximity']:
        if isinstance(config['proximity']['ignore_weak_symbols'], bool):
            ignore_weak_symbols = config['proximity']['ignore_weak_symbols']

    bang_pickle = result_directory / 'bang.pickle'

    if not bang_pickle.exists():
        print("BANG result pickle does not exist, exiting",
              file=sys.stderr)
        sys.exit(1)

    processed = False

    # open the top level pickle
    try:
        bang_data = pickle.load(open(bang_pickle, 'rb'))
    except:
        print("Could not open BANG result pickle, exiting",
              file=sys.stderr)
        sys.exit(1)

    for bang_file in bang_data['scantree']:
        metadata = {}
        if 'elf' in bang_data['scantree'][bang_file]['labels']:
            sha256 = bang_data['scantree'][bang_file]['hash']['sha256']
            elf_name = pathlib.Path(bang_file).name
            suffix = pathlib.Path(bang_file).suffix

            if suffix in ignored_suffixes:
                continue

            metadata['name'] = elf_name
            metadata['sha256'] = sha256

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
                    if len(s) < string_min_cutoff:
                        continue
                    if len(s) > string_max_cutoff:
                        continue
                    # ignore whitespace-only strings
                    if re.match(r'^\s+$', s) is None:
                        strings.add(s)
            if results_data['metadata']['symbols'] != []:
                for s in results_data['metadata']['symbols']:
                    if s['section_index'] == 0:
                        continue
                    if ignore_weak_symbols:
                        if s['binding'] == 'weak':
                            continue
                    if len(s['name']) < identifier_cutoff:
                        continue
                    if '@@' in s['name']:
                        identifier_name = s['name'].rsplit('@@', 1)[0]
                    elif '@' in s['name']:
                        identifier_name = s['name'].rsplit('@', 1)[0]
                    else:
                        identifier_name = s['name']
                    if s['type'] == 'func':
                        if identifier_name in lq_identifiers['elf']['functions']:
                            continue
                        functions.add(identifier_name)
                    elif s['type'] == 'object':
                        if identifier_name in lq_identifiers['elf']['variables']:
                            continue
                        variables.add(identifier_name)
            if strings == set() and variables == set() and functions == set():
                continue

            strings = sorted(strings)
            variables = sorted(variables)
            functions = sorted(functions)

            # concatenate the identifiers:
            # first strings, then functions, then variables
            all_identifiers = strings + functions + variables
            data = " ".join(all_identifiers).encode()

            # compute TLSH and write JSON
            tlsh_result = tlsh.hash(data)
            if tlsh_result != 'TNULL':
                pass


if __name__ == "__main__":
    main()
