#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG
and looks up strings identifiers in a Meilisearch database
to determine which source code files the identifiers could
have been from.
'''

import collections
import os
import pathlib
import pickle
import shutil
import sys
import re

import click
import meilisearch

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

@click.command(short_help='query Meilisearch with results from a BANG result directory')
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

    if not 'meilisearch' in configuration:
        print("\'meilisearch\' section missing in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    if not 'index' in configuration['meilisearch']:
        print("\'index\' section missing in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    meili_index = configuration['meilisearch']['index']

    string_min_cutoff = 8
    if 'string_min_cutoff' in configuration['meilisearch']:
        if isinstance(configuration['meilisearch']['string_min_cutoff'], int):
            string_min_cutoff = configuration['meilisearch']['string_min_cutoff']

    string_max_cutoff = 200
    if 'string_max_cutoff' in configuration['meilisearch']:
        if isinstance(configuration['meilisearch']['string_max_cutoff'], int):
            string_max_cutoff = configuration['meilisearch']['string_max_cutoff']

    # set up a minimal environment for meilisearch
    meili_env = {'verbose': verbose, 'string_min_cutoff': string_min_cutoff,
                 'string_max_cutoff': string_max_cutoff}

    # some sanity checks for Meilisearch
    client = meilisearch.Client('http://127.0.0.1:7700')
    meili_index = client.index(meili_index)

    try:
        health = client.health()
    except meilisearch.errors.MeiliSearchCommunicationError:
        print("Meilisearch not running, exiting...", file=sys.stderr)
        sys.exit(1)

    # open the top level pickle
    bang_pickle = result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    try:
        bang_data = pickle.load(open(bang_pickle, 'rb'))
    except:
        print("Cannot unpickle BANG data", file=sys.stderr)
        sys.exit(1)

    # walk the BANG results
    file_deque = collections.deque()
    file_deque.append(bang_pickle)

    # walk the unpack tree recursively and grab all the ELF file pickles
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
                                if len(s) < meili_env['string_min_cutoff']:
                                    continue
                                if len(s) > meili_env['string_max_cutoff']:
                                    continue
                                # ignore whitespace-only strings
                                if re.match(r'^\s+$', s) is None:
                                    strings.add(s)

                        # process the identifiers
                        for f in strings:
                            results = meili_index.search('"%s"' % f)
                            if results['hits'] != []:
                                for r in results['hits']:
                                    print(elf_file, f, r['id'], r['language'], r['paths'])
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
