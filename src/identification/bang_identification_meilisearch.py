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

    # open the top level pickle
    bang_pickle = result_directory / 'bang.pickle'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    if not (result_directory / 'unpack').exists():
        print("unpack directory not found, exiting", file=sys.stderr)
        sys.exit(1)

    try:
        bang_data = pickle.load(open(bang_pickle, 'rb'))
    except pickle.PickleError as e:
        print("cannot unpickle", file=sys.stderr)
        sys.exit(1)

    # some sanity checks for Meilisearch
    client = meilisearch.Client('http://127.0.0.1:7700')
    meili_index = client.index(meili_index)

    try:
        health = client.health()
    except meilisearch.errors.MeiliSearchCommunicationError:
        print("Meilisearch not running, exiting...", file=sys.stderr)
        sys.exit(1)

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
                        print(bang_file, f, r['id'], r['language'], r['paths'])
                    print()

    os.chdir(old_cwd)

if __name__ == "__main__":
    main()
