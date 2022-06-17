#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG and looks up the
file in a proximity matching database using a few metrics:

* TLSH of the whole file
* telfhash (if any)
* TLSH generated from any identifiers (if any)
* MalwareBazaar

The result is a TLSH hash for each positive match. This hash then needs to
be searched in an another external data source, for example a database.
'''

import os
import pathlib
import pickle
import sys
import re
import urllib

import click
import requests
import tlsh

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


@click.command(short_help='process BANG result directory and extract/generate TLSH hashes for proximity matching')
@click.option('--config-file', '-c', required=True, help='path to configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='path to BANG result directories', type=click.Path(exists=True))
@click.option('--identifiers', '-i', help='pickle with low quality identifiers', type=click.File('rb'))
def main(config_file, result_directory, identifiers):
    result_directory = pathlib.Path(result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        print("%s is not a directory, exiting." % result_directory, file=sys.stderr)
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
        configuration = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    for i in ['general', 'proximity']:
        if i not in configuration:
            print("Invalid configuration file, section %s missing, exiting" % i,
                  file=sys.stderr)
            sys.exit(1)

    verbose = False
    if 'verbose' in configuration['general']:
        if isinstance(configuration['general']['verbose'], bool):
            verbose = configuration['general']['verbose']

    string_min_cutoff = 8
    if 'string_min_cutoff' in configuration['proximity']:
        if isinstance(configuration['proximity']['string_min_cutoff'], int):
            string_min_cutoff = configuration['proximity']['string_min_cutoff']

    string_max_cutoff = 200
    if 'string_max_cutoff' in configuration['proximity']:
        if isinstance(configuration['proximity']['string_max_cutoff'], int):
            string_max_cutoff = configuration['proximity']['string_max_cutoff']

    identifier_cutoff = 2
    if 'identifier_cutoff' in configuration['proximity']:
        if isinstance(configuration['proximity']['identifier_cutoff'], int):
            identifier_cutoff = configuration['proximity']['identifier_cutoff']

    # ignore object files (regular and GHC specific)
    ignored_suffixes = ['.o', '.p_o']

    ignore_weak_symbols = False
    if 'ignore_weak_symbols' in configuration['proximity']:
        if isinstance(configuration['proximity']['ignore_weak_symbols'], bool):
            ignore_weak_symbols = configuration['proximity']['ignore_weak_symbols']

    maximum_distance = 70
    if 'maximum_distance' in configuration['proximity']:
        if isinstance(configuration['proximity']['maximum_distance'], int):
            maximum_distance = configuration['proximity']['maximum_distance']

    # store endpoints from the configuration file
    endpoints = {}
    for endpoint in configuration['proximity']['endpoints']:
        # check if the endpoint URL is actually valid
        try:
            # grab the first item of the values
            e = next(iter(endpoint.values()))
            parsed_url = urllib.parse.urlparse(e)
        except Exception:
            continue
        endpoints.update(endpoint)

    # create a requests session
    session = requests.Session()

    # open the top level pickle
    bang_pickle = result_directory / 'bang.pickle'
    if not bang_pickle.exists():
        print("BANG result pickle does not exist, exiting",
              file=sys.stderr)
        sys.exit(1)

    # open the top level pickle
    try:
        bang_data = pickle.load(open(bang_pickle, 'rb'))
    except:
        print("Could not open BANG result pickle, exiting",
              file=sys.stderr)
        sys.exit(1)

    for bang_file in bang_data['scantree']:
        if 'elf' in bang_data['scantree'][bang_file]['labels']:
            # load the pickle for the ELF file
            sha256 = bang_data['scantree'][bang_file]['hash']['sha256']
            suffix = pathlib.Path(bang_file).suffix

            if suffix in ignored_suffixes:
                continue

            metadata = {}

            # open the result pickle
            try:
                results_data = pickle.load(open(result_directory / 'results' / ("%s.pickle" % sha256), 'rb'))
            except:
                continue

            if 'tlsh' in results_data:
                metadata['tlsh'] = results_data['tlsh']

            if 'metadata' in results_data:
                if 'telfhash' in results_data['metadata']:
                    metadata['telfhash'] = results_data['metadata']['telfhash']

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

                # concatenate the identifiers:
                # first strings, then functions, then variables
                all_identifiers = sorted(strings) + sorted(functions) + sorted(variables)
                data = " ".join(all_identifiers).encode()

                # compute TLSH for identifiers
                tlsh_result = tlsh.hash(data)
                if tlsh_result != 'TNULL':
                    metadata['tlsh_identifiers'] = tlsh_result

            # query the TLSH hash
            for h in metadata:
                if h in endpoints:
                    endpoint = endpoints[h]
                    try:
                        if metadata[h] == '':
                            continue
                        req = session.get('%s/%s' % (endpoint, metadata[h]))
                        json_results = req.json()
                        if json_results['match']:
                            if json_results['distance'] <= maximum_distance:
                                print(endpoint, bang_file, json_results['tlsh'])
                                sys.stdout.flush()
                    except requests.exceptions.RequestException:
                        pass


if __name__ == "__main__":
    main()
