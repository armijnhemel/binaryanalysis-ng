#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG and looks up the
file in a proximity matching database using a few metrics:

* TLSH of the whole file
* telfhash (if any)
* TLSH generated from any identifiers (if any)
* MalwareBazaar (if configured)

The result is a TLSH hash for each positive match. This hash then needs to
be searched in an another external data source, for example a database.
'''

import collections
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
@click.option('--config-file', '-c', required=True, help='path to configuration file',
              type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='path to BANG result directories',
               type=click.Path(exists=True))
@click.option('--identifiers', '-i', help='pickle with low quality identifiers',
              type=click.File('rb'))
def main(config_file, result_directory, identifiers):
    result_directory = pathlib.Path(result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        raise click.ClickException(f"{result_directory} is not a directory")

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
            print("Invalid configuration file, section {i} missing, exiting",
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

        if 'labels' in bang_data:
            if 'elf' in bang_data['labels']:
                filename = file_pickle.parent / 'pathname'
                if filename.exists():
                    # store result data
                    result_data = {}

                    # now read the contents
                    with open(filename, 'r') as pathname:
                        elf_file = pathname.read()

                        if 'tlsh' in bang_data['metadata']['hashes']:
                            result_data['tlsh'] = bang_data['metadata']['hashes']['tlsh']

                        if 'metadata' in bang_data:
                            if 'telfhash' in bang_data['metadata']:
                                result_data['telfhash'] = bang_data['metadata']['telfhash']

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

                    # concatenate the identifiers:
                    # first strings, then functions, then variables
                    all_identifiers = sorted(strings) + sorted(functions) + sorted(variables)
                    data = " ".join(all_identifiers).encode()

                    # compute TLSH for identifiers
                    tlsh_result = tlsh.hash(data)
                    if tlsh_result != 'TNULL':
                        result_data['tlsh_identifiers'] = tlsh_result

                    # query the end points hash
                    for h in metadata:
                        if h in endpoints:
                            endpoint = endpoints[h]
                            try:
                                if metadata[h] == '':
                                    continue
                                req = session.get(f"{endpoint}, {metadata[h]}")
                                json_results = req.json()
                                if json_results['match']:
                                    if json_results['distance'] <= maximum_distance:
                                        print(endpoint, bang_file, json_results['tlsh'])
                                        sys.stdout.flush()
                            except requests.exceptions.RequestException:
                                pass

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
