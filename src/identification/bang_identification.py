#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG, runs YARA rules to
identify what is inside, finds closest files using proximity matching and
searches results in VulnerableCode.
'''

import pathlib
import pickle
import re
import sys
import urllib

import click
import requests
import tlsh
import yara

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from VulnerableCodeConnector import VulnerableCodeConnector, VulnerableCodeException


@click.command(short_help='run YARA rules on a BANG result directory')
@click.option('--config', '-c', required=True, help='path to configuration file',
              type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='path to BANG result directories',
              type=click.Path(exists=True))
@click.option('--identifiers', '-i', help='pickle with low quality identifiers',
              type=click.File('rb'))
def main(config, result_directory, identifiers):
    result_directory = pathlib.Path(result_directory)

    # result_directory should be a real directory
    if not result_directory.is_dir():
        click.ClickException(f"{result_directory} is not a directory.")

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

    if not 'compiled_rules' in configuration['yara']:
        print("\'compiled_rules\' section missing in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    # identifier settings for YARA
    yara_error_fatal = False
    if 'error_fatal' in configuration['yara']:
        if isinstance(configuration['yara']['error_fatal'], bool):
            yara_error_fatal = configuration['yara']['error_fatal']

    yara_string_min_cutoff = 8
    if 'string_min_cutoff' in configuration['yara']:
        if isinstance(configuration['yara']['string_min_cutoff'], int):
            yara_string_min_cutoff = configuration['yara']['string_min_cutoff']

    yara_string_max_cutoff = 200
    if 'string_max_cutoff' in configuration['yara']:
        if isinstance(configuration['yara']['string_max_cutoff'], int):
            yara_string_max_cutoff = configuration['yara']['string_max_cutoff']

    yara_identifier_cutoff = 2
    if 'identifier_cutoff' in configuration['yara']:
        if isinstance(configuration['yara']['identifier_cutoff'], int):
            yara_identifier_cutoff = configuration['yara']['identifier_cutoff']

    yara_ignore_weak_symbols = False
    if 'ignore_weak_symbols' in configuration['yara']:
        if isinstance(configuration['yara']['ignore_weak_symbols'], bool):
            yara_ignore_weak_symbols = configuration['yara']['ignore_weak_symbols']

    # set up a minimal environment for yara
    yara_env = {'string_min_cutoff': yara_string_min_cutoff,
                'string_max_cutoff': yara_string_max_cutoff,
                'identifier_cutoff': yara_identifier_cutoff,
                'ignore_weak_symbols': yara_ignore_weak_symbols}

    # check the compiled_rules directory
    rules_directory = pathlib.Path(configuration['yara']['compiled_rules'])

    # the result directory should exist ...
    if not rules_directory.exists():
        print(f"Rules directory {rules_directory} does not exist, exiting.", file=sys.stderr)
        sys.exit(1)

    # ... and should be a real directory
    if not rules_directory.is_dir():
        print(f"{rules_directory} is not a directory, exiting.", file=sys.stderr)
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

    # identifier settings for proximity matching
    proximity_string_min_cutoff = 8
    if 'string_min_cutoff' in configuration['proximity']:
        if isinstance(configuration['proximity']['string_min_cutoff'], int):
            proximity_string_min_cutoff = configuration['proximity']['string_min_cutoff']

    proximity_string_max_cutoff = 200
    if 'string_max_cutoff' in configuration['proximity']:
        if isinstance(configuration['proximity']['string_max_cutoff'], int):
            proximity_string_max_cutoff = configuration['proximity']['string_max_cutoff']

    proximity_identifier_cutoff = 2
    if 'identifier_cutoff' in configuration['proximity']:
        if isinstance(configuration['proximity']['identifier_cutoff'], int):
            proximity_identifier_cutoff = configuration['proximity']['identifier_cutoff']

    proximity_ignore_weak_symbols = False
    if 'ignore_weak_symbols' in configuration['proximity']:
        if isinstance(configuration['proximity']['ignore_weak_symbols'], bool):
            proximity_ignore_weak_symbols = configuration['proximity']['ignore_weak_symbols']

    proximity_maximum_distance = 80
    if 'maximum_distance' in configuration['proximity']:
        if isinstance(configuration['proximity']['maximum_distance'], int):
            proximity_maximum_distance = configuration['proximity']['maximum_distance']

    # set up a minimal environment for proximity matching
    proximity_env = {'string_min_cutoff': proximity_string_min_cutoff,
                     'string_max_cutoff': proximity_string_max_cutoff,
                     'identifier_cutoff': proximity_identifier_cutoff,
                     'ignore_weak_symbols': proximity_ignore_weak_symbols,
                     'maximum_distance': proximity_maximum_distance}

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
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    if not (result_directory / 'unpack').exists():
        print("unpack directory not found, exiting", file=sys.stderr)
        sys.exit(1)

    bang_data = pickle.load(open(bang_pickle, 'rb'))

    min_string_cutoff = min(yara_env['string_min_cutoff'], proximity_env['string_min_cutoff'])
    max_string_cutoff = max(yara_env['string_max_cutoff'], proximity_env['string_max_cutoff'])
    ignore_weak_symbols = yara_env['ignore_weak_symbols'] and proximity_env['ignore_weak_symbols']

    for bang_file in bang_data['scantree']:
        if 'elf' in bang_data['scantree'][bang_file]['labels']:
            # load the pickle for the ELF file
            sha256 = bang_data['scantree'][bang_file]['hash']['sha256']

            # open the result pickle
            try:
                results_data = pickle.load(open(result_directory / 'results' / f"{sha256}.pickle", 'rb'))
            except:
                continue

            # store various TLSH hashes
            metadata = {}

            if 'tlsh' in results_data:
                metadata['tlsh'] = results_data['tlsh']

            # skip entries for which there is no useful metadata
            if 'metadata' in results_data:
                if 'telfhash' in results_data['metadata']:
                    metadata['telfhash'] = results_data['metadata']['telfhash']

                # extract the identifiers
                yara_strings = set()
                yara_functions = set()
                yara_variables = set()

                proximity_strings = set()
                proximity_functions = set()
                proximity_variables = set()

                if results_data['metadata']['strings'] != []:
                    for s in results_data['metadata']['strings']:
                        if len(s) < min_string_cutoff:
                            continue
                        if len(s) > max_string_cutoff:
                            continue

                        # ignore whitespace-only strings
                        if re.match(r'^\s+$', s) is None:
                            if len(s) >= yara_env['string_min_cutoff'] and len(s) <= yara_env['string_max_cutoff']:
                                yara_strings.add(s)
                            if len(s) >= proximity_env['string_min_cutoff'] and len(s) <= proximity_env['string_max_cutoff']:
                                proximity_strings.add(s)

                if results_data['metadata']['symbols'] != []:
                    for s in results_data['metadata']['symbols']:
                        if s['section_index'] == 0:
                            continue

                        is_weak = False
                        if s['binding'] == 'weak':
                            if ignore_weak_symbols:
                                continue
                            is_weak = True

                        if len(s['name']) < yara_env['identifier_cutoff']:
                            continue
                        if '@@' in s['name']:
                            identifier_name = s['name'].rsplit('@@', 1)[0]
                        elif '@' in s['name']:
                            identifier_name = s['name'].rsplit('@', 1)[0]
                        else:
                            identifier_name = s['name']
                        if s['type'] == 'func':
                            if not (is_weak and yara_env['ignore_weak_symbols']):
                                yara_functions.add(identifier_name)
                            if not (is_weak and proximity_env['ignore_weak_symbols']):
                                proximity_functions.add(identifier_name)
                        elif s['type'] == 'object':
                            if not (is_weak and yara_env['ignore_weak_symbols']):
                                yara_variables.add(identifier_name)
                            if not (is_weak and proximity_env['ignore_weak_symbols']):
                                proximity_variables.add(identifier_name)

                # concatenate the strings, functions and variables for YARA
                yara_data = "\n".join(sorted(yara_strings))
                yara_data += "\n".join(sorted(yara_functions))
                yara_data += "\n".join(sorted(yara_variables))

                # run the YARA rules
                for r in rules:
                    matches = r.match(data=yara_data)
                    if matches == []:
                        continue
                    for match in matches:
                        print(f'Rule {match.rule} matched for {bang_file}')
                        print(f'  number of strings matched: {len(match.strings)}')
                        if verbose:
                            print('\n  Matched strings:\n')
                            for s in match.strings:
                                print(s[2].decode())

                # concatenate the strings, functions and variables for proximity matching
                proximity_data = " ".join(sorted(yara_strings))
                proximity_data += " ".join(sorted(yara_functions))
                proximity_data += " ".join(sorted(yara_variables))

                # turn into binary as TLSH expects that
                proximity_data = proximity_data.encode()

                # compute TLSH for identifiers
                tlsh_result = tlsh.hash(proximity_data)
                if tlsh_result != 'TNULL':
                    metadata['tlsh_identifiers'] = tlsh_result

            # query the TLSH hashes
            for h in metadata:
                if h in endpoints:
                    endpoint = endpoints[h]
                    try:
                        if metadata[h] == '':
                            continue
                        req = session.get(f'{endpoint}/{metadata[h]}')
                        json_results = req.json()
                        if json_results['match']:
                            if json_results['distance'] <= maximum_distance:
                                print(endpoint, bang_file, json_results['tlsh'])
                                sys.stdout.flush()
                    except requests.exceptions.RequestException:
                        pass




if __name__ == "__main__":
    main()
