#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright - Armijn Hemel
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG
and runs YARA rules to identify what is inside
'''

import pathlib
import pickle
import sys

import click
import yara

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

@click.command(short_help='Scan licenses using YARA fingerprinting')
@click.option('--config', '-c', required=True, help='path to configuration file',
              type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='path to BANG result directories')
def main(config, result_directory):
    result_directory = pathlib.Path(result_directory)

    # the result directory should exist ...
    if not result_directory.exists():
        raise click.ClickException(f"Directory {result_directory} does not exist, exiting.")

    # ... and should be a real directory
    if not result_directory.is_dir():
        raise click.ClickException(f"{result_directory} is not a directory, exiting.")

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

    if not 'license_rules' in configuration['yara']:
        print("\'license_rules\' section missing in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    # set up a minimal environment for yara
    yara_env = {'verbose': verbose}

    # check the compiled_rules directory
    rules_directory = pathlib.Path(configuration['yara']['license_rules'])

    # the result directory should exist ...
    if not rules_directory.exists():
        print(f"Rules directory {rules_directory} does not exist, exiting.", file=sys.stderr)
        sys.exit(1)

    # ... and should be a real directory
    if not rules_directory.is_dir():
        print(r"{rules_directory} is not a directory, exiting.", file=sys.stderr)
        sys.exit(1)

    # load the YARA rules found in the directory
    rules = []
    for result in rules_directory.glob('**/*.yarac'):
        try:
            rules.append(yara.load(str(result)))
        except yara.Error as e:
            pass

    # open the top level pickle
    bang_pickle = result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    bang_data = pickle.load(open(bang_pickle, 'rb'))

    files = []

    # walk the relative files in the directory
    if 'unpacked_relative_files' in bang_data:
        for relative_file in bang_data['unpacked_relative_files']:
            # first check if the data actually exists
            scan_file = result_directory.parent / relative_file

            # grab the meta directory of the file
            file_meta_directory = bang_data['unpacked_relative_files'][relative_file]

            # load the pickle with meta information
            file_pickle = result_directory.parent / file_meta_directory / 'info.pkl'
            if not file_pickle.exists():
                # pickle not found. Perhaps nothing interesting was detected
                continue

            # open the result pickle
            try:
                results_data = pickle.load(open(file_pickle, 'rb'))
            except Exception as e:
                continue

            # optionally filter labels here
            files.append(scan_file)

    # TODO: absolute files, extracted files

    for scan_file in files:
        for r in rules:
            matches = r.match(str(scan_file))
            if matches == []:
                continue
            for match in matches:
                print(f'Rule <{match.rule}> matched for {scan_file}')
                print(f'  number of strings matched: {len(match.strings)}')
                if verbose:
                    print('\n  Matched strings:\n')
                    for s in match.strings:
                        print(s[2].decode())
                print()

if __name__ == "__main__":
    main()
