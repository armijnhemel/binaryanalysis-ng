#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG
and runs them in Qiling.
'''

import collections
import os
import pathlib
import pickle
import shutil
import sys
import re

import click
import qiling

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


@click.command(short_help='Emulate ELF files in Qiling')
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

    # open the top level pickle
    bang_pickle = result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    files = []
    file_deque = collections.deque()
    file_deque.append(bang_pickle)

    # walk the unpack tree recursively and grab all the APK files
    while True:
        try:
            file_pickle = file_deque.popleft()
        except:
            break

    # TODO: emulate single binary

if __name__ == "__main__":
    main()
