#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes APK processed by BANG and runs apkid on them
to find any possible obfuscators.
'''

import json
import os
import pathlib
import pickle
import shutil
import subprocess
import sys
import tempfile

import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

@click.command(short_help='process BANG result files and output YARA')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', 'bang_result_directory', required=True, help='source code archive directory', type=click.Path(exists=True))
def main(config_file, bang_result_directory):
    result_directory = pathlib.Path(bang_result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        print("%s is not a directory, exiting." % result_directory)
        sys.exit(1)

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    verbose = False
    if 'verbose' in config['general']:
        if isinstance(config['general']['verbose'], bool):
            verbose = config['general']['verbose']

    # search for apkid
    # TODO: it might be possible to run apkid as a module instead
    if shutil.which('apkid') is None:
        print("apkid not found in path, exiting", file=sys.stderr)
        sys.exit(1)

    # open the top level pickle
    bang_pickle = result_directory / 'bang.pickle'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    bang_data = pickle.load(open(bang_pickle, 'rb'))

    # change working directory
    old_cwd = os.getcwd()
    os.chdir(result_directory / 'unpack')
    for bang_file in bang_data['scantree']:
        if 'apk' in bang_data['scantree'][bang_file]['labels']:
            p = subprocess.Popen(['apkid', '-j', bang_file],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (standard_out, standard_error) = p.communicate()

            if p.returncode != 0:
                continue

            try:
                apk_json = json.loads(standard_out)
            except:
                continue

            # TODO: further process results
            results = json.dumps(apk_json, indent=4)
            print(results)

    os.chdir(old_cwd)

if __name__ == "__main__":
    main()
