#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes JSON results from cvehound
'''

import json
import os
import sys

import packageurl
import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


@click.command(short_help='process cvehound output')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--json-file', '-j', required=True, help='cvehound JSON output', type=click.File('rb'))
def main(config_file, json_file):

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    for i in ['general', 'cvehound']:
        if i not in config:
            print("Invalid configuration file, section %s missing, exiting" % i,
                  file=sys.stderr)
            sys.exit(1)

    verbose = False
    if 'verbose' in config['general']:
        if isinstance(config['general']['verbose'], bool):
            verbose = config['general']['verbose']

    # read the cvehound JSON file
    try:
       cvehound_json = json.load(json_file)
    except:
        print("Could not read cvehound json, exiting", file=sys.stderr)
        sys.exit(1)

    for result in cvehound_json['results']:
        for line in cvehound_json['results'][result]['spatch_output'].splitlines():
            file_name, line_number, character_range, error_msg, cve = line.rsplit(':', maxsplit=5)

            # clean up superfluous whitespace
            file_name = file_name.strip()
            line_number = line_number.strip()
            character_range = character_range.strip()

if __name__ == "__main__":
    main()
