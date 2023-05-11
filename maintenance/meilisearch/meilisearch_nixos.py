#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes NixOS package information obtained with:

$ nix-env -qa --json
'''

import json
import sys

import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader



@click.command(short_help='process NixOS packages information and store in Meilisearch')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--packages-file', '-p', required=True, help='NixOS JSON', type=click.File('r'))
def main(config_file, packages_file):

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    for i in ['general']:
        if i not in config:
            print("Invalid configuration file, section %s missing, exiting" % i,
                  file=sys.stderr)
            sys.exit(1)

    try:
        packages = json.load(packages_file)
    except:
        print("Invalid JSON", file=sys.stderr)
        sys.exit(1)

    nixos_packages = []

    id_counter = 1

    try:
        for i in packages:
            nixos_obj = {'id': id_counter, 'name': packages[i]['name'], 'package': packages[i]['pname'],
                         'version': packages[i]['version'],
                         'homepage': packages[i]['meta'].get('homepage', ''),
                         'description': packages[i]['meta'].get('description', ''),
                         'longDescription': packages[i]['meta'].get('longDescription', '')}
            nixos_packages.append(nixos_obj)
            id_counter += 1
    except Exception as e:
        print(e, i)
        sys.exit(1)

    print(json.dumps(nixos_packages, indent=4))

if __name__ == "__main__":
    main()
