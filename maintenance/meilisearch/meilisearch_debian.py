#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes Debian Packages.gz files
dynamically linked ELF files.
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



class DebPackage():
    def __init__(self):
        pass

@click.command(short_help='process Debian Packages.gz and store in Meilisearch')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--packages-file', '-p', required=True, help='Debian Package (uncompressed)', type=click.File('r'))
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

    cur_pkg = ''
    cur_description = ''
    cur_section = ''
    cur_homepage = ''

    deb_packages = []

    id_counter = 1

    try:
        for i in packages_file:
            if i.startswith('Package:'):
                # store the old package
                # TODO: store as DebPackage object
                if cur_pkg != '':
                    deb_pkg = {'package': cur_pkg, 'description': cur_description,
                               'section': cur_section, 'homepage': cur_homepage,
                               'id': id_counter}

                    deb_packages.append(deb_pkg)
                    id_counter += 1

                # set new package
                cur_pkg = i.strip().split(': ', 1)[1]
                cur_description = ''
                cur_section = ''
                cur_homepage = ''
            elif i.startswith('Description:'):
                cur_description = i.strip().split(': ', 1)[1]
            elif i.startswith('Section:'):
                cur_section = i.strip().split(': ', 1)[1]
            elif i.startswith('Homepage:'):
                cur_homepage = i.strip().split(': ', 1)[1]
    except Exception as e:
        print(e)
        sys.exit(1)

    # TODO: store as DebPackage object
    deb_pkg = {'package': cur_pkg, 'description': cur_description,
               'section': cur_section, 'homepage': cur_homepage,
               'id': id_counter}

    deb_packages.append(deb_pkg)

    # TODO: make configurable
    with open('/tmp/deb.json', 'w') as deb_json:
        json.dump(deb_packages, deb_json)

if __name__ == "__main__":
    main()
