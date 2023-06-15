#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
Proof of concept script documenting how to use the VulnerableCodeConnector class
'''

import click
import packageurl

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from VulnerableCodeConnector import VulnerableCodeConnector, VulnerableCodeException

@click.command(short_help='query VulnerableCode using a package URL')
@click.option('--config', '-c', required=True, help='path to configuration file', type=click.File('r'))
def main(config):

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

    if 'url' not in configuration['vulnerablecode']:
        print("'url' not in configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    vulnerable_code_connector = VulnerableCodeConnector(configuration['vulnerablecode'])
    try:
        results = vulnerable_code_connector.query('pkg:alpine/busybox@1.35.0-r7')
    except VulnerableCodeException as e:
        print(e.args)
        sys.exit(1)

    for r in results['results']:
        print(r)

if __name__ == "__main__":
    main()
