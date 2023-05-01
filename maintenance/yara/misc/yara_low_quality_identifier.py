#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
'''

import sys
import os
import argparse
import pathlib
import pickle

import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from yara_config import YaraConfig

@click.command(short_help='process BANG result files and output YARA')
#@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', help='YARA result directories', type=click.Path(exists=True), required=True)
@click.option('--identifiers', '-i', help='pickle with low quality identifiers', type=click.File('rb'))
def main(result_directory, identifiers):

    yara_directory = pathlib.Path(result_directory)
    if not yara_directory.is_directory():
        print('bla')

    func_files = yara_directory.glob("*.func")
    var_files = yara_directory.glob("*.var")

    package_to_source, source_to_package, package_name_to_source, source_to_package_name = pickle.load(open('debian_packages.pickle', 'rb'))

    # store functions per package
    functions_per_package = {}

    for v in func_files:
        if v.stem in package_to_source:
            source_package = package_to_source[v.stem]
            if source_package not in functions_per_package:
                functions_per_package[source_package] = set()
            with v.open() as ff:
                identifiers = []
                for line in ff:
                    functions_per_package[source_package].add(line.strip())
         
    for package_name in functions_per_package:
        if len(functions_per_package[package_name]) != 0:
            yara_file = yara_directory / 'package' / ("%s.func" % package_name)
            with yara_file.open(mode='w') as p:
                for f in sorted(functions_per_package[package_name]):
                    p.write(f)
                    p.write('\n')

    # store variables per package
    variables_per_package = {}

    for v in var_files:
        if v.stem in package_to_source:
            source_package = package_to_source[v.stem]
            if source_package not in variables_per_package:
                variables_per_package[source_package] = set()
            with v.open() as ff:
                identifiers = []
                for line in ff:
                    variables_per_package[source_package].add(line.strip())
         
    for package_name in variables_per_package:
        if len(variables_per_package[package_name]) != 0:
            yara_file = yara_directory / 'package' / ("%s.var" % package_name)
            with yara_file.open(mode='w') as p:
                for f in sorted(variables_per_package[package_name]):
                    p.write(f)
                    p.write('\n')


if __name__ == "__main__":
    main(sys.argv)
