#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes ELF files extracted/tagged by BANG
and runs cve-bin-tool on them.
'''

import collections
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
@click.option('--result-directory', '-r', 'bang_result_directory', required=True, help='BANG result directories', type=click.Path(exists=True))
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

    # check for cve-bin-tool
    if shutil.which('cve-bin-tool') is None:
        print("cve-bin-tool not found in path, exiting", file=sys.stderr)
        sys.exit(1)

    # open the top level pickle
    bang_pickle = result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    bang_data = pickle.load(open(bang_pickle, 'rb'))

    update_now = False

    files = []
    file_deque = collections.deque()
    file_deque.append(bang_pickle)

    # walk the unpack tree recursively and grab all the ELF files
    while True:
        try:
            file_pickle = file_deque.popleft()
        except:
            break

        try:
            bang_data = pickle.load(open(file_pickle, 'rb'))
        except:
            continue

        if 'labels' in bang_data:
            if 'elf' in bang_data['labels']:
                filename = file_pickle.parent / 'pathname'
                if filename.exists():
                    # now read the contents
                    with open(filename, 'r') as pathname:
                        elf_file = pathname.read()
                        elf = result_directory.parent / elf_file
                        if elf.exists():
                            files.append(elf)

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

    for bang_file in files:
        temporary_file = tempfile.mkstemp()
        os.fdopen(temporary_file[0]).close()
        os.unlink(temporary_file[1])
        temp_name = '%s.json' % temporary_file[1]
        # for some reason "quiet mode" does not output any JSON
        # TODO: test with a newer cve-bin-tool and retest
        if update_now:
            # update the cve-bin-tool database on the first scan (if
            # configured). This requires an Internet connection.
            #p = subprocess.Popen(['cve-bin-tool', '-q', '-u', 'now', '-f', 'json', '-o', temp_name, bang_file],
            p = subprocess.Popen(['cve-bin-tool', '-u', 'now', '-f', 'json', '-o', temp_name, bang_file],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            update_now = False
        else:
            #p = subprocess.Popen(['cve-bin-tool', '-q', '-u', 'never', '-f', 'json', '-o', temp_name, bang_file],
            p = subprocess.Popen(['cve-bin-tool', '-u', 'never', '-f', 'json', '-o', temp_name, bang_file],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (standard_out, standard_error) = p.communicate()

        # return code is the number of products with known CVEs
        # see cli.py in cve-bin-tool
        if p.returncode == 0:
            # no CVEs found, continue
            continue

        try:
            temp = open('%s.json' % temporary_file[1], 'rb')
        except FileNotFoundError:
            continue

        cve_json = json.loads(temp.read())
        temp.close()
        os.unlink(temp_name)
        results = json.dumps(cve_json, indent=4)
        print(results)


if __name__ == "__main__":
    main()
