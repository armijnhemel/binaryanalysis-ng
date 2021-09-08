#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes data from ELF files processed by BANG
and runs cve-bin-tool on them.
'''

import sys
import shutil
import os
import argparse
import pathlib
import pickle
import json
import subprocess

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", action="store", dest="cfg",
                        help="path to F-Droid configuration file", metavar="FILE")
    parser.add_argument("-r", "--result-directory", action="store", dest="result_directory",
                        help="path to BANG result directories", metavar="DIR")
    args = parser.parse_args()

    # sanity checks for the configuration file
    if args.cfg is None:
        parser.error("No configuration file provided, exiting")

    cfg = pathlib.Path(args.cfg)

    # the configuration file should exist ...
    if not cfg.exists:
        parser.error("File %s does not exist, exiting." % cfg)

    # ... and should be a real file
    if not cfg.is_file():
        parser.error("%s is not a regular file, exiting." % cfg)

    # sanity checks for the result directory
    if args.result_directory is None:
        parser.error("No result directory provided, exiting")

    result_directory = pathlib.Path(args.result_directory)

    # the result directory should exist ...
    if not result_directory.exists():
        parser.error("File %s does not exist, exiting." % args.result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        parser.error("%s is not a directory, exiting." % args.result_directory)

    # read the configuration file. This is in YAML format
    try:
        configfile = open(cfg, 'r')
        config = load(configfile, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    verbose = False
    if 'verbose' in config['general']:
        if isinstance(config['general']['verbose'], bool):
            verbose = config['general']['verbose']

    # run cve-bin-tool
    if shutil.which('cve-bin-tool') is None:
        print("cve-bin-tool not found in path, exiting", file=sys.stderr)
        sys.exit(1)

    # open the top level pickle
    bang_pickle = result_directory / 'bang.pickle'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    bang_data = pickle.load(open(bang_pickle, 'rb'))

    update_now = False

    # change working directory
    old_cwd = os.getcwd()
    os.chdir(result_directory / 'unpack')
    for bang_file in bang_data['scantree']:
        if 'elf' in bang_data['scantree'][bang_file]['labels']:
            if not 'busybox' in bang_file:
                continue
            if update_now:
                # update the cve-bin-tool database on the first scan (if
                # configured). This requires an Internet connection.
                p = subprocess.Popen(['cve-bin-tool', '-q', '-u', 'now', '-f', 'json', bang_file],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                update_now = False
            else:
                p = subprocess.Popen(['cve-bin-tool', '-q', '-u', 'never', '-f', 'json', bang_file],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (standard_out, standard_error) = p.communicate()
            if p.returncode == 0:
                # no CVEs found, continue
                continue
            elif p.returncode != 1:
                # some other error
                continue
            print(bang_file, standard_error)

    os.chdir(old_cwd)

if __name__ == "__main__":
    main()
