#!/usr/bin/env python3

# A simple script to test uploads to a queue from which
# BANG can pick up tasks

import json
import os
import sys

import requests
import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


put_url = 'http://127.0.0.1:5000/upload/'

test_data = open('/bin/ls', 'rb')
test_data2 = open('/bin/vim', 'rb')

files = {'ls': test_data, 'vim': test_data2}

#requests.put(put_url, {'filename': 'ls', 'data': test_data})
req = requests.post(put_url, files=files)
print(req.__dict__)

@click.command(short_help='Upload files to a queue')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--source-directory', '-s', required=True, help='source code archive directory', type=click.Path(exists=True))
def main(config_file, source_directory, identifiers):

    source_directory = pathlib.Path(source_directory)

    # should be a real directory
    if not source_directory.is_dir():
        print("%s is not a directory, exiting." % source_directory, file=sys.stderr)
        sys.exit(1)

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)



if __name__ == "__main__":
    main()
