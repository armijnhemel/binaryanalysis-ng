#!/usr/bin/env python3

# A simple script to test uploads to a queue from which
# BANG can pick up tasks

import json
import os
import pathlib
import sys
import urllib.parse

import requests
import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


@click.command(short_help='Upload files to a queue')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--file', '-f', 'upload_file', required=True, help='firmware file to scan', type=click.Path(exists=True))
def main(config_file, upload_file):

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # sanity checks for the configuration
    if not 'config' in config:
        print("invalid configuration file", file=sys.stderr)
        sys.exit(1)

    if not 'url' in config['config']:
        print("mandatory configuration for 'url' not found", file=sys.stderr)
        sys.exit(1)

    put_url = config['config']['url']

    # check if the URL is actually valid
    try:
        parsed_url = urllib.parse.urlparse(put_url)
    except Exception as e:
        print("invalid URL", file=sys.stderr)
        sys.exit(1)

    # check if the scheme is valid
    if parsed_url.scheme not in ['http', 'https']:
        print("invalid URL scheme", file=sys.stderr)
        sys.exit(1)

    try:
        upload_data = open(upload_file, 'rb')
    except:
        print("Could not open file", file=sys.stderr)
        sys.exit(1)

    files = {pathlib.Path(upload_file).name: upload_data}

    try:
        req = requests.post(put_url, files=files)
    except requests.exceptions.ConnectionError as e:
        print("Could not connect to service", file=sys.stderr)
        sys.exit(1)

    print(req.__dict__)


if __name__ == "__main__":
    main()
