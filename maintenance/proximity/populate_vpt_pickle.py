#/usr/bin/env python3
#
# Copyright 2022 - Armijn Hemel
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import json
import pathlib
import sys

import click
import tlsh

import proximity_matcher_webservice.vpt as vpt

@click.command(short_help='process TLSH hashes and turn into a pickle')
@click.option('--json-directory', '-j', required=True, help='JSON file directory', type=click.Path(exists=True))
@click.option('--outfile', '-o', required=True, help='output file for VPT pickle', type=click.File('wb'))
@click.option('--no-optimize', 'optimize', help='disable optimizing pickle', default=True, flag_value=False, is_flag=True)
@click.option('--filter', '-f', 'tlsh_filter', required=True, help='TLSH value to use')
def main(json_directory, outfile, optimize, tlsh_filter):
    json_directory = pathlib.Path(json_directory)

    # should be a real directory
    if not json_directory.is_dir():
        print("%s is not a directory, exiting." % json_directory, file=sys.stderr)
        sys.exit(1)

    tlsh_objects = []
    for result_file in json_directory.glob('**/*'):
        try:
            with open(result_file, 'r') as json_archive:
                json_results = json.load(json_archive)

            # first a sanity check to see if the SHA256 is the same as
            # the stem of the file name
            if result_file.stem != json_results['sha256']:
                continue

            # check if the TLSH filter exists
            if tlsh_filter not in json_results:
                continue

            # check if the filtered TLSH value isn't empty
            if json_results[tlsh_filter] == '':
                continue

            # check if the filtered TLSH value is a valid TLSH value
            # and create a TLSH object
            try:
                t = tlsh.Tlsh()
                t.fromTlshStr(json_results[tlsh_filter])
            except ValueError:
                continue

            tlsh_objects.append(t)

        except Exception as e:
            continue

    if tlsh_objects != []:
        root = vpt.vpt_grow(tlsh_objects)

        vpt.pickle_tree(root, outfile, optimize)

if __name__ == "__main__":
    main()
