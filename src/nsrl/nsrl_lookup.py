#!/usr/bin/env python3

# Process a result from BANG and look up file hashes in NSRL
#
# Licensed under the terms of the Affero General Public License version 3
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions

import collections
import os
import sys
import pickle
import pathlib

import psycopg2

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import click

@click.command(short_help='query NSRL with results from a BANG result directory')
@click.option('--config', '-c', required=True, help='path to configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='path to BANG result directories', type=click.Path(exists=True))
def main(config, result_directory):
    result_directory = pathlib.Path(result_directory)

    # ... and should be a real directory
    if not result_directory.is_dir():
        print("%s is not a directory, exiting." % result_directory, file=sys.stderr)
        sys.exit(1)

    # read the configuration file. This is in YAML format
    try:
        configuration = load(config, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    if 'database' not in configuration or 'general' not in configuration:
        print("Invalid configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    for i in ['postgresql_user', 'postgresql_password', 'postgresql_db']:
        if i not in configuration['database']:
            print("Configuration file malformed: missing database information %s" % i,
                  file=sys.stderr)
            sys.exit(1)
        postgresql_user = configuration['database']['postgresql_user']
        postgresql_password = configuration['database']['postgresql_password']
        postgresql_db = configuration['database']['postgresql_db']

    # default values
    postgresql_host = None
    postgresql_port = None

    if 'postgresql_host' in configuration['database']:
        postgresql_host = configuration['database']['postgresql_host']
    if 'postgresql_port' in configuration['database']:
        postgresql_port = configuration['database']['postgresql_port']

    # test the database connection
    try:
        cursor = psycopg2.connect(database=postgresql_db, user=postgresql_user,
                                  password=postgresql_password,
                                  port=postgresql_port, host=postgresql_host)
        cursor.close()
    except psycopg2.Error:
        print("Database server not running or malconfigured, exiting.",
              file=sys.stderr)
        sys.exit(1)

    # open the top level pickle
    bang_pickle = result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    try:
        bang_data = pickle.load(open(bang_pickle, 'rb'))
    except:
        print("Cannot unpickle BANG data", file=sys.stderr)
        sys.exit(1)

    # create a connection to the database
    conn = psycopg2.connect(database=postgresql_db, user=postgresql_user,
                            password=postgresql_password,
                            port=postgresql_port, host=postgresql_host)

    cursor = conn.cursor()

    # walk the BANG results
    file_deque = collections.deque()
    file_deque.append(bang_pickle)

    manufacturer_cache = {}

    # walk the unpack tree recursively and grab all the file pickles
    while True:
        try:
            file_pickle = file_deque.popleft()
        except:
            break

        try:
            bang_data = pickle.load(open(file_pickle, 'rb'))
        except:
            continue

        # only look at "real" files
        if bang_data['metadata'] != {}:
            if 'hashes' in bang_data['metadata']:
                # TODO: filter empty files
                sha1 = bang_data['metadata']['hashes']['sha1']

                # get more results
                cursor.execute("SELECT p.name, p.version, p.application_type, p.manufacturer_code FROM nsrl_product p, nsrl_entry e WHERE p.code = e.product_code AND e.sha1=%s;", (sha1,))
                productres = cursor.fetchall()
                conn.commit()
                for p in productres:
                    # first create a result object
                    dbres = {}
                    (productname, productversion, applicationtype, manufacturercode) = p
                    if manufacturercode in manufacturer_cache:
                        manufacturer = manufacturer_cache[manufacturercode]
                    else:
                        cursor.execute("SELECT name FROM nsrl_manufacturer WHERE code=%s", (manufacturercode,))
                        manufacturerres = cursor.fetchone()
                        if manufacturerres is None:
                            # this shouldn't happen
                            conn.commit()
                            return results
                        manufacturer = manufacturerres[0]
                        manufacturer_cache[manufacturercode] = manufacturer
                        conn.commit()
                    dbres['productname'] = productname
                    dbres['productversion'] = productversion
                    dbres['applicationtype'] = applicationtype
                    dbres['manufacturer'] = manufacturer

                    # print the result
                    print(bang_result, dbres)

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


if __name__ == "__main__":
    main()
