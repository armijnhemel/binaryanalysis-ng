#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only

'''
This script processes data from Dex files processed by BANG
and puts the relevant data in a PostgreSQL database.
'''

import collections
import pathlib
import pickle
import sys

# import some modules for dependencies, requires psycopg2 2.7+
import psycopg2
import psycopg2.extras

import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


@click.command(short_help='load Dex bytecode information into database')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', required=True, help='BANG result directory', type=click.Path(exists=True, path_type=pathlib.Path))
def main(config_file, result_directory):
    # should be a real directory
    if not result_directory.is_dir():
        print(f"{result_directory} is not a directory, exiting.", file=sys.stderr)
        sys.exit(1)

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    if 'database' not in config or 'general' not in config:
        print("Invalid configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    for i in ['postgresql_user', 'postgresql_password', 'postgresql_db']:
        if i not in config['database']:
            print("Configuration file malformed: missing database information {i}",
                  file=sys.stderr)
            sys.exit(1)
        postgresql_user = config['database']['postgresql_user']
        postgresql_password = config['database']['postgresql_password']
        postgresql_db = config['database']['postgresql_db']

    # default values
    postgresql_host = None
    postgresql_port = None

    if 'postgresql_host' in config['database']:
        postgresql_host = config['database']['postgresql_host']
    if 'postgresql_port' in config['database']:
        postgresql_port = config['database']['postgresql_port']

    # test the database connection
    try:
        cursor = psycopg2.connect(database=postgresql_db, user=postgresql_user,
                                  password=postgresql_password,
                                  port=postgresql_port, host=postgresql_host)
        cursor.close()
    except psycopg2.Error as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    # open a connection to the database
    dbconnection = psycopg2.connect(database=postgresql_db,
                                    user=postgresql_user,
                                    password=postgresql_password,
                                    port=postgresql_port,
                                    host=postgresql_host)
    dbcursor = dbconnection.cursor()

    verbose = False
    if 'verbose' in config['general']:
        if isinstance(config['general']['verbose'], bool):
            verbose = config['general']['verbose']

    # create a prepared statement
    prepared_bytecode = "PREPARE bytecode_insert as INSERT INTO dex_bytecode (dex_sha256, class_name, method_name, bytecode_sha256, bytecode_tlsh) values ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING"
    dbcursor.execute(prepared_bytecode)

    dex_counter = 0
    method_counter = 0

    # walk the results directory
    bang_pickle = result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("Not a valid BANG meta directory")
        sys.exit(1)

    # store the paths of pickes of Dex files for processing
    dex_files = []
    file_deque = collections.deque()

    file_deque.append(bang_pickle)

    # walk the unpack tree recursively and grab all the APK files
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
            if 'dex' in bang_data['labels']:
                dex_files.append(file_pickle)

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

    for file_pickle in dex_files:
        db_rows = []
        with open(file_pickle, 'rb') as dex_pickle:
            bang_data = pickle.load(dex_pickle)

        sha256 = bang_data['metadata']['hashes']['sha256']

        # open the result pickle
        for result in bang_data['metadata']['classes']:
            class_name = result['classname']
            for method in result['methods']:
                method_name = method['name']
                if 'bytecode_hashes' in method:
                    bytecode_sha256 = method['bytecode_hashes']['sha256']
                    bytecode_tlsh = ''
                    if method['bytecode_hashes']['tlsh'] is not None:
                        bytecode_tlsh = method['bytecode_hashes']['tlsh']
                    db_rows.append((sha256, class_name, method_name, bytecode_sha256, bytecode_tlsh))
        dex_counter += 1

        # insert contents of all the files in the APK
        psycopg2.extras.execute_batch(dbcursor, "execute bytecode_insert(%s, %s, %s, %s, %s)", db_rows)
        method_counter += len(db_rows)
        dbconnection.commit()
        if verbose:
            print(f"Processed {dex_counter} dex files")
            print(f"Added {len(db_rows)} methods")
            print(f"Total {method_counter} methods")
            print()

    if verbose:
        print()
        if dex_counter == 1:
            print("Processed: 1 dex file")
        else:
            print(f"Processed {dex_counter} dex files")
        print(f"Processed {method_counter} methods")

    # cleanup
    dbconnection.commit()

    # close the database connection
    dbcursor.close()
    dbconnection.close()

if __name__ == "__main__":
    main()
