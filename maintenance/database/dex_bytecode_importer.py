#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes data from Dex files processed by BANG
and puts the relevant data in a PostgreSQL database.
'''

import sys
import os
import argparse
import stat
import pathlib
import pickle

# import some modules for dependencies, requires psycopg2 2.7+
import psycopg2
import psycopg2.extras

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

    # the configuration file should exist ...
    if not os.path.exists(args.cfg):
        parser.error("File %s does not exist, exiting." % args.cfg)

    # ... and should be a real file
    if not stat.S_ISREG(os.stat(args.cfg).st_mode):
        parser.error("%s is not a regular file, exiting." % args.cfg)

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
        configfile = open(args.cfg, 'r')
        config = load(configfile, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    if 'database' not in config or 'general' not in config:
        print("Invalid configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    for i in ['postgresql_user', 'postgresql_password', 'postgresql_db']:
        if i not in config['database']:
            print("Configuration file malformed: missing database information %s" % i,
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
    except psycopg2.Error:
        print("Database server not running or malconfigured, exiting.",
              file=sys.stderr)
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
    for bang_directory in result_directory.iterdir():
        bang_pickle = bang_directory / 'bang.pickle'
        if not bang_pickle.exists():
            continue

        # open the top level pickle
        bang_data = pickle.load(open(bang_pickle, 'rb'))
        db_rows = []
        for bang_file in bang_data['scantree']:
            if 'dex' in bang_data['scantree'][bang_file]['labels']:
                sha256 = bang_data['scantree'][bang_file]['hash']['sha256']

                # open the result pickle
                results_data = pickle.load(open(bang_directory / 'results' / ("%s.pickle" % sha256), 'rb'))
                for r in results_data['metadata']['classes']:
                    class_name = r['classname']
                    for m in r['methods']:
                        method_name = m['name']
                        if 'bytecode_hashes' in m:
                             bytecode_sha256 = m['bytecode_hashes']['sha256']
                             bytecode_tlsh = ''
                             if m['bytecode_hashes']['tlsh'] is not None:
                                 bytecode_tlsh = m['bytecode_hashes']['tlsh']
                             db_rows.append((sha256, class_name, method_name, bytecode_sha256, bytecode_tlsh))
                dex_counter += 1
        # insert contents of all the files in the APK
        psycopg2.extras.execute_batch(dbcursor, "execute bytecode_insert(%s, %s, %s, %s, %s)", db_rows)
        method_counter += len(db_rows)
        dbconnection.commit()
        if verbose:
            print("Processed %d dex files" % dex_counter)
            print("Added %d methods" % len(db_rows))
            print("Total %d methods" % method_counter)
            print()


    if verbose:
        print()
        if dex_counter == 1:
            print("Processed: 1 dex file")
        else:
            print("Processed %d dex files" % dex_counter)
        print("Processed %d methods" % method_counter)

    # cleanup
    dbconnection.commit()

    # close the database connection
    dbcursor.close()
    dbconnection.close()

if __name__ == "__main__":
    main()
