#!/usr/bin/env python3

# Process a result from BANG and look up file hashes in NSRL
#
# Licensed under the terms of the Affero General Public License version 3
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Copyright 2018-2021 - Armijn Hemel, Tjaldur Software Governance Solutions

import argparse
import configparser
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


def main(argv):
    parser = argparse.ArgumentParser()

    # the following options are provided on the commandline
    parser.add_argument("-c", "--config", action="store", dest="cfg",
                        help="path to configuration file", metavar="FILE")
    parser.add_argument("-d", "--directory", action="store",
                        dest="bang_result_directory",
                        help="path to BANG result directory", metavar="DIR")
    parser.add_argument("-o", "--outputformat", action="store",
                        dest="outputformat",
                        help="output format", metavar="FORMAT")
    args = parser.parse_args()

    # first some sanity checks for the directory that needs to be scanned
    if args.bang_result_directory is None:
        parser.error("Directory argument missing")

    bang_result_directory = pathlib.Path(args.bang_result_directory)

    if not bang_result_directory.exists():
        parser.error("Directory %s does not exist" % bang_result_directory)

    if not bang_result_directory.is_dir():
        parser.error("%s is not a directory" % bang_result_directory)

    # then some checks for the configuration file
    if args.cfg is None:
        parser.error("Configuration file missing")

    cfg = pathlib.Path(args.cfg)

    if not cfg.exists():
        parser.error("Configuration file does not exist")

    if not cfg.is_file():
        parser.error("%s is not a file" % cfg)

    # read the configuration file. This is in YAML format
    try:
        configfile = open(cfg, 'r')
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

    # read the BANG pickle
    try:
        bang_results = pickle.load(open(bang_result_directory / 'bang.pickle', 'rb'))
    except:
        print("Could not read BANG results pickle",
              file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(database=postgresql_db, user=postgresql_user,
                            password=postgresql_password,
                            port=postgresql_port, host=postgresql_host)

    cursor = conn.cursor()

    # process each entry in the BANG result and store the parent per name.
    for bang_result in bang_results['scantree']:
        # ignore empty files as these appear often in NSRL
        if 'empty' in bang_results['scantree'][bang_result]['labels']:
            continue

        # ignore padding
        if 'padding' in bang_results['scantree'][bang_result]['labels']:
            continue

        # retrieve the hash so we can open the result file
        if 'sha1' not in bang_results['scantree'][bang_result]['hash']:
            continue
        sha1 = bang_results['scantree'][bang_result]['hash']['sha1']

        manufacturercache = {}

        # get more results
        cursor.execute("SELECT p.name, p.version, p.application_type, p.manufacturer_code FROM nsrl_product p, nsrl_entry e WHERE p.code = e.product_code AND e.sha1=%s;", (sha1,))
        productres = cursor.fetchall()
        conn.commit()
        for p in productres:
            # first create a result object
            dbres = {}
            (productname, productversion, applicationtype, manufacturercode) = p
            if manufacturercode in manufacturercache:
                manufacturer = manufacturercache[manufacturercode]
            else:
                cursor.execute("SELECT name FROM nsrl_manufacturer WHERE code=%s", (manufacturercode,))
                manufacturerres = cursor.fetchone()
                if manufacturerres is None:
                    # this shouldn't happen
                    conn.commit()
                    return results
                manufacturer = manufacturerres[0]
                manufacturercache[manufacturercode] = manufacturer
                conn.commit()
            dbres['productname'] = productname
            dbres['productversion'] = productversion
            dbres['applicationtype'] = applicationtype
            dbres['manufacturer'] = manufacturer

            # print the result
            print(bang_result, dbres)


if __name__ == "__main__":
    main(sys.argv)
