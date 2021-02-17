#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes files with password/plaintext combinations,
with lines formatted as:

hash plaintext

The test file is phpbb-withmd5.txt which can be downloaded from:

https://wiki.skullsecurity.org/Passwords
'''

import sys
import os
import argparse
import stat

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
                        help="path to configuration file", metavar="FILE")
    parser.add_argument("-f", "--file", action="store", dest="passwdfile",
                        help="path to file with passwords", metavar="FILE")
    args = parser.parse_args()

    # sanity checks for the file with passwords
    if args.passwdfile is None:
        parser.error("No file with passwords provided, exiting")

    # the file with passwords should exist ...
    if not os.path.exists(args.passwdfile):
        parser.error("File %s does not exist, exiting." % args.passwdfile)

    # ... and should be a real file
    if not stat.S_ISREG(os.stat(args.passwdfile).st_mode):
        parser.error("%s is not a regular file, exiting." % args.passwdfile)

    # sanity checks for the configuration file
    if args.cfg is None:
        parser.error("No configuration file provided, exiting")

    # the configuration file should exist ...
    if not os.path.exists(args.cfg):
        parser.error("File %s does not exist, exiting." % args.cfg)

    # ... and should be a real file
    if not stat.S_ISREG(os.stat(args.cfg).st_mode):
        parser.error("%s is not a regular file, exiting." % args.cfg)

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

    verbose = False
    if 'verbose' in config['general']:
        if isinstance(config['general']['verbose'], bool):
            verbose = config['general']['verbose']

    # open the file with passwords.
    # for the phpbb-withmd5.txt file this is latin-1
    encoding = 'latin-1'
    try:
        passwdfile = open(args.passwdfile, 'r', encoding=encoding)
    except:
        print("Cannot open file with passwords",
              file=sys.stderr)
        sys.exit(1)

    # open a connection to the database
    dbconnection = psycopg2.connect(database=postgresql_db,
                                    user=postgresql_user,
                                    password=postgresql_password,
                                    port=postgresql_port,
                                    host=postgresql_host)
    dbcursor = dbconnection.cursor()

    for line in passwdfile:
        (hashed, plaintext) = line.strip().split(maxsplit=1)
        dbcursor.execute("INSERT INTO password (hashed, plaintext) VALUES (%s, %s)", (hashed, plaintext))

    # cleanup
    dbconnection.commit()

    # close the database connection
    dbcursor.close()
    dbconnection.close()

if __name__ == "__main__":
    main()
