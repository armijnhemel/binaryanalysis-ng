#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes files with password/plaintext combinations,
with lines formatted as:

hash plaintext

The test file is phpbb-withmd5.txt which can be downloaded from:

https://wiki.skullsecurity.org/Passwords
'''

import os
import string
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


@click.command(short_help='load passwords and hashes into database')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--file', '-f', 'password_file', required=True, help='file with passwords and hashes', type=click.Path(exists=True))
def main(config_file, password_file):

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
        passwdfile = open(password_file, 'r', encoding=encoding)
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

    passwds = []

    for line in passwdfile:
        try:
            splits = line.strip().split(maxsplit=1)
            if len(splits) == 2:
                (hashed, plaintext) = splits
                # extra sanity check for the hash
                if hashed.isprintable():
                    if '\x00' in plaintext:
                        continue
                    passwds.append((hashed, plaintext))
        except:
            continue

    for (hashed, plaintext) in passwds:
        dbcursor.execute("INSERT INTO password (hashed, plaintext) VALUES (%s, %s) ON CONFLICT DO NOTHING", (hashed, plaintext))

    # cleanup
    dbconnection.commit()

    # close the database connection
    dbcursor.close()
    dbconnection.close()

if __name__ == "__main__":
    main()
