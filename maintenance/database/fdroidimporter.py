#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# This script processes data from the F-Droid project
# and puts the relevant data in a database.
#
# Copyright 2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

import sys
import os
import argparse
import stat
import pathlib
import zipfile
import datetime
import tempfile
import shutil
import hashlib

# import XML processing that guards against several XML attacks
import defusedxml.minidom

# import some modules for dependencies, requires psycopg2 2.7+
import psycopg2
import psycopg2.extras

# import YAML module for the configuration
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", action="store", dest="cfg",
                        help="path to F-Droid configuration file", metavar="FILE")
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

    # read the configuration file. This is in YAML format
    try:
        configfile = open(args.cfg, 'r')
        config = load(configfile, Loader=Loader)
    except:
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
        c = psycopg2.connect(database=postgresql_db, user=postgresql_user,
                             password=postgresql_password,
                             port=postgresql_port, host=postgresql_host)
        c.close()
    except Exception:
        print("Database server not running or malconfigured, exiting.",
              file=sys.stderr)
        sys.exit(1)

    if 'storedirectory' not in config['general']:
        print("F-Droid store directory not defined, exiting", file=sys.stderr)
        sys.exit(1)

    store_directory = pathlib.Path(config['general']['storedirectory'])

    # Check if the base unpack directory exists
    if not store_directory.exists():
        print("Store directory %s does not exist, exiting" % store_directory,
              file=sys.stderr)
        sys.exit(1)

    if not store_directory.is_dir():
        print("Store directory %s is not a directory, exiting" % store_directory,
              file=sys.stderr)
        sys.exit(1)

    # directory for unpacking. By default this will be /tmp or whatever
    # the system default is.
    temporary_directory = None

    if 'tempdir' in config['general']:
        temporary_directory = pathlib.Path(config['general']['tempdir'])
        if temporary_directory.exists():
            if temporary_directory.is_dir():
                # check if the temporary directory is writable
                try:
                    temp_name = tempfile.NamedTemporaryFile(dir=temporary_directory)
                    temp_name.close()
                except Exception:
                    temporary_directory = None
            else:
                temporary_directory = None
        else:
            temporary_directory = None

    # get the latest XML file that was downloaded and process it
    # format is index.xml-%Y%m%d-%H%M%S
    xml_files = store_directory.glob('xml/index.xml-*')

    latest_xml = ''

    for i in xml_files:
        if latest_xml == '':
            latest_xml = i
            latest_timestamp = datetime.datetime.strptime(i.name, "index.xml-%Y%m%d-%H%M%S")
        else:
            timestamp = datetime.datetime.strptime(i.name, "index.xml-%Y%m%d-%H%M%S")
            if timestamp > latest_timestamp:
                latest_xml = i
                latest_timestamp = timestamp

    if latest_xml == '':
        print("No valid F-Droid XML file found', exiting", file=sys.stderr)
        sys.exit(1)

    # now open the XML file to see if it is valid XML data, else exit
    try:
        fdroidxml = defusedxml.minidom.parse(latest_xml.open())
    except:
        print("Could not parse F-Droid XML %s, exiting." % latest_xml, file=sys.stderr)
        sys.exit(1)

    # open a connection to the database
    dbconnection = psycopg2.connect(database=postgresql_db,
                                    user=postgresql_user,
                                    password=postgresql_password,
                                    port=postgresql_port,
                                    host=postgresql_host)
    dbcursor = dbconnection.cursor()

    # filter for irrelevant files that should not be stored in the
    # database as entries just eat space such as the various support
    # libraries, F-Droid support files, etc.
    meta_files_filter = ['META-INF/androidx.*.version',
                    'META-INF/com.android.support_*',
                    'META-INF/com.google.android.material_material.version',
                    'META-INF/android.arch.*', 'META-INF/android.support.*',
                    'META-INF/buildserverid', 'META-INF/fdroidserverid',
                    'META-INF/kotlinx-*.kotlin_module']

    # filter for irrelevant directories that should not be stored in the
    # database as entries just eat space such as the various support
    # libraries, time zone files, F-Droid support files, etc.
    dir_filter = ['zoneinfo/', 'zoneinfo-global/',
                  'org/joda/time/', 'kotlin/', 'kotlinx/']

    # Process the XML. Each application can have several
    # packages (versions) associated with it. The application
    # information is identical for every package.
    for i in fdroidxml.getElementsByTagName('application'):
        application_id = ''
        application_license = ''
        source_url = ''
        for childnode in i.childNodes:
            if childnode.nodeName == 'id':
                package_id = childnode.childNodes[0].data
            elif childnode.nodeName == 'source':
                if childnode.childNodes != []:
                    source_url = childnode.childNodes[0].data
            elif childnode.nodeName == 'license':
                package_license = childnode.childNodes[0].data
            elif childnode.nodeName == 'package':
                # store files and hashes
                apk_hashes = []
                for packagenode in childnode.childNodes:
                    if packagenode.nodeName == 'srcname':
                        pass
                    elif packagenode.nodeName == 'hash':
                        apkhash = packagenode.childNodes[0].data
                    elif packagenode.nodeName == 'apkname':
                        apkname = packagenode.childNodes[0].data
                        apkfile = store_directory / 'binary' / apkname
                        # verify if the APK actually has been downloaded
                        if not apkfile.exists():
                            continue
                        # verify if the APK is a valid zip file
                        if not zipfile.is_zipfile(apkfile):
                            continue

                        apk_zip = zipfile.ZipFile(apkfile)
                        # scan the contents of the APK
                        # 1. create a temporary directory
                        tempdir = tempfile.mkdtemp(dir=temporary_directory)

                        # 2. unpack the APK
                        try:
                            apk_zip.extractall(path=tempdir)
                        except zipfile.BadZipFile:
                            shutil.rmtree(tempdir)
                            continue

                        # 3. hash the contents of each file
                        old_dir = os.getcwd()
                        os.chdir(tempdir)

                        # unfortunately pathlib does not yet have a recursive iterdir()
                        for apk_entries in os.walk('.'):
                            for dir_entry in apk_entries[2]:
                                apk_entry_name = pathlib.PurePosixPath(apk_entries[0], dir_entry)
                                apk_entry = pathlib.Path(apk_entry_name)
                                if not apk_entry.is_file() or apk_entry.is_symlink():
                                    # skip non-files
                                    continue
                                if apk_entry.stat().st_size == 0:
                                    # skip empty files
                                    continue

                                # filter irrelevant directories
                                filter_matched = False
                                for ff in dir_filter:
                                    if apk_entry.is_relative_to(ff):
                                        filter_matched = True
                                        break
                                if filter_matched:
                                    continue
                                # filter irrelevant files
                                if apk_entry.is_relative_to('META-INF'):
                                    for ff in meta_files_filter:
                                        if apk_entry.match(ff):
                                            filter_matched = True
                                            break
                                    if filter_matched:
                                        continue
                                apk_entry_hash = hashlib.new('sha256')
                                apk_entry_hash.update(apk_entry.read_bytes())
                                apk_hashes.append((apk_entry, apk_entry_hash.hexdigest()))
                        os.chdir(old_dir)

                        # 4. clean up
                        shutil.rmtree(tempdir)

    # cleanup
    dbconnection.commit()

    # close the database connection
    dbcursor.close()
    dbconnection.close()

if __name__ == "__main__":
    main()
