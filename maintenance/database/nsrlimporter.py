#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# This script processes the National Software Reference Library (NSRL) CSV
# files and puts the relevant data in a database.
#
# NSRL is a forensics database released by NIST.
#
# https://www.nist.gov/software-quality-group/national-software-reference-library-nsrl
#
# Copyright 2018-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

import csv
import os
import pathlib
import sys

# import some modules for dependencies, requires psycopg2 2.7+
import psycopg2
import psycopg2.extras

import click

# import YAML module for the configuration
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

# Add lots of encodings that the NSRL data can possibly be in. Use
# these for decoding and translate into UTF-8. This is not guaranteed
# to work, but it is better than nothing.
encodings_translate = ['utf-8', 'latin-1', 'euc_jp', 'euc_jis_2004',
                       'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                       'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                       'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                       'shift_jis_2004', 'shift_jisx0213']


@click.command(short_help='process NSRL files and store results in a database')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--directory', '-d', 'nsrldir', required=True, help='NSRL files directory', type=click.Path(exists=True))
@click.option('--no-decode', '-t', 'decode', help='disable decoding files', default=True, flag_value=False, is_flag=True)
def main(config_file, nsrldir, decode):
    # sanity checks for the directory
    nsrldir = pathlib.Path(nsrldir)

    # ... and should be a real directory
    if not nsrldir.is_dir():
        print("%s is not a regular file, exiting." % nsrldir, file=sys.stderr)
        sys.exit(1)

    nsrlfiles = os.listdir(nsrldir)

    for i in ['NSRLFile.txt', 'NSRLMfg.txt', 'NSRLOS.txt', 'NSRLProd.txt']:
        if i not in nsrlfiles:
            print("Mandatory file %s not found in %s, exiting" % (i, nsrldir), file=sys.stderr)
            sys.exit(1)

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except:
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    if 'database' not in config:
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
    except Exception as e:
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

    # NSRL mixes different encodings in the CSV files, so gruesome hacks
    # are needed to work around that, namely:
    # 1. open the file in binary mode
    # 2. split the data
    # 3. decode all the data to UTF-8
    # 4. write the decode data

    if decode:
        for i in ['NSRLFile.txt', 'NSRLMfg.txt', 'NSRLOS.txt', 'NSRLProd.txt']:
            checkfile = open(os.path.join(nsrldir, i), 'rb')
            decodedfilename = os.path.join(nsrldir, '%s-translated' % i)
            decodedfile = open(decodedfilename, 'w')

            # read chunks of 10 million bytes
            readsize = 10000000
            offset = 0
            while True:
                checkfile.seek(offset)
                checkbytes = checkfile.read(readsize)
                buffs = checkbytes.rsplit(b'\r\n')
                lastoffset = checkbytes.rfind(b'\r\n')
                if checkbytes == b'':
                    break
                if len(checkbytes) < readsize:
                    for buff in buffs:
                        if buff == b'':
                            continue
                        for encoding in encodings_translate:
                            try:
                                decodedfile.write(buff.decode(encoding))
                                decodedfile.write('\n')
                                break
                            except Exception as e:
                                pass
                    break
                for buff in buffs[:-1]:
                    if buff == b'':
                        continue
                    for encoding in encodings_translate:
                        try:
                            decodedfile.write(buff.decode(encoding))
                            decodedfile.write('\n')
                            break
                        except:
                            pass
                offset += lastoffset
            decodedfile.close()
        nsrlmfg = 'NSRLMfg.txt-translated'
        nsrlos = 'NSRLOS.txt-translated'
        nsrlprod = 'NSRLProd.txt-translated'
        nsrlfile = 'NSRLFile.txt-translated'
    else:
        nsrlmfg = 'NSRLMfg.txt'
        nsrlos = 'NSRLOS.txt'
        nsrlprod = 'NSRLProd.txt'
        nsrlfile = 'NSRLFile.txt'

    # then process all the (translated files), start with NSRLMfg
    decodedfilename = os.path.join(nsrldir, nsrlmfg)
    nsrfile = open(decodedfilename, 'r')

    # skip the first line
    nsrfile.readline()

    # then process the rest of the lines as CSV entries and split the data
    # across the various tables
    csvreader = csv.reader(nsrfile)

    # create a few prepared statements
    preparedmfg = "PREPARE mfg_insert as INSERT INTO nsrl_manufacturer (code, name) values ($1, $2) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedmfg)

    counter = 1
    bulkinserts = []
    for i in csvreader:
        (manufacturercode, manufacturername) = i
        try:
            manufacturercode = int(manufacturercode)
        except ValueError:
            continue
        bulkinserts.append((manufacturercode, manufacturername))
        if counter % 10000 == 0:
            print("Entries for manufacturer processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            # now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute mfg_insert(%s, %s)", bulkinserts)
            dbconnection.commit()

            # clear the lists
            bulkinserts = []
            bulkhash = []
        counter += 1

    # now insert the remaining files in bulk
    if bulkinserts != []:
        psycopg2.extras.execute_batch(dbcursor, "execute mfg_insert(%s, %s)", bulkinserts)
    print("Entries for manufacturer processed:", counter)
    dbconnection.commit()
    nsrfile.close()

    # then NSRLOS.txt
    decodedfilename = os.path.join(nsrldir, nsrlos)
    nsrfile = open(decodedfilename, 'r')

    # skip the first line
    nsrfile.readline()

    # then process the rest of the lines as CSV entries and split the data
    # across the various tables
    csvreader = csv.reader(nsrfile)

    # create a few prepared statements
    preparedos = "PREPARE os_insert as INSERT INTO nsrl_os (code, name, version, manufacturer_code) values ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedos)

    counter = 1
    bulkinserts = []
    for i in csvreader:
        (oscode, osname, osversion, manufacturercode) = i
        osname = osname.strip()
        try:
            oscode = int(oscode)
            manufacturercode = int(manufacturercode)
        except ValueError:
            continue
        bulkinserts.append((oscode, osname, osversion, manufacturercode))
        if counter % 10000 == 0:
            print("Entries for OS processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            # now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute os_insert(%s, %s, %s, %s)",
                                          bulkinserts)
            dbconnection.commit()

            # clear the lists
            bulkinserts = []
        counter += 1

    # now insert the remaining files in bulk
    if bulkinserts != []:
        psycopg2.extras.execute_batch(dbcursor, "execute os_insert(%s, %s, %s, %s)",
                                      bulkinserts)
    print("Entries for OS processed:", counter)
    dbconnection.commit()
    nsrfile.close()

    # then NSRLProd.txt
    decodedfilename = os.path.join(nsrldir, nsrlprod)
    nsrfile = open(decodedfilename, 'r')

    # skip the first line
    nsrfile.readline()

    # then process the rest of the lines as CSV entries and split the data
    # across the various tables
    csvreader = csv.reader(nsrfile)

    # create a few prepared statements
    preparedproduct = "PREPARE product_insert as INSERT INTO nsrl_product (code, name, version, manufacturer_code, application_type) values ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedproduct)

    # process the lines in the CSV, and then bulk insert them into the database
    counter = 1
    bulkinserts = []
    for i in csvreader:
        (productcode, productname, productversion, oscode, manufacturercode, language, applicationtype) = i
        try:
            productcode = int(productcode)
            manufacturercode = int(manufacturercode)
        except ValueError:
            continue
        bulkinserts.append((productcode, productname, productversion, manufacturercode, applicationtype))
        if counter % 10000 == 0:
            print("Entries for products processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            # now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute product_insert(%s, %s, %s, %s, %s)",
                                          bulkinserts)
            dbconnection.commit()

            # clear the lists
            bulkinserts = []
        counter += 1

    # now insert the remaining files in bulk
    if bulkinserts != []:
        psycopg2.extras.execute_batch(dbcursor, "execute product_insert(%s, %s, %s, %s, %s)",
                                      bulkinserts)
    print("Entries for products processed:", counter)
    dbconnection.commit()
    nsrfile.close()

    # finally NSRLFile.txt
    decodedfilename = os.path.join(nsrldir, nsrlfile)
    nsrfile = open(decodedfilename, 'r')

    # skip the first line
    nsrfile.readline()

    # then process the rest of the lines as CSV entries and split the data
    # across the various tables
    csvreader = csv.reader(nsrfile)

    # create a few prepared statements
    preparedhash = "PREPARE hash_insert as INSERT INTO nsrl_hash (sha1, md5, crc32, filename) values ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedhash)

    preparedentry = "PREPARE entry_insert as INSERT INTO nsrl_entry (sha1, product_code) values ($1, $2) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedentry)

    # temporary data structures
    # keep track of which SHA1 values have been seen. NSRL files
    # are typically sorted by hash so this could possibly be replaced
    # by a simpler data structure.
    sha1seen = set()

    # "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
    # only store: sha1, md5, crc32, filename, product code
    # TODO: special code
    # These are in different tables in the NSRL dataset. The entries in NSRLFile.txt
    # contain a lot of duplication and can be stored more efficiently.
    counter = 1
    bulkinserts = set()
    bulkhash = []
    for i in csvreader:
        if i == []:
            continue
        (sha1, md5, crc32, filename, filesize, productcode, opsystemcode, specialcode) = i
        sha1 = sha1.lower()
        md5 = md5.lower()
        try:
           productcode = int(productcode)
        except ValueError:
           continue

        # Ignore hashes that have already been seen. This is not entirely
        # correct as there are files with the same hashes but different names
        # in the data. But: file names in NSRL are not accurate and sometimes
        # truncated, or abbreviated in another form, so it is not the cleanest
        # to start with.
        if sha1 not in sha1seen:
            bulkhash.append((sha1, md5, crc32, filename))
            sha1seen.add(sha1)
        bulkinserts.add((sha1, productcode))
        if counter % 10000 == 0:
            print("Entries for files processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            # now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute hash_insert(%s, %s, %s, %s)",
                                          bulkhash)
            psycopg2.extras.execute_batch(dbcursor, "execute entry_insert(%s, %s)",
                                          bulkinserts)
            dbconnection.commit()

            # clear the lists
            bulkinserts = set()
            bulkhash = []
        counter += 1

    # now insert the remaining files in bulk
    if bulkhash != []:
        psycopg2.extras.execute_batch(dbcursor, "execute hash_insert(%s, %s, %s, %s)",
                                      bulkhash)
    if bulkinserts != set():
        psycopg2.extras.execute_batch(dbcursor, "execute entry_insert(%s, %s)",
                                      bulkinserts)
    print("Entries for files processed:", counter)

    # cleanup
    dbconnection.commit()
    nsrfile.close()

    dbcursor.close()
    dbconnection.close()

if __name__ == "__main__":
    main()
