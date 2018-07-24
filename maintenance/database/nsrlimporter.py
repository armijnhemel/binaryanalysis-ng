#!/usr/bin/python3

## Binary Analysis Next Generation (BANG!)
##
## This script processes the National Software Reference Library (NSRL) CSV
## files and puts the relevant data in a database.
##
## NSRL is a forensics database released by NIST.
##
## https://www.nist.gov/software-quality-group/national-software-reference-library-nsrl
##
## Copyright 2018 - Armijn Hemel
## Licensed under the terms of the GNU General Public License version 3
## SPDX-License-Identifier: GPL-3.0-only

import sys
import os
import json
import argparse
import stat
import configparser
import csv
import io

## import some modules for dependencies, requires psycopg2 2.7+
import psycopg2
import psycopg2.extras

encodingstotranslate = [ 'utf-8','latin-1','euc_jp', 'euc_jis_2004'
                       , 'jisx0213', 'iso2022_jp', 'iso2022_jp_1'
                       , 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3'
                       , 'iso2022_jp_ext', 'iso2022_kr','shift_jis'
                       ,'shift_jis_2004','shift_jisx0213']

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
    parser.add_argument("-d", "--directory", action="store", dest="nsrldir", help="path to directory with NSRL directory files", metavar="DIR")
    args = parser.parse_args()

    ## sanity checks for the directory
    if args.nsrldir == None:
        parser.error("No NSRL directory provided, exiting")

    ## the configuration file should exist ...
    if not os.path.exists(args.nsrldir):
        parser.error("Directory %s does not exist, exiting." % args.nsrldir)

    ## ... and should be a real directory
    if not stat.S_ISDIR(os.stat(args.nsrldir).st_mode):
        parser.error("%s is not a regular file, exiting." % args.nsrldir)

    nsrlfiles = os.listdir(args.nsrldir)

    for i in ['NSRLFile.txt', 'NSRLMfg.txt', 'NSRLOS.txt', 'NSRLProd.txt']:
        if not i in nsrlfiles:
            print("Mandatory file %s not found in %s, exiting" % (i,args.nsrldir), file=sys.stderr)
            sys.exit(1)

    ## sanity checks for the configuration file
    if args.cfg == None:
        parser.error("No configuration file provided, exiting")

    ## the configuration file should exist ...
    if not os.path.exists(args.cfg):
        parser.error("File %s does not exist, exiting." % args.cfg)

    ## ... and should be a real file
    if not stat.S_ISREG(os.stat(args.cfg).st_mode):
        parser.error("%s is not a regular file, exiting." % args.cfg)

    ## read the configuration file. This is in Windows INI format.
    config = configparser.ConfigParser()

    try:
        configfile = open(args.cfg, 'r')
        config.readfp(configfile)
    except:
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    ## default values
    postgresql_host = None
    postgresql_port = None

    ## then process each individual section and extract configuration options
    for section in config.sections():
        if section == 'database':
            try:
                postgresql_user = config.get(section, 'postgresql_user')
                postgresql_password = config.get(section, 'postgresql_password')
                postgresql_db = config.get(section, 'postgresql_db')
            except:
                print("Configuration file malformed: missing database information", file=sys.stderr)
                configfile.close()
                sys.exit(1)
            try:
                postgresql_host = config.get(section, 'postgresql_host')
            except:
                pass
            try:
                postgresql_port = config.get(section, 'postgresql_port')
            except:
                pass

    configfile.close()

    ## test the database connection
    try:
        c = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, port=postgresql_port, host=postgresql_host)
        c.close()
    except Exception as e:
        print("Database server not running or malconfigured, exiting.", file=sys.stderr)
        sys.exit(1)

    sha1seen = set()

    ## open a connection to the database
    dbconnection = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, port=postgresql_port, host=postgresql_host)
    dbcursor = dbconnection.cursor()

    decode = False

    ## NSRL mixes different encodings in the CSV files, so gruesome hacks
    ## are needed to work around that, namely:
    ## 1. open the file in binary mode
    ## 2. split the data
    ## 3. decode all the data to UTF-8
    ## 4. write the decode data

    if decode:
        for i in ['NSRLFile.txt', 'NSRLMfg.txt', 'NSRLOS.txt', 'NSRLProd.txt']:
            checkfile = open(os.path.join(args.nsrldir, i), 'rb')
            decodedfilename = os.path.join(args.nsrldir, '%s-translated' % i)
            decodedfile = open(decodedfilename, 'w')

            ## read chunks of 10 million bytes
            readsize = 10000000
            offset = 0
            while True:
                checkfile.seek(offset)
                checkbytes = checkfile.read(readsize)
                buffs = checkbytes.rsplit(b'\r\n')
                lastoffset = checkbytes.rfind(b'\r\n')
                if len(checkbytes) == 0:
                    break
                if len(checkbytes) < readsize:
                    for b in buffs:
                        if b == b'':
                            continue
                        for encoding in encodingstotranslate:
                            try:
                                decodedfile.write(b.decode(encoding))
                                decodedfile.write('\n')
                                break
                            except Exception as e:
                                pass
                    break
                else:
                    for b in buffs[:-1]:
                        if b == b'':
                            continue
                        for encoding in encodingstotranslate:
                            try:
                                decodedfile.write(b.decode(encoding))
                                decodedfile.write('\n')
                                break
                            except:
                                pass
                offset += lastoffset
            decodedfile.close()

    ## then process all the translated files, start with NSRLMfg.txt
    decodedfilename = os.path.join(args.nsrldir, 'NSRLMfg.txt-translated')
    nsrfile = open(decodedfilename, 'r')

    ## skip the first line
    nsrfile.readline()

    ## then process the rest of the lines as CSV entries and split the data
    ## across the various tables
    csvreader = csv.reader(nsrfile)

    ## create a few prepared statements
    preparedmfg = "PREPARE mfg_insert as INSERT INTO nsrl_manufacturer (manufacturercode, manufacturername) values ($1, $2) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedmfg)

    counter = 1
    bulkinserts = []
    for i in csvreader:
        (manufacturercode, manufacturername) = i
        manufacturercode = int(manufacturercode)
        bulkinserts.append((manufacturercode, manufacturername))
        if counter % 10000 == 0:
            print("Entries for manufacturer processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            ## now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute mfg_insert(%s, %s)", bulkinserts)
            dbconnection.commit()

            ## clear the lists
            bulkinserts = []
            bulkhash = []
        counter += 1

    ## now insert the remaining files in bulk
    if bulkinserts != []:
        psycopg2.extras.execute_batch(dbcursor, "execute mfg_insert(%s, %s)", bulkinserts)
    print("Entries for manufacturer processed:", counter)
    dbconnection.commit()
    nsrfile.close()

    ## then NSRLOS.txt
    decodedfilename = os.path.join(args.nsrldir, 'NSRLOS.txt-translated')
    nsrfile = open(decodedfilename, 'r')

    ## skip the first line
    nsrfile.readline()

    ## then process the rest of the lines as CSV entries and split the data
    ## across the various tables
    csvreader = csv.reader(nsrfile)

    ## create a few prepared statements
    preparedos = "PREPARE os_insert as INSERT INTO nsrl_os (oscode, osname, osversion, manufacturercode) values ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedos)

    counter = 1
    bulkinserts = []
    for i in csvreader:
        (oscode, osname, osversion, manufacturercode) = i
        oscode = int(oscode)
        manufacturercode = int(manufacturercode)
        bulkinserts.append((oscode, osname, osversion, manufacturercode))
        if counter % 10000 == 0:
            print("Entries for OS processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            ## now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute os_insert(%s, %s, %s, %s)", bulkinserts)
            dbconnection.commit()

            ## clear the lists
            bulkinserts = []
        counter += 1

    ## now insert the remaining files in bulk
    if bulkinserts != []:
        psycopg2.extras.execute_batch(dbcursor, "execute os_insert(%s, %s, %s, %s)", bulkinserts)
    print("Entries for OS processed:", counter)
    dbconnection.commit()
    nsrfile.close()

    ## then NSRLProd.txt
    decodedfilename = os.path.join(args.nsrldir, 'NSRLProd.txt-translated')
    nsrfile = open(decodedfilename, 'r')

    ## skip the first line
    nsrfile.readline()

    ## then process the rest of the lines as CSV entries and split the data
    ## across the various tables
    csvreader = csv.reader(nsrfile)

    ## create a few prepared statements
    preparedproduct = "PREPARE product_insert as INSERT INTO nsrl_product (productcode, productname, productversion, manufacturercode, applicationtype) values ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedproduct)

    counter = 1
    bulkinserts = []
    for i in csvreader:
        (productcode, productname, productversion, oscode, manufacturercode, language, applicationtype) = i
        productcode = int(productcode)
        manufacturercode = int(manufacturercode)
        bulkinserts.append((productcode, productname, productversion, manufacturercode, applicationtype))
        if counter % 10000 == 0:
            print("Entries for products processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            ## now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute product_insert(%s, %s, %s, %s, %s)", bulkinserts)
            dbconnection.commit()

            ## clear the lists
            bulkinserts = []
        counter += 1

    ## now insert the remaining files in bulk
    if bulkinserts != []:
        psycopg2.extras.execute_batch(dbcursor, "execute product_insert(%s, %s, %s, %s, %s)", bulkinserts)
    print("Entries for products processed:", counter)
    dbconnection.commit()
    nsrfile.close()

    ## finally NSRLFile.txt
    decodedfilename = os.path.join(args.nsrldir, 'NSRLFile.txt-translated')
    nsrfile = open(decodedfilename, 'r')

    ## skip the first line
    nsrfile.readline()

    ## then process the rest of the lines as CSV entries and split the data
    ## across the various tables
    csvreader = csv.reader(nsrfile)

    ## create a few prepared statements
    preparedhash = "PREPARE hash_insert as INSERT INTO nsrl_hash (sha1, md5, filename) values ($1, $2, $3) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedhash)

    preparedentry = "PREPARE entry_insert as INSERT INTO nsrl_entry (sha1, productcode) values ($1, $2) ON CONFLICT DO NOTHING"
    dbcursor.execute(preparedentry)

    ## "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
    ## only store: sha1, md5, filename, product code, opsystem code and special code
    ## These are in different tables
    counter = 1
    bulkinserts = []
    bulkhash = []
    for i in csvreader:
        (sha1, md5, crc32, filename, filesize, productcode, opsystemcode, specialcode) = i
        sha1 = sha1.lower()
        md5 = md5.lower()
        productcode = int(productcode)
        if not sha1 in sha1seen:
            bulkhash.append((sha1, md5, filename))
            sha1seen.add(sha1)
        bulkinserts.append((sha1, productcode))
        if counter % 10000 == 0:
            print("Entries for files processed:", counter)
            sys.stdout.flush()
        if counter % 100000 == 0:
            ## now insert the files in bulk
            psycopg2.extras.execute_batch(dbcursor, "execute hash_insert(%s, %s, %s)", bulkhash)
            psycopg2.extras.execute_batch(dbcursor, "execute entry_insert(%s, %s)", bulkinserts)
            dbconnection.commit()

            ## clear the lists
            bulkinserts = []
            bulkhash = []
        counter += 1

    ## now insert the remaining files in bulk
    if bulkhash != []:
        psycopg2.extras.execute_batch(dbcursor, "execute hash_insert(%s, %s, %s)", bulkhash)
    if bulkinserts != []:
        psycopg2.extras.execute_batch(dbcursor, "execute entry_insert(%s, %s)", bulkinserts)
    print("Entries for files processed:", counter)

    ## cleanup
    dbconnection.commit()
    nsrfile.close()

    dbcursor.close()
    dbconnection.close()

if __name__ == "__main__":
    main(sys.argv)
