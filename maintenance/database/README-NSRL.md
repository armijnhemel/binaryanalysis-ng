# NSRL

The NSRL forensics data sets can be found at:

https://www.nist.gov/software-quality-group/national-software-reference-library-nsrl

The main contents of NSRL are published as multiple ISO images, each containing
CSV files. NSRL version 2.76 (March 2022) has the following sets:

* modern (microcomputer applications from 2010 to present)
* android (modern Android applications)
* iOS
* legacy (microcomputer applications from 2009 and earlier)

Data for older Android applications can be found in version 2.65. Data for
older iOS applications can be found in version 2.73.1.

Each of these ISO files contain several CSV files:

* `NSRLFile.txt` (stored ZIP compressed as `NSRLFile.txt.zip`) -- maps checksums and names of individual files to products
* `NSRLMfg.txt` -- information about manufacturers
* `NSRLOS.txt` -- information about operating systems
* `NSRLProd.txt` -- information about individual products

The first line of each file lists the field names.

# Importing the NSRL data

According to the documentation these CSV files ought to be UTF-8, but experience
shows that they might not be. It is advised to translate them first.

Then they need to be made searchable by putting them into a database.

The script `nsrlimporter.py` takes care of both steps (although translation can
optionally be disabled).

## Requirements

* PostgreSQL version that supports UPSERT and hash indexes (10 or higher)
* Python 3
* psycopg2 2.7.x

## Loading the data

To use the files do the following:

1. add the right tables to the database:

    $ psql -U username < nsrl-init.sql

2. mount the ISO files and copy the CSV files to a directory and make sure
that `NSRLFile.txt.zip` has been unzipped.

The easiest is to mount each file over loopback, for example:

    # mkdir /tmp/mnt
    # mount /home/armijn/nsrl/RDS_android.iso /tmp/mnt/

As a normal user do:

    $ cp /tmp/mnt/* /path/to/nsrl/directory

for example:

    $ cp /tmp/mnt/* /home/armijn/tmp/nsrl/

Of course you can also unpack the ISO-files via a desktop manager.

The NSRLFile.txt data is in a ZIP file that first needs to be decompressed:

    $ unzip NSRLFile.txt.zip

3. Import the data. It is advised to start with the 'modern' dataset, as this is the biggest.

run nsrlimporter.py:

    $ python3 nsrlimporter.py -c /path/to/configuration/file -d /path/to/nsrl/directory

for example:

    $ python3 nsrlimporter.py -c config.yaml -d /home/armijn/nsrl/modern/

The data in the NSRL dumps is not guaranteed to be in a single encoding: in
older versions of NSRL various encodings were found. By default the importer
will try to convert the data to UTF-8, although this is not guaranteed to
work. To disable this behaviour (NOT recommended) supply the `-t` flag:

    $ python3 nsrlimporter.py -c /path/to/configuration/file -d /path/to/nsrl/directory -t

4. After the first directory has been processed the indexes should be created to ensure data correctness:

    $ psql -U username < nsrl-index.sql

5. import the other directories in a similar fashion

## Statistics:

Some statistics for a recent version of NSRL (2.74, September 2021, modern applications only):

    bang=> \dt+
                             List of relations
     Schema |       Name        | Type  | Owner |  Size   | Description 
    --------+-------------------+-------+-------+---------+-------------
     public | nsrl_entry        | table | bang  | 13 GB   |
     public | nsrl_hash         | table | bang  | 5391 MB |
     public | nsrl_manufacturer | table | bang  | 4944 kB |
     public | nsrl_os           | table | bang  | 128 kB  |
     public | nsrl_product      | table | bang  | 2184 kB |
    (5 rows)
    
    bang=> \di+
                                          List of relations
     Schema |          Name          | Type  | Owner |       Table       |  Size   | Description 
    --------+------------------------+-------+-------+-------------------+---------+-------------
     public | nsrl_entry_sha1        | index | bang  | nsrl_entry        | 12 GB   |
     public | nsrl_hash_pkey         | index | bang  | nsrl_hash         | 2501 MB |
     public | nsrl_manufacturer_pkey | index | bang  | nsrl_manufacturer | 2280 kB |
     public | nsrl_os_pkey           | index | bang  | nsrl_os           | 72 kB   |
     public | nsrl_product_pkey      | index | bang  | nsrl_product      | 552 kB  |
    (5 rows)

    bang=> select from nsrl_entry ;
    --
    (182824087 rows)
    
    bang=> select from nsrl_hash ;
    --
    (38320334 rows)
    
    bang=> select from nsrl_manufacturer ;
    --
    (95343 rows)
    
    bang=> select from nsrl_os ;
    --
    (1359 rows)
    
    bang=> select from nsrl_product ;
    --
    (24372 rows)

# Database design

There are five tables, with the following schema:

    create table if not exists nsrl_hash(sha1 text, md5 text, crc32 text, filename text, primary key(sha1));
    create table if not exists nsrl_entry(sha1 text, product_code int);
    create table if not exists nsrl_manufacturer(code int, name text, primary key(code));
    create table if not exists nsrl_os(code int, name text, version text, manufacturer_code int, primary key(code));
    create table if not exists nsrl_product(code int, name text, version text, manufacturer_code int, application_type text, primary key(code));

The table `nsrl_entry` has an additional index:

    CREATE INDEX nsrl_entry_sha1 ON nsrl_entry;
