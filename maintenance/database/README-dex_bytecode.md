# Dex bytecode

BANG can process 

## Requirements

* PostgreSQL version that supports UPSERT and hash indexes (10 or higher)
* Python 3
* psycopg2 2.7.x

## Loading the data

For this script a directory with BANG result directories is needed.

To import the data do the following:

1. add the right tables to the database:

    $ psql -U username < dex-init.sql

2. run the script to load the passwords into the database

    $ python3 dex_bytecode_importer.py -c /path/to/configuration/file -f /path/to/bang/result/directories

## Statistics


# Database design

There is one table, with the following schema:

    
    CREATE TABLE IF NOT EXISTS dex_bytecode(dex_sha256 text, class_name text, method_name text, bytecode_sha256 text, bytecode_tlsh text);

There are three additional indexes:

    CREATE INDEX dex_bytecode_dex_sha256 ON apk_contents USING HASH (dex_sha256);
    CREATE INDEX dex_bytecode_bytecode_sha256 ON apk_contents USING HASH (bytecode_sha256);
    CREATE INDEX dex_bytecode_bytecode_tlsh ON apk_contents USING HASH (bytecode_tlsh);
