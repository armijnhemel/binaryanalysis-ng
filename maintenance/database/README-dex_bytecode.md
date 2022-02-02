# Dex bytecode

BANG can process Dalvik Dex files and compute various hashes for the actual
bytecode per method. These hashes can be used to identify code at the method
level and do (possibly) interesting comparisons.

Background material can be found here: <https://www.tdcommons.org/dpubs_series/2479/>

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

Processing 1471 packages (some with multiple Dex files) from F-Droid:

    bang=> \dt+; \di+;
                           List of relations
     Schema |     Name     | Type  | Owner |  Size   | Description
    --------+--------------+-------+-------+---------+-------------
     public | dex_bytecode | table | bang  | 5205 MB |
    (1 row)

                                          List of relations
     Schema |             Name             | Type  | Owner |    Table     |  Size   | Description
    --------+------------------------------+-------+-------+--------------+---------+-------------
     public | dex_bytecode_bytecode_sha256 | index | bang  | dex_bytecode | 757 MB  |
     public | dex_bytecode_bytecode_tlsh   | index | bang  | dex_bytecode | 1111 MB |
     public | dex_bytecode_dex_sha256      | index | bang  | dex_bytecode | 1063 MB |
    (3 rows)

    bang=> select from dex_bytecode ;
    --
    (22306668 rows)

Note: when these statistics were made most indexes were so called
"hash indexes", which were replaced by regular indexes later.

# Database design

There is one table, with the following schema:

    
    CREATE TABLE IF NOT EXISTS dex_bytecode(dex_sha256 text, class_name text, method_name text, bytecode_sha256 text, bytecode_tlsh text);

There are three additional indexes:

    CREATE INDEX dex_bytecode_dex_sha256 ON apk_contents(dex_sha256);
    CREATE INDEX dex_bytecode_bytecode_sha256 ON apk_contents(bytecode_sha256);
    CREATE INDEX dex_bytecode_bytecode_tlsh ON apk_contents (bytecode_tlsh);

In case a lot of data is loaded into a clean database it might be wise to first
load the data and create the indexes later. The index
`dex_bytecode_bytecode_tlsh` isn't a hash index but a regular B-tree, because
for some reason the TLSH data is giving the hash index trouble on PostgreSQL
12.7.
