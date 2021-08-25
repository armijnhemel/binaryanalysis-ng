# Password databases

Sometimes passwords can be found in password files in firmware files. To see
if these are known passwords there is a password database table available
that can be filled with hashed password/plaintext password combinations.

There are relatively few public password databases out there. One is the
file phpbb-withmd5.txt.bz2 that can be downloaded from:

https://wiki.skullsecurity.org/Passwords

The script that loads the data into the database expects lines with
hash/plaintext combinations separated by whitespace. As it is not known what
kind of hash will be encountered there is no restriction on what hashes can
be used (anything goes, also salted passwords) but it is also not recorded
what type of hash a hash that is in the database is (it really is just plain
text).

## Requirements

* PostgreSQL version that supports UPSERT and hash indexes (10 or higher)
* Python 3
* psycopg2 2.7.x

## Loading the data

To use the files do the following:

1. add the right tables to the database:

    $ psql -U username < passwd-init.sql

2. run the script to load the passwords into the database

    $ python3 passwdimporter.py -c /path/to/configuration/file -f /path/to/file/with/passwords

# Database design

There is one table, with the following schema:

    create table if not exists password(hashed text, plaintext text, primary key(hashed));
