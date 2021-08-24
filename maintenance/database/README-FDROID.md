# F-Droid

F-Droid is an alternative app store for Android devices, with only open source
software.

## Crawling F-Droid data

There is a crawler that downloads software from F-Droid.

# Importing the F-Droid data

The script 

## Requirements

* PostgreSQL version that supports UPSERT and hash indexes (10 or higher)
* Python 3
* psycopg2 2.7.x

## Loading the data

To use the files do the following:

1. add the right tables to the database:

    $ psql -U username < fdroid-init.sql
    $ psql -U username < elf-init.sql

2. Import the data:

   $ $ python3 fdroidimporter.py -c /path/to/configuration

The configuration is a YAML file with information, such as database connection
information, the location of the temporary directory for unpacking APK
files and the location of the F-Droid download directory.

# Database design

There are three tables specific to F-Droid, with the following schema:

    CREATE TABLE IF NOT EXISTS fdroid_application(identifier text, source text, license text, PRIMARY KEY(identifier));
    CREATE TABLE IF NOT EXISTS fdroid_package(identifier text, version text, apk text, sha256 text, source_package text, PRIMARY KEY(identifier, version));
    CREATE TABLE IF NOT EXISTS apk_contents(apk text, full_name text, name text, sha256 text);

The table apk_contents has two additional indexes:

    CREATE INDEX apk_contents_sha256 ON apk_contents USING HASH (sha256);
    CREATE INDEX apk_contents_name ON apk_contents USING HASH (name);

Then there is a table specific to ELF files, with the following schema:

   CREATE TABLE IF NOT EXISTS elf_hashes(sha256 text, tlsh text, telfhash text);

with an additional index:

   CREATE INDEX elf_hashes_sha256 ON elf_hashes USING HASH (sha256);

The ELF specific table is shared with other import scripts.

The hash index is used because:

1. it takes a lot less space compared to b-tree indexes
2. only exact matches are needed
3. the contents are not unique per row

## fdroid_application

The `fdroid_application` table contains generic information about applications
but not about specific versions of those applications. Generic information in
this keys is the upstream source URL, a license identifier (assuming that the
package is not relicensed) and the name of the application.

## fdroid_package

The `fdroid_package` table contains information about specific versions of
an application. Apart from the name of the application (which matches
`fdroid_application`) it also contains the version string, the name of the
APK file (the binary package), a SHA256 checksum of the APK and the name of
the source code package that the binary file was generated from.

## apk_contents

The `apk_contents` table contains information about the files inside every
APK file. Apart from the name of the APK file it also contains the name of
file, the full name (relative to the root of the APK, including path
components), the file name (excluding path components) and the SHA256 checksum
of the file.

# Excluded data

Inside APK files there are many files that will not yield useful results
because they appear in many different APKs. They do however make the database
a lot bigger.

Currently the following files and patterns are ignored:

* `META-INF/androidx.*.version`
* `META-INF/com.android.support_*`
* `META-INF/com.google.android.material_material.version`
* `META-INF/android.arch.*', 'META-INF/android.support.*`
* `META-INF/buildserverid', 'META-INF/fdroidserverid`
* `META-INF/kotlinx-*.kotlin_module`
* `META-INF/kotlin-*.kotlin_module`

The following directories are also ignored:

* `zoneinfo/`
* `zoneinfo-global/`
* `org/joda/time/`
* `kotlin/`
* `kotlinx/`

These filters are currently hardcoded. Changing means changing the import
script and rerunning the import.
