# Setting up the database

BANG uses PostgreSQL as a database backend. This document describes
how to configure PostgreSQL for use with BANG. Versions 9 and earlier
are not supported.

If you already have a preconfigured PostgreSQL server then use that. It
is important to know that by default BANG uses password authentication so
it is important to use that. This might change in the future.

When no database server exists, issue the following command:

    # postgresql-setup --initdb

This will initialize the database.

## Authentication

BANG uses password authentication. This is not the default used by PostgreSQL.

Authentication is configured in the file pg_hba.conf. Usually you can find
this file in the top level PostgreSQL directory (for example /var/lib/pgsql/data/
on Fedora systems). This file contains who is allowed to connect and if and how
they should authenticate.

Depending on the version of PostgreSQL the default versions might be different.

For example, you might find that local users (connecting via a file system
socket) are implicitly trusted:

    local   all      all       trust

or minimal checks by looking at the user name on the local system:

    local   all      all       peer

To prompt for the password (recommended) this should be changed in:

    local   all      all       password

For local IPv4 connections you might find:

    host    all      all       127.0.0.1/32      trust

or

    host    all      all       127.0.0.1/32      ident

and should be changed to:

    host    all      all       127.0.0.1/32      password

For access from other machines this should be changed here as well.

NOTE: PostgreSQL's "password" authentication is vulnerable to sniffing attacks, as
it is sent in plain text. This will be changed soon.
