pgopenssltypes
=======

This is a PostgreSQL extension that duplicates much of the openssl(1)
functionality.

* dgst


Installation
------------

You need to run the test suite using a super user, such as the default
"postgres" super user:

    make installcheck PGUSER=postgres

Once pgopenssltypes is installed, you can add it to a database. If you're running
PostgreSQL 9.1.0 or greater, it's a simple as connecting to a database as a
super user and running:

    CREATE EXTENSION pgopenssltypes;

If you've upgraded your cluster to PostgreSQL 9.1 and already had pgopenssltypes
installed, you can upgrade it to a properly packaged extension with:

    CREATE EXTENSION pgopenssltypes FROM unpackaged;

For versions of PostgreSQL less than 9.1.0, you'll need to run the
installation script:

    psql -d mydb -f /path/to/pgsql/share/contrib/pgopenssltypes.sql

If you want to install pgopenssltypes and all of its supporting objects into a specific
schema, use the `PGOPTIONS` environment variable to specify the schema, like
so:

    PGOPTIONS=--search_path=extensions psql -d mydb -f pgopenssltypes.sql

Dependencies
------------

This extension has no dependencies other than PostgreSQL and OpenSSL.

Cryptography Notice
-------------------

This module contains cryptographic software built upon the OpenSSL
library that may be subject to usage, import, or export restrictions
at your location. It is the user's responsibility to comply with all
applicable laws.

Copyright and License
---------------------

Copyright (c) 2014 Bear Giles <bgiles@coyotesong.com>

This module is free software; you can redistribute it and/or modify it under
the [PostgreSQL License](http://www.opensource.org/licenses/postgresql).

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose, without fee, and without a written agreement is
hereby granted, provided that the above copyright notice and this paragraph
and the following two paragraphs appear in all copies.

In no event shall Bear Giles liable to any party for direct, indirect,
special, incidental, or consequential damages, including lost profits,
arising out of the use of this software and its documentation, even if 
Bear Giles has been advised of the possibility of such damage.

Bear Giles specifically disclaims any warranties, including, but not limited
to, the implied warranties of merchantability and fitness for a particular
purpose. The software provided hereunder is on an "as is" basis, and 
Bear Giles has no obligations to provide maintenance, support, updates,
enhancements, or modifications.
