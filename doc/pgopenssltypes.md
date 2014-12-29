pgopenssltypes
==============

Synopsis
--------

This extension adds support for OpenSSL cryptographic types
and functions to PostgreSQL.

Description
-----------

OpenSSL is the library behind a wide variety of encrypted communications,
most notably HTTPS (for Apache et al), OpenSSH, and various other network
services. PostgreSQL optionally uses it to encrypt network access.

OpenSSL can also be used as a general cryptographic library or a simple
Certificate Authority.

This extension creates PostgreSQL user defined types (UDT) that correspond
to the internal OpenSSL types.

+ X509: digital certificate [RFC 5280](https://tools.ietf.org/html/rfc5280)

+ PKCS7: cryptographic messages [RFC 2315](https://tools.ietf.org/html/rfc2315)

+ PKCS8: private certificate keypairs [RFC 5280](https://tools.ietf.org/html/rfc5280)

Several additional types are supported but deprecated since the keys must
be stored unencrypted. This should not be a problem since there is support
for encrypted keypair storage.

+ RSA: RSA keypair (PKCS1) [RFC 3447](https://tools.ietf.org/html/rfc3447)

+ DSA: DSA keypair

+ DSA_PARAMS: DSA parameters

Finally several obscure types used by certificate authorities are supported.

+ X509_REQ: digital certificate request (PKCS10) [RFC 2986](https://tools.ietf.org/html/rfc2986)

+ X509_CRL: digital certificate revocation list [RFC 5280](https://tools.ietf.org/html/rfc5280)

Usage
-----

The extension is loaded by properly installing it (e.g., with the tools
from pgxn.org) and then executing the command `CREATE EXTENSION pgopenssltypes;`

At this point you can define tables using the UDT as though they are standand
varchar[] values. All expect and produce the data in OpenSSL PEM format.


Support
-------

There is no support at this time. The latest code is available at
https://github.com/beargiles/pgopenssltypes.

Author
------

Bear Giles <bgiles@coyotesong.com>

Copyright and License
---------------------

Copyright (c) 2015 Bear Giles.

