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

#### Keystore and Digital Certificate types

These are the main reason why this extension exists - UDTs that store
private keys and digital certificates.

+ X509: digital certificate [RFC 5280](https://tools.ietf.org/html/rfc5280)

+ PKCS12: keystore. Not currently implemented. [RFC 7292](https://tools.ietf.org/html/rfc7292). This is the only type that is not accessed as a PEM text value.

+ PKCS8: keystore for private certificate keypairs [RFC 5280](https://tools.ietf.org/html/rfc5280)

+ PKCS7: cryptographic messages [RFC 2315](https://tools.ietf.org/html/rfc2315)

#### Certificate Authority (CA) types

Certificate authorities use two additional types as digital certificates
move through their lifecycle. They will be used in a proposed 'pgca' extension.

+ X509_REQ: digital certificate request (PKCS10) [RFC 2986](https://tools.ietf.org/html/rfc2986)

+ X509_CRL: digital certificate revocation list [RFC 5280](https://tools.ietf.org/html/rfc5280)

#### Deprecated types

These types are supported for historic reasons but should not be used since
the keys are stored unencrypted. I do not consider this a problem since it
is much better to use a PKCS8 keystore.

+ RSA: RSA keypair (PKCS1) [RFC 3447](https://tools.ietf.org/html/rfc3447)

+ DSA: DSA keypair

+ DSA_PARAMS: DSA parameters

#### Miscellaneous types

These are support types

+ BN: unlimited precision integers.

Usage
-----

The extension is loaded by properly installing it (e.g., with the tools
from pgxn.org) and then executing the command `CREATE EXTENSION pgopenssltypes;`

At this point you can define tables using the UDT as though they are standand
varchar[] values. All expect and produce the data in OpenSSL PEM format.'

#### Digests

A large number of cryptographically strong message digests, or hashes, are available. All take text and return a BN (which can be immediately cast to a
string).

+ dgst_MD5 (for legacy use only)
+ dgst_SHA1 (for legacy use only)
+ dgst_SHA224
+ dgst_SHA256
+ dgst_SHA384
+ dgst_SHA512
+ dgst_ripend160
+ dgst_whirlpool

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

