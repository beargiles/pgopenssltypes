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

+ X509_NAME: subject and issuer names. These are a collection of
key-value pairs. (partially implemented)

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

#### X509v3 Digital Certificates

A large number of accessor functions have been created for X509 Digital
Certificates. This allows us to write database triggers that ensure data
consistency.

If we have a table containing certs and search fields, e.g.,

```
CREATE TABLE certs (
   cert       X509 NOT NULL,
   name       VARCHAR[100] NOT NULL,
   not_before TIMESTAMP NOT NULL,
   not_after  TIMESTAMP NOT NULL
);
```

we will be able to create triggers on insertion and modification

```
CREATE CONSTRAINT TRIGGER cert_update() BEFORE INSERT OR UPDATE
   ON certs NOT DEFERRABLE FOR EACH ROW
   EXECUTE PROCEDURE cert_update_proc();
  
CREATE OR REPLACE FUNCTION cert_update_proc RETURNING trigger $$
   BEGIN
       INSERT INTO certs(cert,
           X509_get_subject_name(cert),
           X509_get_not_before(cert),
           X509_get_not_after(cert));
       RETURN NEW;
   END;
$$ LANGUAGE plpgsql;
```

This ensures that the cached values 1) contain the correct information
and 2) will always reflect what is in the digital certificate.

The accessor functions are

+ X509_get_version
+ X509_get_serial_number
+ X509_get_not_before
+ X509_get_not_after
+ X509_get_subject_name
+ X509_get_issuer_name
+ X509_get_public_key
+ X509_get_alias
+ X509_get_iands_hash
+ X509_get_subject_name_hash
+ X509_get_issuer_name_hash
+ X509_get_keyid

There is also a function to verify that a digital certificate and private key match (`x509_check_private_key`).


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

