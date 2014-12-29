-- ----------------------------------------
--
-- PGOPENSSLTYPES User-defined functions
--
-- Author: Bear Giles
-- Created at: 2014-10-29 12:05:02 -0600
--
-- ----------------------------------------

-- ----------------------------------------
-- Implementation notes: the types use PEM
-- format for input and output and DER format
-- for receive and send. The internal format
-- is DER.
-- ----------------------------------------

-- ----------------------------------------
-- Wrappers to OpenSSL 'dgst' functions.
-- ----------------------------------------
CREATE OR REPLACE FUNCTION dgst_md4(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_md4'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_md5(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_md5'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_sha(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_sha'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_sha1(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_sha1'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_sha224(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_sha224'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_sha256(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_sha256'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_sha384(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_sha384'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_sha512(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_sha512'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_ripemd160(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_ripemd160'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dgst_whirlpool(text)
RETURNS text
AS 'pgopenssltypes', 'dgst_whirlpool'
LANGUAGE C IMMUTABLE STRICT;

-- ----------------------------------------
-- Wrapper for big numbers
-- ----------------------------------------
CREATE TYPE BN;

CREATE OR REPLACE FUNCTION bn_in(cstring)
RETURNS BN
AS 'pgopenssltypes', 'bn_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION bn_out(BN)
RETURNS CSTRING
AS 'pgopenssltypes', 'bn_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE BN (
    INPUT   = bn_in,
    OUTPUT  = bn_out
);

-- ----------------------------------------
-- Wrapper for private keypairs
-- ----------------------------------------
CREATE TYPE PKEY;

CREATE OR REPLACE FUNCTION pkey_in(cstring)
RETURNS PKEY
AS 'pgopenssltypes', 'pkey_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pkey_out(PKEY)
RETURNS CSTRING
AS 'pgopenssltypes', 'pkey_out'
LANGUAGE C IMMUTABLE STRICT;

-- CREATE OR REPLACE FUNCTION pkey_receive(internal)
-- RETURNS PKEY
-- AS 'pgopenssltypes', 'pkey_receive'
-- LANGUAGE C IMMUTABLE STRICT;

-- CREATE OR REPLACE FUNCTION pkey_send(PKEY)
-- RETURNS bytea
-- AS 'pgopenssltypes', 'pkey_send'
-- LANGUAGE C IMMUTABLE STRICT;

--
-- Redefine type with necessary functions.
--
CREATE TYPE PKEY (
    INPUT   = pkey_in,
    OUTPUT  = pkey_out
);

-- ----------------------------------------
-- Wrapper for RSA keys
-- ----------------------------------------
CREATE TYPE RSA;

CREATE OR REPLACE FUNCTION rsa_in(cstring)
RETURNS RSA
AS 'pgopenssltypes', 'rsa_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION rsa_out(RSA)
RETURNS CSTRING
AS 'pgopenssltypes', 'rsa_out'
LANGUAGE C IMMUTABLE STRICT;

-- CREATE OR REPLACE FUNCTION rsa_modulus(RSA)
-- RETURNS text
-- AS 'pgopenssltypes', 'rsa_modulus'
-- LANGUAGE C IMMUTABLE STRICT;

/* FIXME: return boolean */
-- CREATE OR REPLACE FUNCTION rsa_check(RSA)
-- RETURNS text
-- AS 'pgopenssltypes', 'rsa_check'
-- LANGUAGE C IMMUTABLE STRICT;

--
-- Generate RSA key. This is an expensive operation
-- so it should not be called casually.
--
-- CREATE OR REPLACE FUNCTION rsa_generate(int)
-- RETURNS RSA
-- AS 'pgopenssltypes', 'rsa_gen'
-- LANGUAGE C IMMUTABLE STRICT;

--
-- Redefine type with necessary functions.
--
CREATE TYPE RSA (
    INPUT   = rsa_in,
    OUTPUT  = rsa_out
);

-- ----------------------------------------
-- Wrapper for DSA keys and parameters
-- ----------------------------------------
CREATE TYPE DSA;

CREATE OR REPLACE FUNCTION dsa_in(cstring)
RETURNS DSA
AS 'pgopenssltypes', 'dsa_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dsa_out(DSA)
RETURNS CSTRING
AS 'pgopenssltypes', 'dsa_out'
LANGUAGE C IMMUTABLE STRICT;

--
-- Redefine type with necessary functions.
--
CREATE TYPE DSA (
    INPUT   = dsa_in,
    OUTPUT  = dsa_out
);

CREATE TYPE DSA_PARAMS;

CREATE OR REPLACE FUNCTION dsa_params_in(cstring)
RETURNS DSA_PARAMS
AS 'pgopenssltypes', 'dsa_params_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION dsa_params_out(DSA_PARAMS)
RETURNS CSTRING
AS 'pgopenssltypes', 'dsa_params_out'
LANGUAGE C IMMUTABLE STRICT;

--
-- Redefine type with necessary functions.
--
CREATE TYPE DSA_PARAMS (
    INPUT   = dsa_params_in,
    OUTPUT  = dsa_params_out
);

-- ----------------------------------------
-- Wrapper for X509 digital certificates
-- ----------------------------------------
CREATE TYPE X509;

CREATE OR REPLACE FUNCTION x509_in(cstring)
RETURNS X509
AS 'pgopenssltypes', 'x509_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION x509_out(X509)
RETURNS CSTRING
AS 'pgopenssltypes', 'x509_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE X509 (
    INPUT   = x509_in,
    OUTPUT  = x509_out
);

-- ----------------------------------------
-- Wrapper for PKCS12 key stores
-- ----------------------------------------
CREATE TYPE PKCS12;

CREATE OR REPLACE FUNCTION pkcs12_in(cstring)
RETURNS PKCS12
AS 'pgopenssltypes', 'pkcs12_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pkcs12_out(PKCS12)
RETURNS CSTRING
AS 'pgopenssltypes', 'pkcs12_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE PKCS12 (
    INPUT   = pkcs12_in,
    OUTPUT  = pkcs12_out
);

-- ----------------------------------------
-- Wrapper for PKCS8 private key wrapper
-- ----------------------------------------
CREATE TYPE PKCS8;

CREATE OR REPLACE FUNCTION pkcs8_in(cstring)
RETURNS PKCS8
AS 'pgopenssltypes', 'pkcs8_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pkcs8_out(PKCS8)
RETURNS CSTRING
AS 'pgopenssltypes', 'pkcs8_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE PKCS8 (
    INPUT   = pkcs8_in,
    OUTPUT  = pkcs8_out
);

-- ----------------------------------------
-- Wrapper for PKCS7 cryptographic message
-- ----------------------------------------
CREATE TYPE PKCS7;

CREATE OR REPLACE FUNCTION pkcs7_in(cstring)
RETURNS PKCS7
AS 'pgopenssltypes', 'pkcs7_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pkcs7_out(PKCS7)
RETURNS CSTRING
AS 'pgopenssltypes', 'pkcs7_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE PKCS7 (
    INPUT   = pkcs7_in,
    OUTPUT  = pkcs7_out
);

-- ----------------------------------------
-- Wrapper for X509 digital certificate requests
-- ----------------------------------------
CREATE TYPE X509REQ;

CREATE OR REPLACE FUNCTION x509req_in(cstring)
RETURNS X509REQ
AS 'pgopenssltypes', 'x509req_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION x509req_out(X509REQ)
RETURNS CSTRING
AS 'pgopenssltypes', 'x509req_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE X509REQ (
    INPUT   = x509req_in,
    OUTPUT  = x509req_out
);

-- ----------------------------------------
-- Misc.
-- ----------------------------------------
-- list ciphers

-- See more: http://www.postgresql.org/docs/current/static/xfunc-c.html
