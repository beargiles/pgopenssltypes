// todo: standard wrappers...
#ifndef pgopenssltypes_h
#define pgopenssltypes_h

#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif

// digests
Datum dgst_md4(PG_FUNCTION_ARGS);
Datum dgst_md5(PG_FUNCTION_ARGS);
Datum dgst_sha(PG_FUNCTION_ARGS);
Datum dgst_sha1(PG_FUNCTION_ARGS);
Datum dgst_sha224(PG_FUNCTION_ARGS);
Datum dgst_sha256(PG_FUNCTION_ARGS);
Datum dgst_sha384(PG_FUNCTION_ARGS);
Datum dgst_sha512(PG_FUNCTION_ARGS);
Datum dgst_ripemd160(PG_FUNCTION_ARGS);
Datum dgst_whirlpool(PG_FUNCTION_ARGS);

// big numbers
Datum bn_in(PG_FUNCTION_ARGS);
Datum bn_out(PG_FUNCTION_ARGS);

Datum BnGetDatum(BIGNUM *bn);

// private keypairs
Datum pkey_in(PG_FUNCTION_ARGS);
Datum pkey_out(PG_FUNCTION_ARGS);

// RSA keypairs
Datum rsa_in(PG_FUNCTION_ARGS);
Datum rsa_out(PG_FUNCTION_ARGS);

Datum rsa_generate_keypair(PG_FUNCTION_ARGS);
Datum rsa_get_details(PG_FUNCTION_ARGS);

// digital certificates
Datum x509_in(PG_FUNCTION_ARGS);
Datum x509_out(PG_FUNCTION_ARGS);

// PKCS12 keystores
Datum pkcs12_in(PG_FUNCTION_ARGS);
Datum pkcs12_out(PG_FUNCTION_ARGS);

// PKCS8 keystores
Datum pkcs8_in(PG_FUNCTION_ARGS);
Datum pkcs8_out(PG_FUNCTION_ARGS);

// PKCS7 keystores
Datum pkcs7_in(PG_FUNCTION_ARGS);
Datum pkcs7_out(PG_FUNCTION_ARGS);

text *toHex(const unsigned char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif

