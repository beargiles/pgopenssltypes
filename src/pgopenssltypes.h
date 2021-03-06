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

// DSA keys and parameters
Datum dsa_in(PG_FUNCTION_ARGS);
Datum dsa_out(PG_FUNCTION_ARGS);

Datum dsa_params_in(PG_FUNCTION_ARGS);
Datum dsa_params_out(PG_FUNCTION_ARGS);

// digital certificates
Datum x509_in(PG_FUNCTION_ARGS);
Datum x509_out(PG_FUNCTION_ARGS);

Datum x509_get_version(PG_FUNCTION_ARGS);
Datum x509_get_serial_number(PG_FUNCTION_ARGS);
Datum x509_get_not_before(PG_FUNCTION_ARGS);
Datum x509_get_not_after(PG_FUNCTION_ARGS);
Datum x509_get_subject_name(PG_FUNCTION_ARGS);
Datum x509_get_issuer_name(PG_FUNCTION_ARGS);
Datum x509_get_public_key(PG_FUNCTION_ARGS);
Datum x509_get_alias(PG_FUNCTION_ARGS);
Datum x509_check_private_key(PG_FUNCTION_ARGS);
Datum x509_get_iands_hash(PG_FUNCTION_ARGS);
Datum x509_get_subject_name_hash(PG_FUNCTION_ARGS);
Datum x509_get_issuer_name_hash(PG_FUNCTION_ARGS);
Datum x509_get_keyid(PG_FUNCTION_ARGS);

// digital certificate names
Datum x509_name_in(PG_FUNCTION_ARGS);
Datum x509_name_out(PG_FUNCTION_ARGS);

// digital certificate requests
Datum x509_req_in(PG_FUNCTION_ARGS);
Datum x509_req_out(PG_FUNCTION_ARGS);

// digital certificate revocation lists
Datum x509_crl_in(PG_FUNCTION_ARGS);
Datum x509_crl_out(PG_FUNCTION_ARGS);

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

bytea * bn_to_bytea(BIGNUM *bn);
bytea * x509_name_to_bytea(const X509_NAME *name);

#ifdef __cplusplus
}
#endif

#endif
