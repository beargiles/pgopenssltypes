// todo: standard wrappers...
#ifndef pgopenssltypes_h
#define pgopenssltypes_h

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

// private keypairs
Datum pkey_in(PG_FUNCTION_ARGS);
Datum pkey_out(PG_FUNCTION_ARGS);
Datum pkey_receive(PG_FUNCTION_ARGS);
Datum pkey_send(PG_FUNCTION_ARGS);

// RSA keypairs
Datum rsa_in(PG_FUNCTION_ARGS);
Datum rsa_out(PG_FUNCTION_ARGS);
Datum rsa_receive(PG_FUNCTION_ARGS);
Datum rsa_send(PG_FUNCTION_ARGS);

// digital certificates
Datum x509_in(PG_FUNCTION_ARGS);
Datum x509_out(PG_FUNCTION_ARGS);
Datum x509_receive(PG_FUNCTION_ARGS);
Datum x509_send(PG_FUNCTION_ARGS);

// PKCS12 keystores
Datum pkcs12_in(PG_FUNCTION_ARGS);
Datum pkcs12_out(PG_FUNCTION_ARGS);
Datum pkcs12_receive(PG_FUNCTION_ARGS);
Datum pkcs12_send(PG_FUNCTION_ARGS);

// PKCS8 keystores
Datum pkcs8_in(PG_FUNCTION_ARGS);
Datum pkcs8_out(PG_FUNCTION_ARGS);
Datum pkcs8_receive(PG_FUNCTION_ARGS);
Datum pkcs8_send(PG_FUNCTION_ARGS);

// PKCS7 keystores
Datum pkcs7_in(PG_FUNCTION_ARGS);
Datum pkcs7_out(PG_FUNCTION_ARGS);
Datum pkcs7_receive(PG_FUNCTION_ARGS);
Datum pkcs7_send(PG_FUNCTION_ARGS);

text *toHex(const unsigned char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif

