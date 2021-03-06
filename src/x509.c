#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "pgopenssltypes.h"

// for valuable hints see: https://zakird.com/2013/10/13/certificate-parsing-with-openssl/

//X509_check_ca(cert) - returns int (0 = false, > 0 valid)
// SPKAC - Netscape extension used by some CAs.
// X509_extract_key
// X509_name_cmp
// X509_get_signature_type

// X509_get_X509_PUBKEY
// X509_verify(X509 *, EVP_PKEY *)

// X509_sign(X509, PKEY, MD)
// X509_sign_ctx(X509, EVP_MD_CTX)
// ulong X509_NAME_hash(X509_NAME *)

// X509_pubkey_digest(X509, EVP_MD, unsigned char *md, unsigned int *len)
// X509_digest(X509, EVP_MD, unsigned char *, unsigned int *len)
// X509_REQ_digest
// X509_NAME_digest

// PKEY * X509_PUBKEY_get(X509_PUBKEY *)
// i2d_PUBKEY
// d2i PUBKEY

// X509_NAME_set(X509_NAME **, X509_NAME *)

// int X509_alias_set1(X509 *, unsigned char *name, int len)
// int X509_keyid_set1(X509 *, unsigned char *id, int len);
// X509_TRUST_set
// X509_add1_trust_object
// X509_add1_reject_object
// X509_trust_clear(X509 *)
// X509_reject_clear(X509 *)

// X509_PKEY * X509_PKEY_new()

// X509 *X509_dup(X509)
// X509_REQ *X509_to_X509_REQ(
// X509 *X509_REQ_to_X509(

/*
 * Wrappers for OpenSSL 'x509' functions.
 */
static X509 * x509_from_string(const char *txt);
static X509 * x509_from_bytea(const bytea *raw);
static char * x509_to_string(const X509 *cert);
static bytea * x509_to_bytea(const X509 *cert);

#define DATE_LEN 128

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(x509_in);

Datum x509_in(PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	X509 *x509;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write X509 cert into buffer
	x509 = x509_from_string(txt);
	if (x509 == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
		PG_RETURN_NULL();
	}

	result = x509_to_bytea(x509);
	X509_free(x509);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(x509_out);

Datum x509_out(PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	X509 *cert;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write X509 cert into buffer
	cert = x509_from_bytea(raw);
	result = x509_to_string(cert);
	X509_free(cert);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to X509.
 */
static X509 * x509_from_string(const char *txt) {
	BIO *inp;
	X509 *cert;

	cert = X509_new();
	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_X509(inp, &cert, 0, NULL);
	BIO_free(inp);

	return cert;
}

/*
 * Convert bytea to X509.
 */
static X509 * x509_from_bytea(const bytea *raw) {
	BIO *bio;
	X509 *cert;

	// convert into X509
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	cert = X509_new();
	d2i_X509_bio(bio, &cert);
	BIO_free(bio);

	return cert;
}

/*
 * Convert X509 to string.
 */
static char * x509_to_string(const X509 *cert) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write X509 into buffer
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, (X509 *) cert);

	// create results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = palloc(len + 1);
	strncpy(result, ptr, len);
	result[len] = '\0';
	BIO_free(bio);

	return result;
}

/*
 * Convert X509 to bytea.
 */
static bytea * x509_to_bytea(const X509 *cert) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write X509 cert into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_X509_bio(bio, (X509 *) cert);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}

/*
 * Get certificate version number. Should always be '3'.
 */
PG_FUNCTION_INFO_V1(x509_get_version);

Datum x509_get_version(PG_FUNCTION_ARGS) {
	bytea *raw;
	X509 *cert;
	int version;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	cert = x509_from_bytea(raw);
	if (cert == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
	}

	version = X509_get_version(cert);
	X509_free(cert);

	PG_RETURN_INT32(version);
}

/*
 * Get certificate serial number.
 */
PG_FUNCTION_INFO_V1(x509_get_serial_number);

Datum x509_get_serial_number(PG_FUNCTION_ARGS) {
	bytea *raw;
	bytea *result;
	BIGNUM *bn;
	X509 *cert;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	cert = x509_from_bytea(raw);
	if (cert == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
	}

	bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
	result = bn_to_bytea(bn);
	BN_free(bn);
	X509_free(cert);

	PG_RETURN_BYTEA_P(result);
}

/*
 * Get certificate 'not before' timestamp.
 */
PG_FUNCTION_INFO_V1(x509_get_not_before);

Datum x509_get_not_before(PG_FUNCTION_ARGS) {
	bytea *raw;
	X509 *cert;
	BIO *bio;
	char buf[DATE_LEN];
	int r;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// read cert
	cert = x509_from_bytea(raw);
	if (cert == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
		PG_RETURN_NULL();
	}

	// extract 'not before' date
	bio = BIO_new(BIO_s_mem());
	if ((r = ASN1_TIME_print(bio, X509_get_notBefore(cert))) <= 0) {
		X509_free(cert);
		BIO_free(bio);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg("unable to retrieve 'notBefore' timestamp")));
		PG_RETURN_NULL();
	}

	// convert 'not before' date
	if ((r = BIO_gets(bio, buf, DATE_LEN)) <= 0) {
		X509_free(cert);
		BIO_free(bio);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg("unable to create ISO-8601 timestamp")));
		PG_RETURN_NULL();
	}

	BIO_free(bio);
	X509_free(cert);

	// FIXME convert ISO-8601 timestamp

	PG_RETURN_NULL();
}

/*
 * Get certificate 'not after' timestamp.
 */
PG_FUNCTION_INFO_V1(x509_get_not_after);

Datum x509_get_not_after(PG_FUNCTION_ARGS) {
	bytea *raw;
	X509 *cert;
	BIO *bio;
	char buf[DATE_LEN];
	int r;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// read cert
	cert = x509_from_bytea(raw);
	if (cert == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
		PG_RETURN_NULL();
	}

	// extract 'not after' date
	bio = BIO_new(BIO_s_mem());
	if ((r = ASN1_TIME_print(bio, X509_get_notAfter(cert))) <= 0) {
		X509_free(cert);
		BIO_free(bio);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg("unable to retrieve 'notAfter' timestamp")));
		PG_RETURN_NULL();
	}

	// convert 'not before' date
	if ((r = BIO_gets(bio, buf, DATE_LEN)) <= 0) {
		X509_free(cert);
		BIO_free(bio);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg("unable to create ISO-8601 timestamp")));
		PG_RETURN_NULL();
	}

	BIO_free(bio);
	X509_free(cert);

	// FIXME convert ISO-8601 timestamp

	PG_RETURN_NULL();
}

/*
 * Get certificate subject name.
 */
PG_FUNCTION_INFO_V1(x509_get_subject_name);

Datum x509_get_subject_name(PG_FUNCTION_ARGS) {
	bytea *raw;
	bytea *result;
	X509 *cert;
	X509_NAME *name;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// read cert
	cert = x509_from_bytea(raw);
	if (cert == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
		PG_RETURN_NULL();
	}

	// convert name
	name = X509_get_subject_name(cert);
	if (name == NULL) {
		X509_free(cert);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"X509 record missing mandatory subject name field")));
		PG_RETURN_NULL();
	}

	result = x509_name_to_bytea(name);
	X509_free(cert);

	PG_RETURN_BYTEA_P(result);
}

/*
 * Get certificate issuer name.
 */
PG_FUNCTION_INFO_V1(x509_get_issuer_name);

Datum x509_get_issuer_name(PG_FUNCTION_ARGS) {
	bytea *raw;
	bytea *result;
	X509 *cert;
	X509_NAME *name;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// read cert
	cert = x509_from_bytea(raw);
	if (cert == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
		PG_RETURN_NULL();
	}

	// convert name
	name = X509_get_issuer_name(cert);
	if (name == NULL) {
		X509_free(cert);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"X509 record missing mandatory issuer name field")));
		PG_RETURN_NULL();
	}

	result = x509_name_to_bytea(name);
	X509_free(cert);

	PG_RETURN_BYTEA_P(result);
}

/*
 * Get certificate public key.
 */
PG_FUNCTION_INFO_V1(x509_get_public_key);

Datum x509_get_public_key(PG_FUNCTION_ARGS) {
	// PKEY *X509_get_pubkey(X509 *)
	PG_RETURN_NULL();
}

/*
 * Get certificate alias
 */
PG_FUNCTION_INFO_V1(x509_get_alias);

Datum x509_get_alias(PG_FUNCTION_ARGS) {
	// uchar * X509_alias_get0(X509*, *len);
	PG_RETURN_NULL();
}

/*
 * Get certificate alias.
 */
PG_FUNCTION_INFO_V1(x509_check_private_key);

Datum x509_check_private_key(PG_FUNCTION_ARGS) {
	// int X509_check_private_key (X509 *, PKEY *)
	PG_RETURN_NULL();
}

/*
 * Get Issuer and Serial Number Hash (used for indexing, should be unique).
 */
PG_FUNCTION_INFO_V1(x509_get_iands_hash);

Datum x509_get_iands_hash(PG_FUNCTION_ARGS) {
	// ulong X509_issuer_and_serial_hash(X509 *)
	PG_RETURN_NULL();
}

/*
 * Get Subject Hash (used for indexing).
 */
PG_FUNCTION_INFO_V1(x509_get_subject_name_hash);

Datum x509_get_subject_name_hash(PG_FUNCTION_ARGS) {
	// ulong X509_subject_name_hash(*X)
	PG_RETURN_NULL();
}

/*
 * Get Issuer Hash (used for indexing).
 */
PG_FUNCTION_INFO_V1(x509_get_issuer_name_hash);

Datum x509_get_issuer_name_hash(PG_FUNCTION_ARGS) {
	// ulong X509_issuer_name_hash(*X)
	PG_RETURN_NULL();
}

/*
 * Get KeyID (hash) (used for indexing).
 */
PG_FUNCTION_INFO_V1(x509_get_keyid);

Datum x509_get_keyid(PG_FUNCTION_ARGS) {
	// uchar *X509_keyid_get0(X509 *, *len)
	PG_RETURN_NULL();
}
