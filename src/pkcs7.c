#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'pkcs7' functions.
 */
static PKCS7 * pkcs7_from_string(const char *txt);
static PKCS7 * pkcs7_from_bytea(const bytea *raw);
static char * pkcs7_to_string(const PKCS7 *pkcs7);
static bytea * pkcs7_to_bytea(const PKCS7 *pkcs7);

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs7_in);

Datum pkcs7_in(PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	PKCS7 *pkcs7;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write PKCS7 cert into buffer
	pkcs7 = pkcs7_from_string(txt);
	result = pkcs7_to_bytea(pkcs7);
	PKCS7_free(pkcs7);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs7_out);

Datum pkcs7_out(PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	PKCS7 *pkcs7;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write PKCS7 cert into buffer
	pkcs7 = pkcs7_from_bytea(raw);
	result = pkcs7_to_string(pkcs7);
	PKCS7_free(pkcs7);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to PKCS7.
 */
static PKCS7 * pkcs7_from_string(const char *txt) {
	BIO *inp;
	PKCS7 *pkcs7;

	pkcs7 = PKCS7_new();
	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_PKCS7(inp, &pkcs7, 0, NULL);
	BIO_free(inp);

	return pkcs7;
}

/*
 * Convert bytea to PKCS7.
 */
static PKCS7 * pkcs7_from_bytea(const bytea *raw) {
	BIO *bio;
	PKCS7 *pkcs7;

	// convert into PKCS7
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	pkcs7 = PKCS7_new();
	d2i_PKCS7_bio(bio, &pkcs7);
	BIO_free(bio);

	if (pkcs7 == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode PKCS7 record")));
	}

	return pkcs7;
}

/*
 * Convert PKCS7 to string.
 */
static char * pkcs7_to_string(const PKCS7 *pkcs7) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write PKCS7 into buffer
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(bio, (PKCS7 *) pkcs7);

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
 * Convert PKCS7 to bytea.
 */
static bytea * pkcs7_to_bytea(const PKCS7 *pkcs7) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write PKCS7 cert into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_PKCS7_bio(bio, (PKCS7 *) pkcs7);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}
