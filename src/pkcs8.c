#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'pkcs8' functions.
 */
static PKCS8_PRIV_KEY_INFO * pkcs8_from_string(const char *txt);
static PKCS8_PRIV_KEY_INFO * pkcs8_from_bytea(const bytea *raw);
static char * pkcs8_to_string(const PKCS8_PRIV_KEY_INFO *pkcs8);
static bytea * pkcs8_to_bytea(const PKCS8_PRIV_KEY_INFO *pkcs8);

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs8_in);

Datum pkcs8_in(PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	PKCS8_PRIV_KEY_INFO *pkcs8;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write PKCS8_PRIV_KEY_INFO cert into buffer
	pkcs8 = pkcs8_from_string(txt);
	result = pkcs8_to_bytea(pkcs8);
	PKCS8_PRIV_KEY_INFO_free(pkcs8);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs8_out);

Datum pkcs8_out(PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	PKCS8_PRIV_KEY_INFO *pkcs8;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write PKCS8_PRIV_KEY_INFO cert into buffer
	pkcs8 = pkcs8_from_bytea(raw);
	result = pkcs8_to_string(pkcs8);
	PKCS8_PRIV_KEY_INFO_free(pkcs8);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to PKCS8_PRIV_KEY_INFO.
 */
static PKCS8_PRIV_KEY_INFO * pkcs8_from_string(const char *txt) {
	BIO *inp;
	PKCS8_PRIV_KEY_INFO *pkcs8;

	pkcs8 = PKCS8_PRIV_KEY_INFO_new();
	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_PKCS8_PRIV_KEY_INFO(inp, &pkcs8, 0, NULL);
	BIO_free(inp);

	return pkcs8;
}

/*
 * Convert bytea to PKCS8_PRIV_KEY_INFO.
 */
static PKCS8_PRIV_KEY_INFO * pkcs8_from_bytea(const bytea *raw) {
	BIO *bio;
	PKCS8_PRIV_KEY_INFO *pkcs8;

	// convert into PKCS8_PRIV_KEY_INFO
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	pkcs8 = PKCS8_PRIV_KEY_INFO_new();
	d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &pkcs8);
	BIO_free(bio);

	if (pkcs8 == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode PKCS8 record")));
	}

	return pkcs8;
}

/*
 * Convert PKCS8_PRIV_KEY_INFO to string.
 */
static char * pkcs8_to_string(const PKCS8_PRIV_KEY_INFO *pkcs8) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write PKCS8_PRIV_KEY_INFO into buffer
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, (PKCS8_PRIV_KEY_INFO *) pkcs8);

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
 * Convert PKCS8_PRIV_KEY_INFO to bytea.
 */
static bytea * pkcs8_to_bytea(const PKCS8_PRIV_KEY_INFO *pkcs8) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write PKCS8_PRIV_KEY_INFO cert into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_PKCS8_PRIV_KEY_INFO_bio(bio, (PKCS8_PRIV_KEY_INFO *) pkcs8);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}
