#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'x509' functions.
 */
static X509 * x509_from_string(const char *txt);
static X509 * x509_from_bytea(const bytea *raw);
static char * x509_to_string(const X509 *x509);
static bytea * x509_to_bytea(const X509 *x509);

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
	X509 *x509;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write X509 cert into buffer
	x509 = x509_from_bytea(raw);
	result = x509_to_string(x509);
	X509_free(x509);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to X509.
 */
static X509 * x509_from_string(const char *txt) {
	BIO *inp;
	X509 *x509;

	x509 = X509_new();
	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_X509(inp, &x509, 0, NULL);
	BIO_free(inp);

	return x509;
}

/*
 * Convert bytea to X509.
 */
static X509 * x509_from_bytea(const bytea *raw) {
	BIO *bio;
	X509 *x509;

	// convert into X509
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	x509 = X509_new();
	d2i_X509_bio(bio, &x509);
	BIO_free(bio);

	if (x509 == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 record")));
	}

	return x509;
}

/*
 * Convert X509 to string.
 */
static char * x509_to_string(const X509 *x509) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write X509 into buffer
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, (X509 *) x509);

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
static bytea * x509_to_bytea(const X509 *x509) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write X509 cert into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_X509_bio(bio, (X509 *) x509);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}
