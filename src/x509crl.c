#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'x509_crl' functions.
 */
static X509_CRL * x509_crl_from_string(const char *txt);
static X509_CRL * x509_crl_from_bytea(const bytea *raw);
static char * x509_crl_to_string(const X509_CRL *x509_crl);
static bytea * x509_crl_to_bytea(const X509_CRL *x509_crl);

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1( x509_crl_in);

Datum x509_crl_in( PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	X509_CRL *x509_crl;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write X509_CRL into buffer
	x509_crl = x509_crl_from_string(txt);
	result = x509_crl_to_bytea(x509_crl);
	X509_CRL_free(x509_crl);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1( x509_crl_out);

Datum x509_crl_out( PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	X509_CRL *x509_crl;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write X509_CRL into buffer
	x509_crl = x509_crl_from_bytea(raw);
	result = x509_crl_to_string(x509_crl);
	X509_CRL_free(x509_crl);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to X509_CRL.
 */
static X509_CRL * x509_crl_from_string(const char *txt) {
	BIO *inp;
	X509_CRL *x509_crl;

	x509_crl = X509_CRL_new();
	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_X509_CRL(inp, &x509_crl, 0, NULL);
	BIO_free(inp);

	return x509_crl;
}

/*
 * Convert bytea to X509_CRL.
 */
static X509_CRL * x509_crl_from_bytea(const bytea *raw) {
	BIO *bio;
	X509_CRL *x509_crl;

	// convert into X509_CRL
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	x509_crl = X509_CRL_new();
	d2i_X509_CRL_bio(bio, &x509_crl);
	BIO_free(bio);

	if (x509_crl == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509_CRL record")));
	}

	return x509_crl;
}

/*
 * Convert X509_CRL to string.
 */
static char * x509_crl_to_string(const X509_CRL *x509_crl) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write X509_CRL into buffer
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_CRL(bio, (X509_CRL *) x509_crl);

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
 * Convert X509_CRL to bytea.
 */
static bytea * x509_crl_to_bytea(const X509_CRL *x509_crl) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write X509_CRL into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_X509_CRL_bio(bio, (X509_CRL *) x509_crl);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}
