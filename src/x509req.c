#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'x509_req' functions.
 */
static X509_REQ * x509_req_from_string(const char *txt);
static X509_REQ * x509_req_from_bytea(const bytea *raw);
static char * x509_req_to_string(const X509_REQ *x509_req);
static bytea * x509_req_to_bytea(const X509_REQ *x509_req);

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1( x509_req_in);

Datum x509_req_in( PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	X509_REQ *x509_req;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write X509_REQ into buffer
	x509_req = x509_req_from_string(txt);
	result = x509_req_to_bytea(x509_req);
	X509_REQ_free(x509_req);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1( x509_req_out);

Datum x509_req_out( PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	X509_REQ *x509_req;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write X509_REQ into buffer
	x509_req = x509_req_from_bytea(raw);
	result = x509_req_to_string(x509_req);
	X509_REQ_free(x509_req);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to X509_REQ.
 */
static X509_REQ * x509_req_from_string(const char *txt) {
	BIO *inp;
	X509_REQ *x509_req;

	x509_req = X509_REQ_new();
	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_X509_REQ(inp, &x509_req, 0, NULL);
	BIO_free(inp);

	return x509_req;
}

/*
 * Convert bytea to X509_REQ.
 */
static X509_REQ * x509_req_from_bytea(const bytea *raw) {
	BIO *bio;
	X509_REQ *x509_req;

	// convert into X509_REQ
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	x509_req = X509_REQ_new();
	d2i_X509_REQ_bio(bio, &x509_req);
	BIO_free(bio);

	if (x509_req == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509_REQ record")));
	}

	return x509_req;
}

/*
 * Convert X509_REQ to string.
 */
static char * x509_req_to_string(const X509_REQ *x509_req) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write X509_REQ into buffer
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, (X509_REQ *) x509_req);

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
 * Convert X509_REQ to bytea.
 */
static bytea * x509_req_to_bytea(const X509_REQ *x509_req) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write X509_REQ into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_X509_REQ_bio(bio, (X509_REQ *) x509_req);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}
