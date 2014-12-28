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

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(x509_in);

Datum
x509_in(PG_FUNCTION_ARGS)
{
	char *txt = PG_GETARG_CSTRING(0);
	BIO *inp, *outp;
	bytea *result;
	char *ptr;
	int len;
	X509 *x509;

	// check for null input
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// convert to X509 object?
	inp = BIO_new_mem_buf(txt, strlen(txt));
	PEM_read_bio_X509(inp, &x509, 0, NULL);

	// verify this is a valid object?

	// write object into buffer
	outp = BIO_new(BIO_s_mem());
	i2d_X509_bio(outp, x509);

	// create bytea results.
	len = BIO_number_written(outp);
	result = (bytea *) palloc (len + VARHDRSZ);
	BIO_get_mem_ptr(outp, &ptr);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);

	// release memory
	BIO_free(inp);
	BIO_free(outp);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(x509_out);

Datum
x509_out(PG_FUNCTION_ARGS)
{
	bytea *raw = PG_GETARG_BYTEA_P(0);
	long len;
	char *ptr, *result;
	BIO *inp, *outp;
	X509 *x509;

	// check for null value.
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// convert into X509 object
	inp = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	d2i_X509_bio(inp, &x509);

	// verify object?

	// write object into buffer
	// arguments: ..., cipher, keyptr, keylen, passwd_cb, passwd_cb_data
	outp = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(outp, x509);

	// create bytea results.
	BIO_get_mem_ptr(outp, &ptr);
	len = BIO_number_written(outp);
	result = palloc(len + 1);
	strncpy(result, ptr, len);
	result[len] = '\0';

	// release memory
	BIO_free(inp);
	BIO_free(outp);

	PG_RETURN_CSTRING(result);
}

