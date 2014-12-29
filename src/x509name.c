#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "pgopenssltypes.h"

// X509_NAME_print(BIO *bp, X509_NAME *name, int obase);
// X509_NAME_print_ex(
// X509_NAME_entry_count(X509_NAME *)
// X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY *, char *field, int typ, bytes, len)

/*
 * Wrappers for OpenSSL 'x509 name' functions.
 */
static X509_NAME * x509_name_from_string(const char *txt);
static X509_NAME * x509_name_from_bytea(const bytea *raw);
static char * x509_name_to_string(const X509_NAME *name);

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(x509_name_in);

Datum x509_name_in(PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	X509_NAME *x509;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write X509 cert into buffer
	x509 = x509_name_from_string(txt);
	result = x509_name_to_bytea(x509);
	X509_NAME_free(x509);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(x509_name_out);

Datum x509_name_out(PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	X509_NAME *name;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write X509 name into buffer
	name = x509_name_from_bytea(raw);
	result = x509_name_to_string(name);
	X509_NAME_free(name);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to X509.
 */
static X509_NAME * x509_name_from_string(const char *txt) {
	BIO *inp;
	X509_NAME *x509;

	x509 = X509_NAME_new();
	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	// FIXME - this method does not exist and I don't see an easy parser.
	// PEM_read_bio_X509_NAME(inp, &x509, 0, NULL);
	BIO_free(inp);

	return x509;
}

/*
 * Convert bytea to X509.
 */
static X509_NAME * x509_name_from_bytea(const bytea *raw) {
	X509_NAME *name;
	unsigned char *p;

	// convert into X509_NAME
	name = X509_NAME_new();
	p = (unsigned char *) VARDATA(raw);
	d2i_X509_NAME(&name, (const unsigned char **) &p, VARSIZE(raw) - VARHDRSZ);

	if (name == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode X509 NAME record")));
	}

	return name;
}

/*
 * Convert X509 NAME to string.
 */
static char * x509_name_to_string(const X509_NAME *name) {
	int len;
	char *result;

	// write X509 NAME into buffer
	len = 1200;
	result = palloc(len+1);
	memset(result, 0, len);
	X509_NAME_oneline((X509_NAME *) name, result, len);
	result[len] = '\0';

	return result;
}

/*
 * Convert X509 NAME to bytea.
 */
bytea * x509_name_to_bytea(const X509_NAME *name) {
	int len;
	unsigned char *out;
	bytea *result;
	char *ptr;

	// write X509 cert into buffer
	len = i2d_X509_NAME((X509_NAME *) name, &out);
	if (len <= 0) {
		return NULL;
	}

	// create bytea results.
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);

	return result;
}
