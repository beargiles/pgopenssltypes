#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "access/tupdesc.h"
#include "access/htup_details.h"
#include "access/attnum.h"
#include "catalog/pg_type.h"
#include "utils/elog.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "pgopenssltypes.h"

// int DSA_generate_key(DSA *)
// int DSA_generate_parameters_ex(DSA *, int bits, const unsigned char *seed, int seed_len, int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
// int DSA_size(DSA *)
// int DSA_print(BIO *, const DSA *x, int off);
// int DSAparams_print(BIO *bp, const DSA *)

/*
 * Wrappers for OpenSSL 'dsa' functions.
 */
static DSA * dsa_from_string(const char *txt);
static DSA * dsa_from_bytea(const bytea *raw);
static char * dsa_to_string(const DSA *dsa);
static bytea * dsa_to_bytea(const DSA *dsa);

static DSA * dsa_params_from_string(const char *txt);
static DSA * dsa_params_from_bytea(const bytea *raw);
static char * dsa_params_to_string(const DSA *dsa);
static bytea * dsa_params_to_bytea(const DSA *dsa);

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(dsa_in);

Datum dsa_in(PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	DSA *dsa;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write DSA keypair into buffer
	dsa = dsa_from_string(txt);
	result = dsa_to_bytea(dsa);
	DSA_free(dsa);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(dsa_out);

Datum dsa_out(PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	DSA *dsa;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write DSA keypair into buffer
	dsa = dsa_from_bytea(raw);
	result = dsa_to_string(dsa);
	DSA_free(dsa);

	PG_RETURN_CSTRING(result);
}

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(dsa_params_in);

Datum dsa_params_in(PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	DSA *dsa;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write DSA param into buffer
	dsa = dsa_params_from_string(txt);
	result = dsa_params_to_bytea(dsa);
	DSA_free(dsa);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(dsa_params_out);

Datum dsa_params_out(PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	DSA *dsa;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write DSA keypair into buffer
	dsa = dsa_params_from_bytea(raw);
	result = dsa_params_to_string(dsa);
	DSA_free(dsa);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert string to DSA.
 */
static DSA * dsa_from_string(const char *txt) {
	BIO *inp;
	DSA *dsa;

	dsa = DSA_new();

	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_DSAPrivateKey(inp, &dsa, 0, NULL);
	BIO_free(inp);

	return dsa;
}

/*
 * Convert bytea to DSA.
 */
static DSA * dsa_from_bytea(const bytea *raw) {
	BIO *bio;
	DSA *dsa;

	// convert into DSA keypair
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	dsa = DSA_new();
	d2i_DSAPrivateKey_bio(bio, &dsa);
	BIO_free(bio);

	if (dsa == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode DSA keypair record")));
	}

	return dsa;
}

/*
 * Convert DSA to string.
 */
static char * dsa_to_string(const DSA *dsa) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write DSA keypair into buffer
	// arguments: ..., cipher, keyptr, keylen, passwd_cb, passwd_cb_data
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_DSAPrivateKey(bio, (DSA *) dsa, NULL, NULL, 0, NULL,
	NULL);

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
 * Convert DSA to bytea.
 */
static bytea * dsa_to_bytea(const DSA *dsa) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write DSA keypair into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_DSAPrivateKey_bio(bio, (DSA *) dsa);

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
 * Convert string to DSA PARAM
 */
static DSA * dsa_params_from_string(const char *txt) {
	BIO *bio;
	DSA *dsa;

	dsa = DSA_new();

	bio = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_DSAparams(bio, &dsa, 0, NULL);
	BIO_free(bio);

	return dsa;
}

/*
 * Convert bytea to DSA PARAM.
 */
static DSA * dsa_params_from_bytea(const bytea *raw) {
	BIO *bio;
	DSA *dsa;

	// convert into DSA params
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	dsa = DSA_new();
	d2i_DSAparams_bio(bio, &dsa);
	BIO_free(bio);

	if (dsa == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode DSA parameters record")));
	}

	return dsa;
}

/*
 * Convert DSA to string.
 */
static char * dsa_params_to_string(const DSA *dsa) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write DSA params into buffer
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_DSAparams(bio, dsa);

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
 * Convert DSA to bytea.
 */
static bytea * dsa_params_to_bytea(const DSA *dsa) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write DSA params into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_DSAparams_bio(bio, (DSA * ) dsa);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}

