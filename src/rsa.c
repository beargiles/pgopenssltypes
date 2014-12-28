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
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'rsa' functions.
 */
static RSA * rsa_from_string(const char *txt);
static RSA * rsa_from_bytea(const bytea *raw);
static char * rsa_to_string(const RSA *rsa);
static bytea * rsa_to_bytea(const RSA *rsa);

static RSA * rsa_generate_keypair_internal(int bits);

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1( rsa_in);

Datum rsa_in( PG_FUNCTION_ARGS) {
	char *txt;
	bytea *result;
	RSA *rsa;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// write RSA keypair into buffer
	rsa = rsa_from_string(txt);
	result = rsa_to_bytea(rsa);
	RSA_free(rsa);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1( rsa_out);

Datum rsa_out( PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	RSA *rsa;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// write RSA keypair into buffer
	rsa = rsa_from_bytea(raw);
	result = rsa_to_string(rsa);
	RSA_free(rsa);

	PG_RETURN_CSTRING(result);
}

/**
 * Generate a random keypair
 */
PG_FUNCTION_INFO_V1( rsa_generate_keypair);

Datum rsa_generate_keypair( PG_FUNCTION_ARGS) {
	bytea *result;
	int bits;
	RSA *rsa;

	bits = PG_GETARG_INT32(0);
	if (bits <= 0) {
		bits = 2048;
	}

	if (bits < 2048) {
		ereport(INFO,
				(errcode(ERRCODE_CHECK_VIOLATION), errmsg(
						"RSA keys should be at least 2048 bits.")));

		rsa = rsa_generate_keypair_internal(bits);
		result = rsa_to_bytea(rsa);
		RSA_free(rsa);

		// return bytea
		PG_RETURN_BYTEA_P(result);
	}
}

/**
 * Get details about an RSA keypair
 */
PG_FUNCTION_INFO_V1( rsa_get_details);

Datum rsa_get_details( PG_FUNCTION_ARGS) {
	bytea *raw;
	RSA *rsa;
	TupleDesc desc;
	HeapTuple tuple;
	Datum *values;
	bool *retNulls;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// read keypair, verify success.
	rsa = rsa_from_bytea(raw);
	if (rsa == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode RSA keypair record")));
		PG_RETURN_NULL();
	}

	// read details about return value.
	if (get_call_result_type(fcinfo, NULL, &desc) != TYPEFUNC_COMPOSITE) {
		RSA_free(rsa);
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg(
						"function returning record called in context "
								"that cannot accept type record")));
		PG_RETURN_NULL();
	}
	desc = BlessTupleDesc(desc);

	// these values are freed by PostgreSQL
	values = (Datum *) palloc(6 * sizeof(Datum));
	retNulls = (bool *) palloc(6 * sizeof(bool));

	// set return values
	values[0] = Int32GetDatum(8 * RSA_size(rsa));
	retNulls[0] = false;

	if (rsa->n == NULL) {
		retNulls[1] = true;
	} else {
		retNulls[1] = false;
		values[1] = BnGetDatum(rsa->n);
	}

	if (rsa->e == NULL) {
		retNulls[2] = true;
	} else {
		retNulls[2] = false;
		values[2] = BnGetDatum(rsa->e);
	}

	if (rsa->d == NULL) {
		retNulls[3] = true;
	} else {
		retNulls[3] = false;
		values[3] = BnGetDatum(rsa->d);
	}

	if (rsa->p == NULL) {
		retNulls[4] = true;
	} else {
		retNulls[4] = false;
		values[4] = BnGetDatum(rsa->p);
	}

	if (rsa->q == NULL) {
		retNulls[5] = true;
	} else {
		retNulls[5] = false;
		values[5] = BnGetDatum(rsa->q);
	}

	RSA_free(rsa);

	// convert to tuple.
	tuple = heap_form_tuple(desc, values, retNulls);
	FreeTupleDesc(desc);

	// return datum.
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

/*
 * Convert string to RSA.
 */
static RSA * rsa_from_string(const char *txt) {
	BIO *inp;
	RSA *rsa;

	rsa = RSA_new();

	inp = BIO_new_mem_buf((char *) txt, strlen(txt));
	PEM_read_bio_RSAPrivateKey(inp, &rsa, 0, NULL);
	BIO_free(inp);

	return rsa;
}

/*
 * Convert bytea to RSA.
 */
static RSA * rsa_from_bytea(const bytea *raw) {
	BIO *bio;
	RSA *rsa;

	// convert into RSA keypair
	bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	BIO_set_close(bio, BIO_NOCLOSE);
	rsa = RSA_new();
	d2i_RSAPrivateKey_bio(bio, &rsa);
	BIO_free(bio);

	if (rsa == NULL) {
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED), errmsg(
						"unable to decode RSA keypair record")));
	}

	return rsa;
}

/*
 * Convert RSA to string.
 */
static char * rsa_to_string(const RSA *rsa) {
	BIO *bio;
	int len;
	char *ptr, *result;

	// write RSA keypair into buffer
	// arguments: ..., cipher, keyptr, keylen, passwd_cb, passwd_cb_data
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bio, (RSA *) rsa, NULL, NULL, 0, NULL,
	NULL);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = palloc(len + 1);
	strncpy(result, ptr, len);
	result[len] = '\0';
	BIO_free(bio);

	return result;
}

/*
 * Convert RSA to bytea.
 */
static bytea * rsa_to_bytea(const RSA *rsa) {
	BIO *bio;
	int len;
	bytea *result;
	char *ptr;

	// write RSA keypair into buffer
	bio = BIO_new(BIO_s_mem());
	i2d_RSAPrivateKey_bio(bio, (RSA *) rsa);

	// create bytea results.
	len = BIO_number_written(bio);
	BIO_get_mem_data(bio, &ptr);
	result = (bytea *) palloc(len + VARHDRSZ);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);
	BIO_free(bio);

	return result;
}

RSA * rsa_generate_keypair_internal(int bits) {
	BIGNUM *ep;
	RSA *rsa;

	rsa = RSA_new();
	ep = BN_new();
	BN_dec2bn(&ep, "65537");
	RSA_generate_key_ex(rsa, bits, ep, NULL);
	BN_free(ep);

	return rsa;
}
