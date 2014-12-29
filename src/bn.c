#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bn.h>

#include "pgopenssltypes.h"

static char * bn_to_string(BIGNUM *bn, char ch);

/*
 * Wrappers for OpenSSL 'bignum' functions.
 */

PG_FUNCTION_INFO_V1(bn_in);

Datum bn_in(PG_FUNCTION_ARGS) {
	char *txt;
	int len;
	bytea *result;
	BIGNUM *bn;

	// check for null input
	txt = PG_GETARG_CSTRING(0);
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// convert to bignum
	bn = BN_new();
	len = BN_dec2bn(&bn, txt);

	if (strlen(txt) != len) {
		elog(ERROR, "length mismatch - non-numeric values?");
		PG_RETURN_NULL();
	}

	// write to binary format
	result = bn_to_bytea(bn);
	BN_free(bn);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(bn_out);

Datum bn_out(PG_FUNCTION_ARGS) {
	bytea *raw;
	char *result;
	BIGNUM *bn;

	// check for null value.
	raw = PG_GETARG_BYTEA_P(0);
	if (raw == NULL) {
		PG_RETURN_NULL();
	}

	if (VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_CSTRING("0");
	}

	// convert into bignum
	bn = BN_bin2bn((const unsigned char *) VARDATA(raw) + 1, VARSIZE(raw) - VARHDRSZ - 1, NULL);
	result = bn_to_string(bn, VARDATA(raw)[0]);
	BN_free(bn);

	PG_RETURN_CSTRING(result);
}

/*
 * Convert BIGNUM to bytea.
 */
bytea * bn_to_bytea(BIGNUM *bn) {
	int len;
	bytea *result;

	// create bytea results.
	len = BN_num_bytes(bn);
	result = (bytea *) palloc(len + 1 + VARHDRSZ);
	memcpy(VARDATA(result), BN_is_negative(bn) ? "-" : "+", 1);
	BN_bn2bin(bn, (unsigned char *) VARDATA(result) + 1);
	SET_VARSIZE(result, len + 1 + VARHDRSZ);

	return result;
}

static char * bn_to_string(BIGNUM *bn, char ch) {
	char *ptr, *result;
	int len;

	// convert bignum to decimal
	ptr = BN_bn2dec(bn);

	// create bytea results.
	len = strlen(ptr);
	if (ch == '-') {
		result = palloc (2 + len);
		result[0] = '-';
		strncpy(result + 1, ptr, len);
		result[len + 1] = '\0';
	} else {
		result = palloc (1 + len);
		strncpy(result, ptr, len);
		result[len] = '\0';
	}

	// release memory
	OPENSSL_free(ptr);

	return result;
}

/**
 * Convert BIGNUM to Datum (for return in records).
 */
Datum BnGetDatum(BIGNUM *bn) {
	return PointerGetDatum(bn_to_bytea(bn));
}
