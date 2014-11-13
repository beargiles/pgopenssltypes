#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'rsa' functions.
 */

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(rsa_in);

Datum
rsa_in(PG_FUNCTION_ARGS)
{
	char *txt = PG_GETARG_CSTRING(0);
	BIO *inp, *outp;
	bytea *result;
	char *ptr;
	int len;
	RSA *rsa;

	// check for null input
	if (txt == NULL || strlen(txt) == 0) {
		PG_RETURN_NULL();
	}

	// convert to RSA
	inp = BIO_new_mem_buf(txt, strlen(txt));
	PEM_read_bio_RSAPrivateKey(inp, &rsa, 0, NULL);
	BIO_free(inp);

	// verify this is a valid keypair
	//RSA_verify(rsa);

	// write RSA keypair into buffer
	outp = BIO_new(BIO_s_mem());
	i2d_RSAPrivateKey_bio(outp, rsa);
	
	// create bytea results.
	len = BIO_number_written(outp);
	result = (bytea *) palloc (len + VARHDRSZ);
	BIO_get_mem_ptr(outp, &ptr);
	memcpy(VARDATA(result), ptr, len);
	SET_VARSIZE(result, len + VARHDRSZ);

	// release memory
	BIO_free(outp);

	// return bytea
	PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(rsa_out);

Datum
rsa_out(PG_FUNCTION_ARGS)
{
	bytea *raw = PG_GETARG_BYTEA_P(0);
	long len;
	char *ptr, *result;
	BIO *inp, *outp;
	RSA *rsa;

	// check for null value.
	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
		PG_RETURN_NULL();
	}

	// convert into RSA keypair
	inp = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
	d2i_RSAPrivateKey_bio(inp, &rsa);
	BIO_free(inp);

	// verify function.
	//RSA_verify(rsa);

	// write RSA keypair into buffer
	// arguments: ..., cipher, keyptr, keylen, passwd_cb, passwd_cb_data
	outp = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(outp, rsa, NULL, NULL, 0, NULL, NULL);
	
	// create bytea results.
	BIO_get_mem_ptr(outp, &ptr);
	len = BIO_number_written(outp);
	result = palloc(len + 1);
	strncpy(result, ptr, len);
	result[len] = '\0';

	PG_RETURN_CSTRING(result);
}

/*
 * Read DER format.
 */
PG_FUNCTION_INFO_V1(rsa_receive);

Datum
rsa_receive(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Write DER format.
 */
PG_FUNCTION_INFO_V1(rsa_send);

Datum
rsa_send(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}
