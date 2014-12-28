#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'pkcs12' functions.
 */

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs12_in);

Datum
pkcs12_in(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs12_out);

Datum
pkcs12_out(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

