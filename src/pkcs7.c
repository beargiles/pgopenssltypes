#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'pkcs7' functions.
 */

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs7_in);

Datum
pkcs7_in(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs7_out);

Datum
pkcs7_out(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}
