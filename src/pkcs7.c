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
	char *txt = PG_GETARG_CSTRING(0);
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs7_out);

Datum
pkcs7_out(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Read DER format.
 */
PG_FUNCTION_INFO_V1(pkcs7_receive);

Datum
pkcs7_receive(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Write DER format.
 */
PG_FUNCTION_INFO_V1(pkcs7_send);

Datum
pkcs7_send(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}
