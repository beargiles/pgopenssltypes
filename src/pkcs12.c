#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"

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
	char *txt = PG_GETARG_CSTRING(0);
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs12_out);

Datum
pkcs12_out(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Read DER format.
 */
PG_FUNCTION_INFO_V1(pkcs12_receive);

Datum
pkcs12_receive(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Write DER format.
 */
PG_FUNCTION_INFO_V1(pkcs12_send);

Datum
pkcs12_send(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}
