#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'pkcs8' functions.
 */

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs8_in);

Datum
pkcs8_in(PG_FUNCTION_ARGS)
{
	char *txt = PG_GETARG_CSTRING(0);
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkcs8_out);

Datum
pkcs8_out(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Read DER format.
 */
PG_FUNCTION_INFO_V1(pkcs8_receive);

Datum
pkcs8_receive(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Write DER format.
 */
PG_FUNCTION_INFO_V1(pkcs8_send);

Datum
pkcs8_send(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}
