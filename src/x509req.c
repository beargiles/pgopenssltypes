#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'x509 request' functions.
 */

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(x509req_in);

Datum
x509req_in(PG_FUNCTION_ARGS)
{
	char *txt = PG_GETARG_CSTRING(0);
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(x509req_out);

Datum
x509req_out(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Read DER format.
 */
PG_FUNCTION_INFO_V1(x509req_receive);

Datum
x509req_receive(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Write DER format.
 */
PG_FUNCTION_INFO_V1(x509req_send);

Datum
x509req_send(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}
