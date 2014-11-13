#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'x509' functions.
 */

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(x509_in);

Datum
x509_in(PG_FUNCTION_ARGS)
{
	char *txt = PG_GETARG_CSTRING(0);
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(x509_out);

Datum
x509_out(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Read DER format.
 */
PG_FUNCTION_INFO_V1(x509_receive);

Datum
x509_receive(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}

/*
 * Write DER format.
 */
PG_FUNCTION_INFO_V1(x509_send);

Datum
x509_send(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	PG_RETURN_NULL();
}
