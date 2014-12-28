#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'pkey' functions.
 */

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pkey_in);

Datum
pkey_in(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pkey_out);

Datum
pkey_out(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

