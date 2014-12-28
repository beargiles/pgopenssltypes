#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

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
	PG_RETURN_NULL();
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(x509req_out);

Datum
x509req_out(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

