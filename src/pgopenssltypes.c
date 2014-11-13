#include "postgres.h"
#include "fmgr.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "pgopenssltypes.h"

/*
 * You can include more files here if needed.
 * To use some types, you must include the
 * correct file here based on:
 * http://www.postgresql.org/docs/current/static/xfunc-c.html#XFUNC-C-TYPE-TABLE
 */

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(init);

Datum init(PG_FUNCTION_ARGS);

// PG_INIT() ? 
Datum
init(PG_FUNCTION_ARGS)
{
	OpenSSL_add_ssl_algorithms();

	/*
	 * This is an empty body and will return NULL
	 *
	 * You should remove this comment and type
	 * cool code here!
	 */

	PG_RETURN_NULL();
}
