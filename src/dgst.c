#include <stdio.h>
#include "postgres.h"
#include "fmgr.h"
#include <postgresql/internal/c.h>
#include <openssl/evp.h>

#include "pgopenssltypes.h"

/*
 * Wrappers for OpenSSL 'dgst' functions.
 *
 * Questions: is there a way to get a list of available digests?
 */

/*
 * Common code to compute digest.
 */
static
Datum
local_digest(const EVP_MD *digest, const char *data, unsigned int len)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = sizeof(md);

	int r = EVP_Digest(data, len, md, &mdlen, digest, NULL);
	if (r != 1) {
		elog(ERROR, "error computing digest");
	}

	PG_RETURN_TEXT_P(toHex(md, mdlen));
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_md4);

Datum
dgst_md4(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("MD4");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "MD4");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_md5);

Datum
dgst_md5(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("MD5");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "MD5");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_sha);

Datum
dgst_sha(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("SHA");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "SHA");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_sha1);

Datum
dgst_sha1(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("SHA1");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "SHA1");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_sha224);

Datum
dgst_sha224(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("SHA224");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "SHA224");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_sha256);

Datum
dgst_sha256(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("SHA256");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "SHA256");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_sha384);

Datum
dgst_sha384(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("SHA384");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "SHA384");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_sha512);

Datum
dgst_sha512(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("SHA512");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "SHA512");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_rmd160);

Datum
dgst_ripemd160(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("RIPEMD160");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "RIPEMD160");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}

/*
 * Compute digest.
 */
PG_FUNCTION_INFO_V1(dgst_whirlpool);

Datum
dgst_whirlpool(PG_FUNCTION_ARGS)
{
	text *txt = PG_GETARG_TEXT_P(0);
	const EVP_MD *digest = EVP_get_digestbyname("WHIRLPOOL");

	if (digest == NULL) {
		elog(ERROR, "unknown digest: %s", "WHIRLPOOL");
		PG_RETURN_NULL();
	}

	return local_digest(digest, VARDATA(txt), VARSIZE(txt) - VARHDRSZ);
}
