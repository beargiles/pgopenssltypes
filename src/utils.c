#include "postgres.h"
#include "fmgr.h"
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include "pgopenssltypes.h"

static const char hex[] = "0123456789ABCDEF";

text *toHex(const unsigned char *data, size_t len) {
	text *result = (text *) palloc (2 * len + VARHDRSZ);
	char *p = VARDATA(result);
	int i;

	for (i = 0; i < len; i++) {
		p[2*i] = hex[(data[i] >> 4) & 0x0F];	
		p[2*i+1] = hex[data[i] & 0x0F];	
	}

	SET_VARSIZE(result, 2*len + VARHDRSZ);

	return result;
}
