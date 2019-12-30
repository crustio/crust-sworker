#include "FormatUtils.h"

static char *_hex_buffer = NULL;
static size_t _hex_buffer_size = 0;
const char _hextable[] = "0123456789abcdef";

int char_to_int(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return 0;
}

void hex_string_to_bytes(const char *src, unsigned char *target)
{
	while (*src && src[1])
	{
		*(target++) = (unsigned char)(char_to_int(*src) * 16 + char_to_int(src[1]));
		src += 2;
	}
}

/**
 * @description: Print hexstring
 * */
void print_hexstring(FILE *fp, const void *vsrc, size_t len)
{
	const unsigned char *sp = (const unsigned char *)vsrc;
	size_t i;
	for (i = 0; i < len; ++i)
	{
		fprintf(fp, "%02x", sp[i]);
	}
}

/**
 * @description: Dehexstring data
 * @return: status
 * */
int from_hexstring(unsigned char *dest, const void *vsrc, size_t len)
{
	size_t i;
	const unsigned char *src = (const unsigned char *)vsrc;

	for (i = 0; i < len; ++i)
	{
		unsigned int v;
#ifdef _WIN32
		if (sscanf_s(&src[i * 2], "%2xhh", &v) == 0)
			return 0;
#else
		if (sscanf(&src[i * 2], "%2xhh", &v) == 0)
			return 0;
#endif
		dest[i] = (unsigned char)v;
	}

	return 1;
}

/**
 * @description: Transform string to hexstring
 * @return: Hexstringed data
 * */
char *hexstring(const void *vsrc, size_t len)
{
	size_t i, bsz;
	const unsigned char *src = (const unsigned char *)vsrc;
	unsigned char *bp;

	bsz = len * 2 + 1; /* Make room for NULL byte */
	if (bsz >= _hex_buffer_size)
	{
		/* Allocate in 1K increments. Make room for the NULL byte. */
		size_t newsz = 1024 * (bsz / 1024) + ((bsz % 1024) ? 1024 : 0);
		_hex_buffer_size = newsz;
		_hex_buffer = (char *)realloc(_hex_buffer, newsz);
		if (_hex_buffer == NULL)
		{
			return "(out of memory)";
		}
	}

	for (i = 0, bp = _hex_buffer; i < len; ++i)
	{
		*bp = (uint8_t)_hextable[src[i] >> 4];
		++bp;
		*bp = (uint8_t)_hextable[src[i] & 0xf];
		++bp;
	}
	_hex_buffer[len * 2] = 0;

	return _hex_buffer;
}

/**
 * @description: Base64 encode data
 * @return: Base64 encoded data
 * */
char *base64_encode(const char *msg, size_t sz)
{
	BIO *b64, *bmem;
	char *bstr, *dup;
	size_t len;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());

	/* Single line output, please */
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO_push(b64, bmem);

	if (BIO_write(b64, msg, (int)sz) == -1)
	{
		BIO_free(bmem);
		BIO_free(b64);
		return NULL;
	}

	BIO_flush(b64);

	len = (size_t)BIO_get_mem_data(bmem, &bstr);
	dup = (char *)malloc(len + 1);
	if (dup == NULL)
	{
		BIO_free(bmem);
		BIO_free(b64);
		return NULL;
	}

	memcpy(dup, bstr, len);
	dup[len] = 0;

	BIO_free(bmem);
	BIO_free(b64);

	return dup;
}

/**
 * @description: Base64 decode data
 * @return: Decoded data
 * */
char *base64_decode(const char *msg, size_t *sz)
{
	BIO *b64, *bmem;
	char *buf;
	size_t len = strlen(msg);

	buf = (char *)malloc(len + 1);
	if (buf == NULL)
		return NULL;
	memset(buf, 0, len + 1);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new_mem_buf(msg, (int)len);

	BIO_push(b64, bmem);

	int rsz = BIO_read(b64, buf, (int)len);
	if (rsz == -1)
	{
		free(buf);
		return NULL;
	}

	*sz = (size_t)rsz;

	BIO_free_all(bmem);

	return buf;
}
