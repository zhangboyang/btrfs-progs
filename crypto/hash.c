#include "crypto/hash.h"
#include "crypto/crc32c.h"
#include "crypto/xxhash.h"
#include "crypto/sha.h"
#include "crypto/blake2.h"

/*
 * Default builtin implementations
 */
int hash_crc32c(const u8* buf, size_t length, u8 *out)
{
	u32 crc = ~0;

	crc = crc32c(~0, buf, length);
	put_unaligned_le32(~crc, out);

	return 0;
}

int hash_xxhash(const u8 *buf, size_t length, u8 *out)
{
	XXH64_hash_t hash;

	hash = XXH64(buf, length, 0);
	put_unaligned_le64(hash, out);

	return 0;
}

/*
 * Implementations of cryptographic primitives
 */
#if CRYPTOPROVIDER_BUILTIN == 1

int hash_sha256(const u8 *buf, size_t len, u8 *out)
{
	SHA256Context context;

	SHA256Reset(&context);
	SHA256Input(&context, buf, len);
	SHA256Result(&context, out);

	return 0;
}

int hash_blake2b(const u8 *buf, size_t len, u8 *out)
{
	blake2b_state S;

	blake2b_init(&S, CRYPTO_HASH_SIZE_MAX);
	blake2b_update(&S, buf, len);
	blake2b_final(&S, out, CRYPTO_HASH_SIZE_MAX);

	return 0;
}

int hash_auth_sha256(const u8 *tag, size_t tlength,
		     const u8 *buf, size_t length, u8 *out,
		     const u8 *key, size_t keylen)
{
	HMAC256Context context;

	hmac256Reset(&context, key, keylen);
	if (tag)
		hmac256Input(&context, tag, tlength);
	hmac256Input(&context, buf, length);
	hmac256Result(&context, out);

	return 0;
}

int hash_auth_blake2b(const u8 *tag, size_t tlength,
		      const u8 *buf, size_t length, u8 *out,
		      const u8 *key, size_t keylen)
{
	blake2b_state S;

	blake2b_init_key(&S, CRYPTO_HASH_SIZE_MAX, key, keylen);
	if (tag)
		blake2b_update(&S, tag, tlength);
	blake2b_update(&S, buf, length);
	blake2b_final(&S, out, CRYPTO_HASH_SIZE_MAX);

	return 0;
}

#endif

#if CRYPTOPROVIDER_LIBGCRYPT == 1

#include <gcrypt.h>

int hash_sha256(const u8 *buf, size_t len, u8 *out)
{
	gcry_md_hash_buffer(GCRY_MD_SHA256, out, buf, len);
	return 0;
}

int hash_blake2b(const u8 *buf, size_t len, u8 *out)
{
	gcry_md_hash_buffer(GCRY_MD_BLAKE2B_256, out, buf, len);
	return 0;
}

int hash_auth_sha256(const u8 *tag, size_t tlength,
		     const u8 *buf, size_t length, u8 *out,
		     const u8 *key, size_t keylen)
{
	gcry_mac_hd_t mac;

	gcry_mac_open(&mac, GCRY_MAC_HMAC_SHA256, 0, NULL);
	gcry_mac_setkey(mac, key, keylen);
	if (tag)
		gcry_mac_write(mac, tag, tlength);
	gcry_mac_write(mac, buf, length);
	length = CRYPTO_HASH_SIZE_MAX;
	gcry_mac_read(mac, out, &length);
	gcry_mac_close(mac);

	return 0;
}

int hash_auth_blake2b(const u8 *tag, size_t tlength,
		      const u8 *buf, size_t length, u8 *out,
		      const u8 *key, size_t keylen)
{
	gcry_md_hd_t md;
	void *digest;

	/* Use digest with a key and not the HMAC API, results are not equal  */
	gcry_md_open(&md, GCRY_MD_BLAKE2B_256, 0);
	gcry_md_setkey(md, key, keylen);
	if (tag)
		gcry_md_write(md, tag, tlength);
	gcry_md_write(md, buf, length);
	digest = gcry_md_read(md, GCRY_MD_BLAKE2B_256);
	memcpy(out, digest, CRYPTO_HASH_SIZE_MAX);
	gcry_md_close(md);

	return 0;
}

#endif

#if CRYPTOPROVIDER_LIBSODIUM == 1

#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_auth_hmacsha256.h>

int hash_sha256(const u8 *buf, size_t len, u8 *out)
{
	return crypto_hash_sha256(out, buf, len);
}

int hash_blake2b(const u8 *buf, size_t len, u8 *out)
{
	return crypto_generichash_blake2b(out, CRYPTO_HASH_SIZE_MAX, buf, len,
			NULL, 0);
}

int hash_auth_sha256(const u8 *tag, size_t tlength,
		     const u8 *buf, size_t length, u8 *out,
		     const u8 *key, size_t keylen)
{
	crypto_auth_hmacsha256_state state;

	crypto_auth_hmacsha256_init(&state, (unsigned char *)key, keylen);
	if (tag)
		crypto_auth_hmacsha256_update(&state, tag, tlength);
	crypto_auth_hmacsha256_update(&state, buf, length);
	crypto_auth_hmacsha256_final(&state, out);

	return 0;
}

int hash_auth_blake2b(const u8 *tag, size_t tlength,
		      const u8 *buf, size_t length, u8 *out,
		      const u8 *key, size_t keylen)
{
	/* TODO */
	crypto_generichash_blake2b_state state;
	crypto_generichash_blake2b_init(&state, key, keylen, CRYPTO_HASH_SIZE_MAX);
	if (tag)
		crypto_generichash_blake2b_update(&state, tag, tlength);
	return crypto_generichash_blake2b_final(&state, out, CRYPTO_HASH_SIZE_MAX);
}

#endif

#if CRYPTOPROVIDER_LIBKCAPI == 1

#include <kcapi.h>

int hash_sha256(const u8 *buf, size_t len, u8 *out)
{
	static struct kcapi_handle *handle = NULL;
	int ret;

	if (!handle) {
		ret = kcapi_md_init(&handle, "sha256", 0);
		if (ret < 0) {
			fprintf(stderr,
				"HASH: cannot instantiate sha256, error %d\n",
				ret);
			exit(1);
		}
	}
	ret = kcapi_md_digest(handle, buf, len, out, CRYPTO_HASH_SIZE_MAX);
	/* kcapi_md_destroy(handle); */

	return ret;
}

int hash_blake2b(const u8 *buf, size_t len, u8 *out)
{
	static struct kcapi_handle *handle = NULL;
	int ret;

	if (!handle) {
		ret = kcapi_md_init(&handle, "blake2b-256", 0);
		if (ret < 0) {
			fprintf(stderr,
				"HASH: cannot instantiate blake2b-256, error %d\n",
				ret);
			exit(1);
		}
	}
	ret = kcapi_md_digest(handle, buf, len, out, CRYPTO_HASH_SIZE_MAX);
	/* kcapi_md_destroy(handle); */

	return ret;
}

int hash_auth_sha256(const u8 *tag, size_t tlength,
		     const u8 *buf, size_t length, u8 *out,
		     const u8 *key, size_t keylen)
{
	u8 tmp[tlength + length];
	int ret;

	/*
	 * Calling to kernel for init/update/update/final costs more in context
	 * switches than a temporary buffer
	 */
	memcpy(tmp, tag, tlength);
	memcpy(tmp + tlength, buf, length);

	/*
	 * This is slow as it needs to open a connection each time but is safe
	 * in case it's called with different keys.
	 */
	ret = kcapi_md_hmac_sha256(key, keylen, tmp, tlength + length, out,
				   CRYPTO_HASH_SIZE_MAX);

	return ret;
}

int hash_auth_blake2b(const u8 *tag, size_t tlength,
		      const u8 *buf, size_t length, u8 *out,
		      const u8 *key, size_t keylen)
{
	struct kcapi_handle *handle;
	u8 tmp[tlength + length];
	int ret;

	/*
	 * Calling to kernel for init/update/update/final costs more in context
	 * switches than a temporary buffer
	 */
	memcpy(tmp, tag, tlength);
	memcpy(tmp + tlength, buf, length);

	/*
	 * This is slow as it needs to open a connection each time but is safe
	 * in case it's called with different keys.
	 */
	ret = kcapi_md_init(&handle, "blake2b-256", 0);
	if (ret < 0) {
		fprintf(stderr,
			"HASH: cannot instantiate blake2b-256, error %d\n",
			ret);
		exit(1);
	}
	ret = kcapi_md_setkey(handle, key, keylen);
	ret = kcapi_md_digest(handle, tmp, tlength + length, out, CRYPTO_HASH_SIZE_MAX);
	kcapi_md_destroy(handle);

	return ret;
}

#endif

void auth_key_init(struct auth_key_spec *spec)
{
	memset(spec, 0, sizeof(struct auth_key_spec));
}

void auth_key_reset(struct auth_key_spec *spec)
{
	if (!spec->spec_valid) {
		auth_key_init(spec);
		return;
	}
	if (spec->type == AUTH_KEY_BY_RAW) {
		free(spec->spec);
		if (spec->key_valid)
			free(spec->key);
	}

	auth_key_init(spec);
}

/*
 * Parse key specifier string @str into @spec
 *
 * Format:
 * - id:1234
 * - name:keyname
 * - file:/read/from/this/file
 * - fd:3
 * - raw:useonlyfortesting
 */
int auth_key_parse(struct auth_key_spec *spec, const char *str)
{
	if (strncmp("raw:", str, strlen("raw:")) == 0) {
		spec->type = AUTH_KEY_BY_RAW;
		spec->spec = strdup(str);
	} else {
		spec->spec_valid = false;
		return -EINVAL;
	}

	spec->spec_valid = true;
	return 0;
}

/*
 * Set up key material according to the spec
 */
int auth_key_setup(struct auth_key_spec *spec)
{
	if (spec->type == AUTH_KEY_BY_RAW) {
                spec->key = strdup(spec->spec + strlen("raw:"));
                spec->length = strlen(spec->key);
        } else {
                fprintf(stderr, "unsupported auth key spec: %s\n", spec->spec);
		spec->key_valid = false;
                return -EINVAL;
        }

	spec->key_valid = true;
        return 0;
}
