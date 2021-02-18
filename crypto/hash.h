#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include "../kerncompat.h"

#define CRYPTO_HASH_SIZE_MAX	32

int hash_crc32c(const u8 *buf, size_t length, u8 *out);
int hash_xxhash(const u8 *buf, size_t length, u8 *out);
int hash_sha256(const u8 *buf, size_t length, u8 *out);
int hash_blake2b(const u8 *buf, size_t length, u8 *out);
int hash_auth_sha256(const u8 *buf, size_t length, u8 *out,
		     const u8 *key, size_t keylen);
int hash_auth_blake2b(const u8 *buf, size_t length, u8 *out,
		      const u8 *key, size_t keylen);

#endif
