#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include "../kerncompat.h"
#include <stdbool.h>

#define CRYPTO_HASH_SIZE_MAX	32

enum auth_key_spec_type {
	AUTH_KEY_NONE,
	AUTH_KEY_BY_RAW,
	AUTH_KEY_BY_NAME,
	AUTH_KEY_BY_ID,
	AUTH_KEY_BY_FILE,
	AUTH_KEY_BY_FD,
};

struct auth_key_spec {
	enum auth_key_spec_type type;
	bool spec_valid;
	char *spec;
	union {
		unsigned int id;
		const char *filename;
		int fd;
	};

	bool key_valid;
	char *key;
	size_t length;
};

int hash_crc32c(const u8 *buf, size_t length, u8 *out);
int hash_xxhash(const u8 *buf, size_t length, u8 *out);
int hash_sha256(const u8 *buf, size_t length, u8 *out);
int hash_blake2b(const u8 *buf, size_t length, u8 *out);
int hash_auth_sha256(const u8 *tag, size_t tlength,
		     const u8 *buf, size_t length, u8 *out,
		     const u8 *key, size_t keylen);
int hash_auth_blake2b(const u8 *tag, size_t tlength,
		      const u8 *buf, size_t length, u8 *out,
		      const u8 *key, size_t keylen);

void auth_key_init(struct auth_key_spec *spec);
void auth_key_reset(struct auth_key_spec *spec);
int auth_key_parse(struct auth_key_spec *spec, const char *str);
int auth_key_setup(struct auth_key_spec *spec);

#endif
