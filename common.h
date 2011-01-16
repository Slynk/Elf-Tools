#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include "aes.h"
#include "sha1.h"

enum sce_key {
	KEY_LV0 = 0,
	KEY_LV1,
	KEY_LV2,
	KEY_APP,
	KEY_ISO,
	KEY_LDR,
	KEY_PKG,
	KEY_SPP
};

struct key {
	uint8_t key[32];
	uint8_t iv[16];

	int pub_avail;
	int priv_avail;
	uint8_t pub[40];
	uint8_t priv[21];
	uint32_t ctype;
};

struct id2name_tbl {
	uint32_t id;
	const char *name;
};

const char *id2name(uint32_t id, struct id2name_tbl *t, const char *unk);

void fail(const char *fmt, ...) __attribute__((noreturn));

void aes256cbc(uint8_t *key, uint8_t *iv, uint8_t *in, uint64_t len, uint8_t *out);
void aes256cbc_enc(uint8_t *key, uint8_t *iv, uint8_t *in, uint64_t len, uint8_t *out);
void aes128ctr(uint8_t *key, uint8_t *iv, uint8_t *in, uint64_t len, uint8_t *out);

int key_get(enum sce_key type, const char *suffix, struct key *k);
int key_get_simple(const char *name, uint8_t *bfr, uint32_t len);
struct keylist *keys_get(enum sce_key type);

void decompress(uint8_t *in, uint64_t in_len, uint8_t *out, uint64_t out_len);

int sce_decrypt_header(uint8_t *ptr, struct keylist *klist);
int sce_decrypt_data(uint8_t *ptr);

uint8_t get_u8(uint8_t *p);
uint16_t get_u16(uint8_t *p);
uint32_t get_u32(uint8_t *p);
uint64_t get_u64(uint8_t *p);

void set_u16(uint8_t *p, uint16_t v);
void set_u32(uint8_t *p, uint32_t v);
void set_u64(uint8_t *p, uint64_t v);
#endif