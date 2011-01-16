#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>
#include <dirent.h>

#include "common.h"
#include "aes.h"
#include "sha1.h"


struct keylist {
	uint32_t n;
	struct key *keys;
};

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	fprintf(stderr, "%s\n", msg);
	perror("perror");

	exit(1);
}

const char *id2name(uint32_t id, struct id2name_tbl *t, const char *unk)
{
	while (t->name != NULL) {
		if (id == t->id)
			return t->name;
		t++;
	}
	return unk;
}


static struct id2name_tbl t_key2file[] = {
	{KEY_LV0, "lv0"},
	{KEY_LV1, "lv1"},
	{KEY_LV2, "lv2"},
	{KEY_APP, "app"},
	{KEY_ISO, "iso"},
	{KEY_LDR, "ldr"},
	{KEY_PKG, "pkg"},
	{KEY_SPP, "spp"},
	{0, NULL}
};


static int key_build_path(char *ptr)
{
	char *home = NULL;
	char *dir = NULL;

	memset(ptr, 0, 256);

	dir = getenv("SONY_KEYS");
	if (dir != NULL) {
		strncpy(ptr, dir, 256);
		return 0;
	}

	home = getenv("HOME");
	if (home == NULL)
		return -1;

	snprintf(ptr, 256, "%s/.ps3/", home);

	return 0;
}

static int key_read(const char *path, uint32_t len, uint8_t *dst)
{
	FILE *fp = NULL;
	uint32_t read;
	int ret = -1;

	fp = fopen(path, "r");
	if (fp == NULL)
		goto fail;

	read = fread(dst, len, 1, fp);

	if (read != 1)
		goto fail;

	ret = 0;

fail:
	if (fp != NULL)
		fclose(fp);

	return ret;
}


struct keylist *keys_get(enum sce_key type)
{
	const char *name = NULL;
	char base[256];
	char path[256];
	void *tmp = NULL;
	char *id;
	DIR *dp;
	struct dirent *dent;
	struct keylist *klist;
	uint8_t bfr[4];

	klist = malloc(sizeof *klist);
	if (klist == NULL)
		goto fail;

	memset(klist, 0, sizeof *klist);

	name = id2name(type, t_key2file, NULL);
	if (name == NULL)
		goto fail;

	if (key_build_path(base) < 0)
		goto fail;

	dp = opendir(base);
	if (dp == NULL)
		goto fail;

	while ((dent = readdir(dp)) != NULL) {
		if (strncmp(dent->d_name, name, strlen(name)) == 0 &&
		    strstr(dent->d_name, "key") != NULL) {
			tmp = realloc(klist->keys, (klist->n + 1) * sizeof(struct key));
			if (tmp == NULL)
				goto fail;

			id = strrchr(dent->d_name, '-');
			if (id != NULL)
				id++;

			klist->keys = tmp;
			memset(&klist->keys[klist->n], 0, sizeof(struct key));

			snprintf(path, sizeof path, "%s/%s-key-%s", base, name, id);
			key_read(path, 32, klist->keys[klist->n].key);
	
			snprintf(path, sizeof path, "%s/%s-iv-%s", base, name, id);
			key_read(path, 16, klist->keys[klist->n].iv);
	
			klist->keys[klist->n].pub_avail = -1;
			klist->keys[klist->n].priv_avail = -1;

			snprintf(path, sizeof path, "%s/%s-pub-%s", base, name, id);
			if (key_read(path, 40, klist->keys[klist->n].pub) == 0) {
				snprintf(path, sizeof path, "%s/%s-ctype-%s", base, name, id);
				key_read(path, 4, bfr);

				klist->keys[klist->n].pub_avail = 1;
				klist->keys[klist->n].ctype = get_u32(bfr);
			}

			snprintf(path, sizeof path, "%s/%s-priv-%s", base, name, id);
			if (key_read(path, 21, klist->keys[klist->n].priv) == 0)
				klist->keys[klist->n].priv_avail = 1;


			klist->n++;
		}
	}

	return klist;

fail:
	if (klist != NULL) {
		if (klist->keys != NULL)
			free(klist->keys);
		free(klist);
	}
	klist = NULL;

	return NULL;
}



int key_get_simple(const char *name, uint8_t *bfr, uint32_t len)
{
	char base[256];
	char path[256];

	if (key_build_path(base) < 0)
		return -1;

	snprintf(path, sizeof path, "%s/%s", base, name);
	if (key_read(path, len, bfr) < 0)
		return -1;

	return 0;
}

int key_get(enum sce_key type, const char *suffix, struct key *k)
{
	const char *name;
	char base[256];
	char path[256];
	uint8_t tmp[4];

	if (key_build_path(base) < 0)
		return -1;

	name = id2name(type, t_key2file, NULL);
	if (name == NULL)
		return -1;

	snprintf(path, sizeof path, "%s/%s-key-%s", base, name, suffix);
	if (key_read(path, 32, k->key) < 0)
		return -1;
	
	snprintf(path, sizeof path, "%s/%s-iv-%s", base, name, suffix);
	if (key_read(path, 16, k->iv) < 0)
		return -1;

	k->pub_avail = k->priv_avail = 1;

	snprintf(path, sizeof path, "%s/%s-ctype-%s", base, name, suffix);
	if (key_read(path, 4, tmp) < 0) { 
		k->pub_avail = k->priv_avail = -1;
		return 0;
	}

	k->ctype = get_u32(tmp);

	snprintf(path, sizeof path, "%s/%s-pub-%s", base, name, suffix);
	if (key_read(path, 40, k->pub) < 0)
		k->pub_avail = -1;

	snprintf(path, sizeof path, "%s/%s-priv-%s", base, name, suffix);
	if (key_read(path, 21, k->priv) < 0)
		k->priv_avail = -1;

	return 0;
}	

void decompress(uint8_t *in, uint64_t in_len, uint8_t *out, uint64_t out_len)
{
	z_stream s;
	int ret;

	memset(&s, 0, sizeof(s));

	s.zalloc = Z_NULL;
	s.zfree = Z_NULL;
	s.opaque = Z_NULL;

	ret = inflateInit(&s);
	if (ret != Z_OK)
		fail("inflateInit returned %d", ret);

	s.avail_in = in_len;
	s.next_in = in;

	s.avail_out = out_len;
	s.next_out = out;

	ret = inflate(&s, Z_FINISH);
	if (ret != Z_OK && ret != Z_STREAM_END)
		fail("inflate returned %d", ret);

	inflateEnd(&s);
}


int sce_decrypt_header(uint8_t *ptr, struct keylist *klist)
{
	uint32_t meta_offset;
	uint32_t meta_len;
	uint64_t header_len;
	uint32_t i, j;
	uint8_t tmp[0x40];
	int success = 0;


	meta_offset = get_u32(ptr + 0x0c);
	header_len  = get_u64(ptr + 0x10);

	for (i = 0; i < klist->n; i++) {
		aes256cbc(klist->keys[i].key,
			  klist->keys[i].iv,
			  ptr + meta_offset + 0x20,
			  0x40,
			  tmp); 

		success = 1;
		for (j = 0x10; j < (0x10 + 0x10); j++)
			if (tmp[j] != 0)
				success = 0;
	
		for (j = 0x30; j < (0x30 + 0x10); j++)
			if (tmp[j] != 0)
			       success = 0;

		if (success == 1) {
			memcpy(ptr + meta_offset + 0x20, tmp, 0x40);
			break;
		}
	}

	if (success != 1)
		return -1;

	memcpy(tmp, ptr + meta_offset + 0x40, 0x10);
	aes128ctr(ptr + meta_offset + 0x20,
		  tmp,
		  ptr + meta_offset + 0x60,
		  0x20,
		  ptr + meta_offset + 0x60);

	meta_len = header_len - meta_offset;

	aes128ctr(ptr + meta_offset + 0x20,
		  tmp,
		  ptr + meta_offset + 0x80,
		  meta_len - 0x80,
		  ptr + meta_offset + 0x80);

	return i;
}

int sce_decrypt_data(uint8_t *ptr)
{
	uint64_t meta_offset;
	uint32_t meta_len;
	uint32_t meta_n_hdr;
	uint64_t header_len;
	uint32_t i;

	uint64_t offset;
	uint64_t size;
	uint32_t keyid;
	uint32_t ivid;
	uint8_t *tmp;

	uint8_t iv[16];

	meta_offset = get_u32(ptr + 0x0c);
	header_len  = get_u64(ptr + 0x10);
	meta_len = header_len - meta_offset;
	meta_n_hdr = get_u32(ptr + meta_offset + 0x60 + 0xc);

	for (i = 0; i < meta_n_hdr; i++) {
		tmp = ptr + meta_offset + 0x80 + 0x30*i;
		offset = get_u64(tmp);
		size = get_u64(tmp + 8);
		keyid = get_u32(tmp + 0x24);
		ivid = get_u32(tmp + 0x28);

		if (keyid == 0xffffffff || ivid == 0xffffffff)
			continue;

		memcpy(iv, ptr + meta_offset + 0x80 + 0x30 * meta_n_hdr + ivid * 0x10, 0x10);
		aes128ctr(ptr + meta_offset + 0x80 + 0x30 * meta_n_hdr + keyid * 0x10,
		          iv,
 		          ptr + offset,
			  size,
			  ptr + offset);
	}

	return 0;
}

void aes256cbc(uint8_t *key, uint8_t *iv_in, uint8_t *in, uint64_t len, uint8_t *out)
{
	AES_KEY k;
	uint32_t i;
	uint8_t tmp[16];
	uint8_t iv[16];

	memcpy(iv, iv_in, 16);
	memset(&k, 0, sizeof k);
	AES_set_decrypt_key(key, 256, &k);

	while (len > 0) {
		memcpy(tmp, in, 16);
		AES_decrypt(in, out, &k);

		for (i = 0; i < 16; i++)
			out[i] ^= iv[i];

		memcpy(iv, tmp, 16);

		out += 16;
		in += 16;
		len -= 16;

	}
}

void aes128ctr(uint8_t *key, uint8_t *iv, uint8_t *in, uint64_t len, uint8_t *out)
{
	AES_KEY k;
	uint32_t i;
	uint8_t ctr[16];
	uint64_t tmp;

	memset(ctr, 0, 16);
	memset(&k, 0, sizeof k);

	AES_set_encrypt_key(key, 128, &k);

	for (i = 0; i < len; i++) {
		if ((i & 0xf) == 0) {
			AES_encrypt(iv, ctr, &k);
	
			// increase nonce
			tmp = get_u64(iv + 8) + 1;
			set_u64(iv + 8, tmp);
			if (tmp == 0)
				set_u64(iv, get_u64(iv) + 1);
		}
		*out++ = *in++ ^ ctr[i & 0x0f];
	}
}

uint8_t get_u8(uint8_t *p)
{
	return *p;
}

uint16_t get_u16(uint8_t *p)
{
	uint16_t a;

	a  = p[0] << 8;
	a |= p[1];

	return a;
}

uint32_t get_u32(uint8_t *p)
{
	uint32_t a;

	a  = p[0] << 24;
	a |= p[1] << 16;
	a |= p[2] <<  8;
	a |= p[3] <<  0;

	return a;
}

uint64_t get_u64(uint8_t *p)
{
	uint32_t a, b;

	a = get_u32(p);
	b = get_u32(p + 4);

	return ((uint64_t)a<<32) | b;
}

void set_u16(uint8_t *p, uint16_t v)
{
	p[0] = v >>  8;
	p[1] = v;
}

void set_u32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >>  8;
	p[3] = v;
}

void set_u64(uint8_t *p, uint64_t v)
{
	set_u32(p + 4, v);
	v >>= 32;
	set_u32(p, v);
}