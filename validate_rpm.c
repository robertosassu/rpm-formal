// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the RPM parser.
 */

/* Execute:
 *
 * frama-c -eva -cpp-frama-c-compliant -cpp-extra-args="-I /usr/include -I /usr/include/x86_64-linux-gnu" -machdep gcc_x86_64 -eva-precision 1 -eva-split-limit 5000 validate_rpm.c
 */

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#ifndef __FRAMAC__
#include <asm/byteorder.h>
#else
#define __cpu_to_be32(x) x
#define __be32_to_cpu(x) x
#endif
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#define pr_debug printf

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifdef __FRAMAC__
#include "__fc_builtin.h"
#else
static void Frama_C_make_unknown(char *src, int src_len)
{
	int i;

	srand(time(NULL));

	for (i = 0; i < src_len; i++)
		src[i] = rand() % 256;
}
static int Frama_C_int_interval(int low, int high)
{
	srand(time(NULL));
	return (rand() % (high - low)) + low;
}
#endif

#define RPMTAG_FILEDIGESTS 1035
#define RPMTAG_FILEDIGESTALGO 5011

#define RPM_INT32_TYPE 4
#define RPM_STRING_ARRAY_TYPE 8

#define MD5_DIGEST_SIZE         16
#define SHA1_DIGEST_SIZE        20
#define RMD160_DIGEST_SIZE      20
#define SHA256_DIGEST_SIZE      32
#define SHA384_DIGEST_SIZE      48
#define SHA512_DIGEST_SIZE      64
#define SHA224_DIGEST_SIZE      28
#define RMD128_DIGEST_SIZE      16
#define RMD256_DIGEST_SIZE      32
#define RMD320_DIGEST_SIZE      40
#define WP512_DIGEST_SIZE 64
#define WP384_DIGEST_SIZE 48
#define WP256_DIGEST_SIZE 32
#define TGR192_DIGEST_SIZE 24
#define TGR160_DIGEST_SIZE 20
#define TGR128_DIGEST_SIZE 16
#define SM3256_DIGEST_SIZE 32
#define STREEBOG256_DIGEST_SIZE	32
#define STREEBOG512_DIGEST_SIZE	64

#define LENGTH 200

struct rpm_hdr {
	uint32_t magic;
	uint32_t reserved;
	uint32_t tags;
	uint32_t datasize;
} __attribute__((packed));

struct rpm_entryinfo {
	int32_t tag;
	uint32_t type;
	int32_t offset;
	uint32_t count;
} __attribute__((packed));

enum pgp_algos {
	DIGEST_ALGO_MD5		=  1,
	DIGEST_ALGO_SHA1	=  2,
	DIGEST_ALGO_RMD160	=  3,
	/* 4, 5, 6, and 7 are reserved. */
	DIGEST_ALGO_SHA256	=  8,
	DIGEST_ALGO_SHA384	=  9,
	DIGEST_ALGO_SHA512	= 10,
	DIGEST_ALGO_SHA224	= 11,
};

enum hash_algo {
	HASH_ALGO_MD4,
	HASH_ALGO_MD5,
	HASH_ALGO_SHA1,
	HASH_ALGO_RIPE_MD_160,
	HASH_ALGO_SHA256,
	HASH_ALGO_SHA384,
	HASH_ALGO_SHA512,
	HASH_ALGO_SHA224,
	HASH_ALGO_RIPE_MD_128,
	HASH_ALGO_RIPE_MD_256,
	HASH_ALGO_RIPE_MD_320,
	HASH_ALGO_WP_256,
	HASH_ALGO_WP_384,
	HASH_ALGO_WP_512,
	HASH_ALGO_TGR_128,
	HASH_ALGO_TGR_160,
	HASH_ALGO_TGR_192,
	HASH_ALGO_SM3_256,
	HASH_ALGO_STREEBOG_256,
	HASH_ALGO_STREEBOG_512,
	HASH_ALGO__LAST
};

static const enum hash_algo pgp_algo_mapping[DIGEST_ALGO_SHA224 + 1] = {
	[DIGEST_ALGO_MD5]	= HASH_ALGO_MD5,
	[DIGEST_ALGO_SHA1]	= HASH_ALGO_SHA1,
	[DIGEST_ALGO_RMD160]	= HASH_ALGO_RIPE_MD_160,
	[4]			= HASH_ALGO__LAST,
	[5]			= HASH_ALGO__LAST,
	[6]			= HASH_ALGO__LAST,
	[7]			= HASH_ALGO__LAST,
	[DIGEST_ALGO_SHA256]	= HASH_ALGO_SHA256,
	[DIGEST_ALGO_SHA384]	= HASH_ALGO_SHA384,
	[DIGEST_ALGO_SHA512]	= HASH_ALGO_SHA512,
	[DIGEST_ALGO_SHA224]	= HASH_ALGO_SHA224,
};

const char *const hash_algo_name[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]		= "md4",
	[HASH_ALGO_MD5]		= "md5",
	[HASH_ALGO_SHA1]	= "sha1",
	[HASH_ALGO_RIPE_MD_160]	= "rmd160",
	[HASH_ALGO_SHA256]	= "sha256",
	[HASH_ALGO_SHA384]	= "sha384",
	[HASH_ALGO_SHA512]	= "sha512",
	[HASH_ALGO_SHA224]	= "sha224",
	[HASH_ALGO_RIPE_MD_128]	= "rmd128",
	[HASH_ALGO_RIPE_MD_256]	= "rmd256",
	[HASH_ALGO_RIPE_MD_320]	= "rmd320",
	[HASH_ALGO_WP_256]	= "wp256",
	[HASH_ALGO_WP_384]	= "wp384",
	[HASH_ALGO_WP_512]	= "wp512",
	[HASH_ALGO_TGR_128]	= "tgr128",
	[HASH_ALGO_TGR_160]	= "tgr160",
	[HASH_ALGO_TGR_192]	= "tgr192",
	[HASH_ALGO_SM3_256]	= "sm3",
	[HASH_ALGO_STREEBOG_256] = "streebog256",
	[HASH_ALGO_STREEBOG_512] = "streebog512",
};

static const int hash_digest_size[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]		= MD5_DIGEST_SIZE,
	[HASH_ALGO_MD5]		= MD5_DIGEST_SIZE,
	[HASH_ALGO_SHA1]	= SHA1_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_160]	= RMD160_DIGEST_SIZE,
	[HASH_ALGO_SHA256]	= SHA256_DIGEST_SIZE,
	[HASH_ALGO_SHA384]	= SHA384_DIGEST_SIZE,
	[HASH_ALGO_SHA512]	= SHA512_DIGEST_SIZE,
	[HASH_ALGO_SHA224]	= SHA224_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_128]	= RMD128_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_256]	= RMD256_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_320]	= RMD320_DIGEST_SIZE,
	[HASH_ALGO_WP_256]	= WP256_DIGEST_SIZE,
	[HASH_ALGO_WP_384]	= WP384_DIGEST_SIZE,
	[HASH_ALGO_WP_512]	= WP512_DIGEST_SIZE,
	[HASH_ALGO_TGR_128]	= TGR128_DIGEST_SIZE,
	[HASH_ALGO_TGR_160]	= TGR160_DIGEST_SIZE,
	[HASH_ALGO_TGR_192]	= TGR192_DIGEST_SIZE,
	[HASH_ALGO_SM3_256]	= SM3256_DIGEST_SIZE,
	[HASH_ALGO_STREEBOG_256] = STREEBOG256_DIGEST_SIZE,
	[HASH_ALGO_STREEBOG_512] = STREEBOG512_DIGEST_SIZE,
};

/**
 * struct digest_cache - Digest cache
 * @num_slots: Number of slots
 * @algo: Algorithm of digests stored in the cache
 * @path_str: Path of the digest list the cache was created from
 * @mask: For which IMA actions and purpose the digest cache can be used
 *
 * This structure represents a cache of digests extracted from a file, to be
 * primarily used for IMA measurement and appraisal.
 */
struct digest_cache {
	unsigned int num_slots;
	enum hash_algo algo;
	char *path_str;
	u8 mask;
};

static int digest_cache_htable_init(struct digest_cache *digest_cache,
				    u64 num_digests, enum hash_algo algo)
{
	return 0;
}

static int digest_cache_htable_add(struct digest_cache *digest_cache,
				   u8 *digest, enum hash_algo algo)
{
	return 0;
}

int hex2bin(u8 *dst, const char *src, size_t count)
{
	return 0;
}

bool valid_buffer = false;

/**
 * digest_list_parse_rpm - Parse a tlv digest list
 * @digest_cache: Digest cache
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function parses an rpm digest list.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
/*@ requires \valid_read(data+(0..data_len-1)) && \initialized(data+(0..data_len-1));
  @ behavior valid_header:
  @   assumes valid_buffer == true;
  @   ensures \result == 0;
  @ behavior unknown_header:
  @   assumes valid_buffer == false;
  @   ensures \result == 0 || \result == -EINVAL;
  @ complete behaviors valid_header, unknown_header;
  @ disjoint behaviors valid_header, unknown_header;
 */
int digest_list_parse_rpm(struct digest_cache *digest_cache, const u8 *data,
			  size_t data_len)
{
	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};
	const struct rpm_hdr *hdr;
	const struct rpm_entryinfo *entry;
	u32 tags, max_tags, datasize;
	u32 digests_count, max_digests_count;
	u32 digests_offset, algo_offset;
	u32 digest_len, pkg_pgp_algo, i;
	bool algo_offset_set = false, digests_offset_set = false;
	enum hash_algo pkg_kernel_algo = HASH_ALGO_MD5;
	u8 rpm_digest[SHA512_DIGEST_SIZE];
	int ret;

	if (data_len < sizeof(*hdr)) {
		pr_debug("Not enough data for RPM header, current %ld, expected: %ld\n",
			 data_len, sizeof(*hdr));
		return -EINVAL;
	}

	for (i = 0; i < sizeof(rpm_header_magic); i++) {
		if (data[i] != rpm_header_magic[i]) {
			pr_debug("RPM header magic mismatch\n");
			return -EINVAL;
		}
	}

	//@ assert data_len >= sizeof(*hdr);
	hdr = (const struct rpm_hdr *)data;
	data += sizeof(*hdr);
	data_len -= sizeof(*hdr);

	tags = __be32_to_cpu(hdr->tags);
	max_tags = data_len / sizeof(*entry);

	/* Finite termination on tags loop. */
	if (tags > max_tags)
		return -EINVAL;

	datasize = __be32_to_cpu(hdr->datasize);
	if (datasize != data_len - tags * sizeof(*entry))
		return -EINVAL;

	pr_debug("Scanning %d RPM header sections\n", tags);
	//@ dynamic_split algo_offset_set;
	//@ dynamic_split digests_offset_set;
	//@ dynamic_split data_len;
	for (i = 0; i < tags; i++) {
		if (data_len < sizeof(*entry))
			return -EINVAL;

		entry = (const struct rpm_entryinfo *)data;
		data += sizeof(*entry);
		data_len -= sizeof(*entry);

		switch (__be32_to_cpu(entry->tag)) {
		case RPMTAG_FILEDIGESTS:
			if (__be32_to_cpu(entry->type) != RPM_STRING_ARRAY_TYPE)
				return -EINVAL;

			digests_offset = __be32_to_cpu(entry->offset);
			digests_count = __be32_to_cpu(entry->count);
			digests_offset_set = true;

			pr_debug("Found RPMTAG_FILEDIGESTS at offset %u, count: %u\n",
				 digests_offset, digests_count);
			break;
		case RPMTAG_FILEDIGESTALGO:
			if (__be32_to_cpu(entry->type) != RPM_INT32_TYPE)
				return -EINVAL;

			algo_offset = __be32_to_cpu(entry->offset);
			algo_offset_set = true;

			pr_debug("Found RPMTAG_FILEDIGESTALGO at offset %u\n",
				 algo_offset);
			break;
		default:
			break;
		}
	}

	if (!digests_offset_set)
		return 0;

	if (algo_offset_set) {
		if (algo_offset >= data_len)
			return -EINVAL;

		if (data_len - algo_offset < sizeof(uint32_t))
			return -EINVAL;

		pkg_pgp_algo = *(uint32_t *)&data[algo_offset];
		pkg_pgp_algo = __be32_to_cpu(pkg_pgp_algo);
		if (pkg_pgp_algo > DIGEST_ALGO_SHA224) {
			pr_debug("Unknown PGP algo %d\n", pkg_pgp_algo);
			return -EINVAL;
		}

		pkg_kernel_algo = pgp_algo_mapping[pkg_pgp_algo];
		if (pkg_kernel_algo >= HASH_ALGO__LAST) {
			pr_debug("Unknown mapping for PGP algo %d\n",
				 pkg_pgp_algo);
			return -EINVAL;
		}

		pr_debug("Found mapping for PGP algo %d: %s\n", pkg_pgp_algo,
			 hash_algo_name[pkg_kernel_algo]);
	}

	//@ merge algo_offset_set;
	//@ merge digests_offset_set;

	digest_cache->algo = pkg_kernel_algo;
	digest_len = hash_digest_size[pkg_kernel_algo];
	//@ split digest_len;

	if (digests_offset > data_len)
		return -EINVAL;

	/* Worst case, every digest is a \0. */
	max_digests_count = data_len - digests_offset;

	/* Finite termination on digests_count loop. */
	if (digests_count > max_digests_count)
		return -EINVAL;

	ret = digest_cache_htable_init(digest_cache, digests_count,
				       pkg_kernel_algo);
	if (ret < 0)
		return ret;

	/*@ loop invariant \forall integer i; 0 <= i <= digests_count ==> digests_offset <= data_len;
	  @ loop assigns i, digests_offset;
	  @ loop variant i - digests_count; */
	for (i = 0; i < digests_count; i++) {
		if (digests_offset == data_len)
			return -EINVAL;

		//@ assert \valid_read(data+digests_offset);
		if (!data[digests_offset]) {
			digests_offset++;
			continue;
		}

		if (data_len - digests_offset < digest_len * 2 + 1)
			return -EINVAL;

		//@ assert \valid_read(data+(digests_offset..digests_offset + digest_len * 2));
		//@ assert !valid_buffer || data[digests_offset] == 'A';
		write(1, &data[digests_offset], digest_len * 2 + 1);
		printf("\n");

		ret = hex2bin(rpm_digest, (const char *)&data[digests_offset],
			      digest_len);
		if (ret < 0) {
			pr_debug("Invalid hex format for digest %s\n",
				 &data[digests_offset]);
			return -EINVAL;
		}

		ret = digest_cache_htable_add(digest_cache, rpm_digest,
					      pkg_kernel_algo);
		if (ret < 0)
			return ret;

		digests_offset += digest_len * 2 + 1;
	}

	return ret;
}

void digest_list_gen_rpm_deterministic(void)
{
	struct digest_cache digest_cache = { 0 };
	char digest_str[129] = { "A" };
	unsigned char a[LENGTH], *data_ptr;
	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};
	struct rpm_hdr *hdr;
	struct rpm_entryinfo *entry;
	uint32_t tags, datasize;
	uint32_t digests_tag_idx, algo_tag_idx;
	uint32_t digests_offset, digests_count;
	uint32_t algo_offset = 0;
	uint32_t digest_len, i;
	uint32_t algo = DIGEST_ALGO_MD5, algo_data;
	uint32_t digest_str_len, offset;
	enum hash_algo kernel_algo;
	int ret __attribute__((unused));

	memset(a, 0, sizeof(a));
	memcpy(a, rpm_header_magic, sizeof(rpm_header_magic));

	hdr = (struct rpm_hdr *)a;
	tags = Frama_C_int_interval(2, 4);
	//@ split tags;

	hdr->tags = __cpu_to_be32(tags);
	datasize = LENGTH - tags * sizeof(*entry) - sizeof(*hdr);
	hdr->datasize = __cpu_to_be32(datasize);

	algo = Frama_C_int_interval(DIGEST_ALGO_MD5, DIGEST_ALGO_SHA224);
	//@ split algo;

	algo_data = __cpu_to_be32(algo);
	kernel_algo = pgp_algo_mapping[algo];

	/* Skip the reserved values. */
	if (kernel_algo >= HASH_ALGO__LAST)
		return;

	digest_len = hash_digest_size[kernel_algo];
	digest_str_len = digest_len * 2 + 1;

	digests_count = Frama_C_int_interval(0,
				(datasize - sizeof(algo) * 2) / digest_str_len);
	//@ dynamic_split digests_count;

	digests_tag_idx = Frama_C_int_interval(0, tags - 1);
	//@ dynamic_split digests_tag_idx;

	algo_tag_idx = !digests_tag_idx ? tags - 1 : 0;

	digests_offset = Frama_C_int_interval(sizeof(algo),
				datasize - (digests_count * digest_str_len));
	//@ dynamic_split digests_offset;

	data_ptr = a + sizeof(*hdr) + tags * sizeof(*entry);

	for (i = 0; i < digests_count; i++) {
		offset = digests_offset + i * digest_str_len;
		memcpy(data_ptr + offset, digest_str, digest_len * 2);
		data_ptr[offset + digest_len * 2] = '\0';
	}

	if (digests_offset >= sizeof(algo))
		algo_offset = digests_offset - sizeof(algo);
	else
		algo_offset = digests_offset + digests_count * digest_str_len;

	memcpy(data_ptr + algo_offset, &algo_data, sizeof(algo_data));

	entry = (struct rpm_entryinfo *)(a + sizeof(*hdr));
	entry[digests_tag_idx].tag = __cpu_to_be32(RPMTAG_FILEDIGESTS);
	entry[digests_tag_idx].type = __cpu_to_be32(RPM_STRING_ARRAY_TYPE);
	entry[digests_tag_idx].count = __cpu_to_be32(digests_count);
	entry[digests_tag_idx].offset = __cpu_to_be32(digests_offset);

	entry[algo_tag_idx].tag = __cpu_to_be32(RPMTAG_FILEDIGESTALGO);
	entry[algo_tag_idx].type = __cpu_to_be32(RPM_INT32_TYPE);
	entry[algo_tag_idx].count = __cpu_to_be32(1);
	entry[algo_tag_idx].offset = __cpu_to_be32(algo_offset);

	ret = digest_list_parse_rpm(&digest_cache, a, LENGTH);
	//@ assert ret == 0;
}

void digest_list_gen_rpm_non_deterministic(void)
{
	struct digest_cache digest_cache = { 0 };
	unsigned char a[LENGTH];

	Frama_C_make_unknown((char *)a, LENGTH);
	digest_list_parse_rpm(&digest_cache, a, LENGTH);
}

#ifdef TEST
int read_file(const char *path, size_t *len, unsigned char **data)
{
	struct stat st;
	int rc = 0, fd;

	if (stat(path, &st) == -1)
		return -ENOENT;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -EACCES;

	*len = st.st_size;

	*data = mmap(NULL, *len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (*data == MAP_FAILED)
		rc = -ENOMEM;

	close(fd);
	return rc;
}
#endif

//@ requires argv != NULL && \valid_read(argv+(0..argc - 1)) && \initialized(argv);
int main(int argc, char *argv[])
{
#ifndef TEST
	if (argc != 1 || !argv[0])
		return -ENOENT;

	valid_buffer = true;
	digest_list_gen_rpm_deterministic();
	valid_buffer = false;
	digest_list_gen_rpm_non_deterministic();
#else
	struct digest_cache digest_cache = { 0 };
	unsigned char *data;
	size_t data_len;
	int ret;

	if (argc != 2 || !argv[1])
		return -ENOENT;

	ret = read_file(argv[1], &data_len, &data);
	if (ret < 0)
		return ret;

	ret = digest_list_parse_rpm(&digest_cache, data, data_len);
	munmap(data, data_len);

	return ret;
#endif
}
