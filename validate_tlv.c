// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the TLV parser.
 */

/* Execute:
 * 
 * frama-c -eva -cpp-frama-c-compliant -cpp-extra-args="-I /usr/include -I /usr/include/x86_64-linux-gnu" -machdep gcc_x86_64 -eva-precision 11 -eva-split-limit 5000000 -eva-unroll-recursive-calls 30 -eva-interprocedural-splits validate_tlv.c
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
#define __cpu_to_be64(x) x
#define __be64_to_cpu(x) x
#endif
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <linux/types.h>

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
	return (rand() % (high - low + 1)) + low;
}
#endif

#define pr_fmt(fmt) "TLV DIGEST LIST: "fmt
#define pr_debug
#define kenter(FMT, ...) \
	pr_debug("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_debug("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

#define FOR_EACH_DIGEST_LIST_TYPE(DIGEST_LIST_TYPE) \
	DIGEST_LIST_TYPE(DIGEST_LIST_FILE) \
	DIGEST_LIST_TYPE(DIGEST_LIST__LAST)

#define FOR_EACH_FIELD(FIELD) \
	FIELD(DIGEST_LIST_ALGO) \
	FIELD(DIGEST_LIST_ENTRY) \
	FIELD(FIELD__LAST)

#define FOR_EACH_ENTRY_FIELD(ENTRY_FIELD) \
	ENTRY_FIELD(ENTRY_DIGEST) \
	ENTRY_FIELD(ENTRY_PATH) \
	ENTRY_FIELD(ENTRY__LAST)

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

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

#define LENGTH_DETERM 5000
#define LENGTH_NON_DETERM 140

typedef int (*parse_callback)(void *, __u64, const __u8 *, __u64);

/**
 * enum digest_list_types - Type of digest list
 *
 * Enumerates the types of digest lists to parse.
 */
enum digest_list_types {
	FOR_EACH_DIGEST_LIST_TYPE(GENERATE_ENUM)
};

/**
 * enum fields - Digest list fields
 *
 * Enumerates the digest list fields.
 */
enum digest_list_fields {
	FOR_EACH_FIELD(GENERATE_ENUM)
};

/**
 * enum entry_fields - Entry-specific fields
 *
 * Enumerates the digest list entry-specific fields.
 */
enum entry_fields {
	FOR_EACH_ENTRY_FIELD(GENERATE_ENUM)
};

/**
 * struct tlv_hdr - Header of TLV format
 * @data_type: Type of data to parse
 * @num_fields: Number of fields provided
 * @_reserved: Reserved for future use
 * @total_len: Total length of the data blob, excluding the header
 *
 * This structure represents the header of the TLV data format.
 */
struct tlv_hdr {
	__u64 data_type;
	__u64 num_fields;
	__u64 _reserved;
	__u64 total_len;
} __attribute__((packed));

/**
 * struct tlv_entry - Data entry of TLV format
 * @field: Data field identifier
 * @length: Data length
 * @data: Data
 *
 * This structure represents a TLV entry of the data part of TLV data format.
 */
struct tlv_entry {
	__u64 field;
	__u64 length;
	__u8 data[];
} __attribute__((packed));

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
	__u8 mask;
};

bool valid_buffer = false;

/**
 * tlv_parse_hdr - Parse a TLV header
 * @data: Data to parse (updated)
 * @data_len: Length of @data (updated)
 * @parsed_data_type: Parsed data type (updated)
 * @parsed_num_fields: Parsed data fields (updated)
 * @parsed_total_len: Length of parsed data part, excluding the header (updated)
 * @data_types: Array of data type strings
 * @num_data_types: Number of elements of @data_types
 *
 * Parse the header of the TLV data format, update the data pointer and length,
 * and provide the data type, number of fields and the length of that element.
 *
 * Return: Zero on success, a negative value on error.
 */
/*@ requires \valid_read(*data+(0..*data_len-1)) && \initialized(*data+(0..*data_len-1)) && \valid(parsed_data_type) && \valid(parsed_num_fields) && \valid(parsed_total_len) && \valid_read(data_types);
  @ assigns *data, *data_len, *parsed_num_fields, *parsed_total_len;
  @ ensures \valid_read(*data+(0..*data_len-1));
 */
int tlv_parse_hdr(const __u8 **data, size_t *data_len, __u64 *parsed_data_type,
		  __u64 *parsed_num_fields, __u64 *parsed_total_len,
		  const char **data_types, __u64 num_data_types)
{
	struct tlv_hdr *hdr;

	if (*data_len < sizeof(*hdr)) {
		pr_debug("Data blob too short, %lu bytes, expected %lu\n",
			 *data_len, sizeof(*hdr));
		return -EBADMSG;
	}

	hdr = (struct tlv_hdr *)*data;

	*data += sizeof(*hdr);
	*data_len -= sizeof(*hdr);

	*parsed_data_type = __be64_to_cpu(hdr->data_type);
	if (*parsed_data_type >= num_data_types) {
		pr_debug("Invalid data type %llu, max: %llu\n",
			 *parsed_data_type, num_data_types - 1);
		return -EBADMSG;
	}

	*parsed_num_fields = __be64_to_cpu(hdr->num_fields);

	if (hdr->_reserved != 0) {
		pr_debug("_reserved must be zero\n");
		return -EBADMSG;
	}

	*parsed_total_len = __be64_to_cpu(hdr->total_len);
	if (*parsed_total_len > *data_len) {
		pr_debug("Invalid total length %llu, expected: %lu\n",
			 *parsed_total_len, *data_len);
		return -EBADMSG;
	}

	pr_debug("Header: type: %s, num fields: %llu, total len: %llu\n",
		 data_types[*parsed_data_type], *parsed_num_fields,
		 *parsed_total_len);

	return 0;
}

/**
 * tlv_parse_data - Parse a TLV data
 * @callback: Callback function to call to parse the fields
 * @callback_data: Opaque data to supply to the callback function
 * @parsed_num_fields: Parsed data fields
 * @data: Data to parse
 * @data_len: Length of @data
 * @fields: Array of field strings
 * @num_fields: Number of elements of @fields
 *
 * Parse the data part of the TLV data format and call the supplied callback
 * function for each data field, passing also the opaque data pointer.
 *
 * Return: Zero on success, a negative value on error.
 */
/*@ requires \valid_read(data+(0..data_len-1)) && \initialized(data+(0..data_len-1)) && \valid_read(fields);
  @ assigns \nothing;
 */
int tlv_parse_data(parse_callback callback, void *callback_data,
		   __u64 parsed_num_fields, const __u8 *data, size_t data_len,
		   const char **fields, __u64 num_fields)
{
	const __u8 *data_ptr = data;
	struct tlv_entry *entry;
	__u64 parsed_field;
	__u64 len, i, max_parsed_num_fields;
	int ret;

	max_parsed_num_fields = data_len / sizeof(*entry);

	/* Finite termination on parsed_num_fields. */
	if (parsed_num_fields > max_parsed_num_fields)
		return -EBADMSG;

	//@ dynamic_split data_len;
	for (i = 0; i < parsed_num_fields; i++) {
		if (data_len < sizeof(*entry))
			return -EBADMSG;

		//@ assert \valid_read(data_ptr+(0..sizeof(*entry) - 1));
		entry = (struct tlv_entry *)data_ptr;
		data_ptr += sizeof(*entry);
		data_len -= sizeof(*entry);

		parsed_field = __be64_to_cpu(entry->field);
		if (parsed_field >= num_fields) {
			pr_debug("Invalid field %llu, max: %llu\n",
				 parsed_field, num_fields - 1);
			return -EBADMSG;
		}

		len = __be64_to_cpu(entry->length);

		if (data_len < len)
			return -EBADMSG;

		pr_debug("Data: field: %s, len: %llu\n", fields[parsed_field],
			 len);

		if (!len)
			continue;

		//@ dynamic_split len;

		//@ assert \valid_read(data_ptr+(0..len - 1));
		ret = callback(callback_data, parsed_field, data_ptr, len);
		if (ret < 0) {
			pr_debug("Parsing of field %s failed, ret: %d\n",
				 fields[parsed_field], ret);
			return -EBADMSG;
		}

		data_ptr += len;
		data_len -= len;
		//@ merge len;
	}

	if (data_len) {
		pr_debug("Excess data: %ld bytes\n", data_len);
		return -EBADMSG;
	}

	//@ merge data_len;

	return 0;
}

/**
 * tlv_parse - Parse data in TLV format
 * @expected_data_type: Desired data type
 * @callback: Callback function to call to parse the fields
 * @callback_data: Opaque data to supply to the callback function
 * @data: Data to parse
 * @data_len: Length of @data
 * @data_types: Array of data type strings
 * @num_data_types: Number of elements of @data_types
 * @fields: Array of field strings
 * @num_fields: Number of elements of @fields
 *
 * Parse data in TLV format and call the supplied callback function for each
 * data field, passing also the opaque data pointer.
 *
 * Return: Zero on success, a negative value on error.
 */
/*@ requires \valid_read(data+(0..data_len-1)) && \initialized(data+(0..data_len-1)) && \valid_read(fields) && \valid_read(data_types); */
int tlv_parse(__u64 expected_data_type, parse_callback callback,
	      void *callback_data, const __u8 *data, size_t data_len,
	      const char **data_types, __u64 num_data_types,
	      const char **fields, __u64 num_fields)
{
	__u64 parsed_data_type;
	__u64 parsed_num_fields;
	__u64 parsed_total_len;
	int ret = 0;

	pr_debug("Start parsing data blob, size: %ld, expected data type: %s\n",
		 data_len, data_types[expected_data_type]);

	while (data_len) {
		ret = tlv_parse_hdr(&data, &data_len, &parsed_data_type,
				    &parsed_num_fields, &parsed_total_len,
				    data_types, num_data_types);
		if (ret < 0)
			goto out;

		if (parsed_data_type == expected_data_type)
			break;

		/*
		 * tlv_parse_hdr() already checked that
		 * parsed_total_len <= data_len.
		 */
		data += parsed_total_len;
		data_len -= parsed_total_len;
	}

	if (!data_len) {
		pr_debug("Data type %s not found\n",
			 data_types[expected_data_type]);
		ret = -ENOENT;
		goto out;
	}

	ret = tlv_parse_data(callback, callback_data, parsed_num_fields, data,
			     parsed_total_len, fields, num_fields);
out:
	pr_debug("End of parsing data blob, ret: %d\n", ret);
	return ret;
}

const char *digest_list_types_str[] = {
	FOR_EACH_DIGEST_LIST_TYPE(GENERATE_STRING)
};

const char *digest_list_fields_str[] = {
	FOR_EACH_FIELD(GENERATE_STRING)
};

const char *entry_fields_str[] = {
	FOR_EACH_ENTRY_FIELD(GENERATE_STRING)
};

static int parse_digest_list_algo(struct digest_cache *digest_cache,
				  enum digest_list_fields field,
				  const __u8 *field_data, __u64 field_data_len)
{
	__u8 algo;
	int ret = 0;

	kenter(",%u,%llu", field, field_data_len);

	if (digest_cache->algo != HASH_ALGO__LAST) {
		pr_debug("Digest algorithm already set to %s\n",
			 hash_algo_name[digest_cache->algo]);
		ret = -EBADMSG;
		goto out;
	}

	if (field_data_len != sizeof(__u8)) {
		pr_debug("Unexpected data length %llu, expected %lu\n",
			 field_data_len, sizeof(__u8));
		ret = -EBADMSG;
		goto out;
	}

	algo = *field_data;

	if (algo >= HASH_ALGO__LAST) {
		pr_debug("Unexpected digest algo %u\n", algo);
		ret = -EBADMSG;
		goto out;
	}

	digest_cache->algo = algo;
	pr_debug("Digest algo: %s\n", hash_algo_name[algo]);
out:
	kleave(" = %d", ret);
	return ret;
}

//@ requires \valid_read(field_data+(0..field_data_len - 1)) && \valid(digest_cache);
static int parse_entry_digest(struct digest_cache *digest_cache,
			      enum entry_fields field, const __u8 *field_data,
			      __u64 field_data_len)
{
	int ret = 0, i;

	kenter(",%u,%llu", field, field_data_len);

	if (field_data_len != (__u64)hash_digest_size[digest_cache->algo]) {
		pr_debug("Unexpected data length %llu, expected %d\n",
			 field_data_len, hash_digest_size[digest_cache->algo]);
		ret = -EBADMSG;
		goto out;
	}

	//@ assert !valid_buffer || field_data[0] == 'A';

	printf("%s:", hash_algo_name[digest_cache->algo]);

	//@ loop unroll hash_digest_size[digest_cache->algo];
	for (i = 0; i < hash_digest_size[digest_cache->algo]; i++)
		printf("%02x", (unsigned int)field_data[i]);
out:
	kleave(" = %d", ret);
	return ret;
}

//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int parse_entry_path(struct digest_cache *digest_cache,
			    enum entry_fields field, const __u8 *field_data,
			    __u64 field_data_len)
{
	//@ assert !valid_buffer || field_data[0] == 'B';

	printf(" %.*s\n", (int)field_data_len, field_data);
	return 0;
}

//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int entry_callback(void *callback_data, __u64 field,
			  const __u8 *field_data, __u64 field_data_len)
{
	struct digest_cache *digest_cache;
	int ret;

	digest_cache = (struct digest_cache *)callback_data;

	switch (field) {
	case ENTRY_DIGEST:
		ret = parse_entry_digest(digest_cache, field, field_data,
					 field_data_len);
		break;
	case ENTRY_PATH:
		ret = parse_entry_path(digest_cache, field, field_data,
				       field_data_len);
		break;
	default:
		pr_debug("Unhandled field %s\n", entry_fields_str[field]);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int parse_digest_list_entry(struct digest_cache *digest_cache,
				   enum digest_list_fields field,
				   const __u8 *field_data, __u64 field_data_len)
{
	int ret;

	kenter(",%u,%llu", field, field_data_len);

	ret = tlv_parse(DIGEST_LIST_FILE, entry_callback, digest_cache,
			field_data, field_data_len, digest_list_types_str,
			DIGEST_LIST__LAST, entry_fields_str, ENTRY__LAST);

	kleave(" = %d", ret);
	return ret;
}

//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int digest_list_callback(void *callback_data, __u64 field,
				const __u8 *field_data, __u64 field_data_len)
{
	struct digest_cache *digest_cache;
	int ret;

	digest_cache = (struct digest_cache *)callback_data;

	switch (field) {
	case DIGEST_LIST_ALGO:
		ret = parse_digest_list_algo(digest_cache, field, field_data,
					     field_data_len);
		break;
	case DIGEST_LIST_ENTRY:
		ret = parse_digest_list_entry(digest_cache, field, field_data,
					      field_data_len);
		break;
	default:
		pr_debug("Unhandled field %s\n",
			 digest_list_fields_str[field]);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

/*@ requires \valid_read(data+(0..data_len-1)) && \initialized(data+(0..data_len-1));
  @ behavior valid_data:
  @   assumes valid_buffer == true;
  @   ensures \result == 0;
  @ behavior unknown_data:
  @   assumes valid_buffer == false;
  @   ensures \result == 0 || \result == -EINVAL || \result == -EBADMSG;
  @ complete behaviors valid_data, unknown_data;
  @ disjoint behaviors valid_data, unknown_data;
 */
int digest_list_parse_tlv(struct digest_cache *digest_cache, const __u8 *data,
			  size_t data_len)
{
	__u64 parsed_data_type;
	__u64 parsed_num_fields;
	__u64 parsed_total_len;
	int ret;

	ret = tlv_parse_hdr(&data, &data_len, &parsed_data_type,
			    &parsed_num_fields, &parsed_total_len,
			    digest_list_types_str, DIGEST_LIST__LAST);
	if (ret < 0)
		return ret;

	if (parsed_data_type != DIGEST_LIST_FILE)
		return 0;

	return tlv_parse_data(digest_list_callback, digest_cache,
			      parsed_num_fields, data, data_len,
			      digest_list_fields_str, FIELD__LAST);
}

void digest_list_gen_tlv_deterministic(void)
{
	struct digest_cache digest_cache = { .algo = HASH_ALGO__LAST };
	unsigned char a[LENGTH_DETERM], *a_ptr = a;
	struct tlv_hdr *outer_hdr = (struct tlv_hdr *)a;
	struct tlv_hdr *inner_hdr;
	struct tlv_entry *outer_entry, *inner_entry;
	__u64 outer_num_fields, inner_num_fields, digest_len;
	__u64 path_len;
	__u64 i;
	__u8 algo;
	int ret;

	memset(a, 0, sizeof(a));

	algo = Frama_C_int_interval(HASH_ALGO_MD4, HASH_ALGO__LAST - 1);
	//@ split algo;

	digest_len = hash_digest_size[algo];

	outer_hdr->data_type = __cpu_to_be64(DIGEST_LIST_FILE);
	outer_num_fields = Frama_C_int_interval(1, 3);
	//@ split outer_num_fields;

	outer_hdr->num_fields = __cpu_to_be64(outer_num_fields);
	outer_hdr->total_len = 0;

	a_ptr += sizeof(*outer_hdr);

	outer_entry = (struct tlv_entry *)a_ptr;
	a_ptr += sizeof(*outer_entry);

	outer_entry->field = __cpu_to_be64(DIGEST_LIST_ALGO);
	outer_entry->length = __cpu_to_be64(sizeof(__u8));
	outer_entry->data[0] = algo;

	a_ptr++;

	outer_hdr->total_len += sizeof(*outer_entry) + sizeof(__u8);

	//@ loop unroll outer_num_fields;
	for (i = 1; i < outer_num_fields; i++) {
		outer_entry = (struct tlv_entry *)a_ptr;
		a_ptr += sizeof(*outer_entry);

		outer_entry->field = __cpu_to_be64(DIGEST_LIST_ENTRY);
		inner_hdr = (struct tlv_hdr *)a_ptr;
		a_ptr += sizeof(*inner_hdr);

		inner_hdr->data_type = __cpu_to_be64(DIGEST_LIST_FILE);
		inner_num_fields = Frama_C_int_interval(1, 2);
		//@ split inner_num_fields;

		inner_hdr->num_fields = __cpu_to_be64(inner_num_fields);
		inner_entry = (struct tlv_entry *)(inner_hdr + 1);
		a_ptr += sizeof(*inner_entry) + digest_len;

		inner_entry->field = __cpu_to_be64(ENTRY_DIGEST);
		inner_entry->length = __cpu_to_be64(digest_len);
		memset(inner_entry->data, 'A', digest_len);

		inner_hdr->total_len = sizeof(*inner_entry) + digest_len;

		if (inner_num_fields == 2) {
			inner_entry = (struct tlv_entry *)a_ptr;
			a_ptr += sizeof(*inner_entry);

			inner_entry->field = __cpu_to_be64(ENTRY_PATH);
			path_len = Frama_C_int_interval(10, 12);
			//@ split path_len;

			inner_entry->length = __cpu_to_be64(path_len);

			memset(inner_entry->data, 'B', path_len);
			a_ptr += path_len;

			inner_hdr->total_len += sizeof(*inner_entry) + path_len;
		}

		outer_entry->length = sizeof(*inner_hdr) + inner_hdr->total_len;
		outer_hdr->total_len += sizeof(*outer_entry) + outer_entry->length;
		inner_hdr->total_len = __cpu_to_be64(inner_hdr->total_len);
		outer_entry->length  = __cpu_to_be64(outer_entry->length);
	}

	outer_hdr->total_len = __cpu_to_be64(outer_hdr->total_len);

	ret = digest_list_parse_tlv(&digest_cache, a, a_ptr - a);
	//@ assert ret == 0;
}

void digest_list_gen_tlv_non_deterministic(void)
{
	struct digest_cache digest_cache = { 0 };
	unsigned char a[LENGTH_NON_DETERM];

	Frama_C_make_unknown((char *)a, LENGTH_NON_DETERM);
	digest_list_parse_tlv(&digest_cache, a, LENGTH_NON_DETERM);
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

#ifndef TEST
int main(void)
{
	valid_buffer = true;
	digest_list_gen_tlv_deterministic();
	valid_buffer = false;
	digest_list_gen_tlv_non_deterministic();
#else
int main(int argc, char *argv[])
{
	struct digest_cache digest_cache = { .algo = HASH_ALGO__LAST };
	unsigned char *data;
	size_t data_len;
	int ret;

	if (argc != 2 || !argv[1])
		return -ENOENT;

	ret = read_file(argv[1], &data_len, &data);
	if (ret < 0)
		return ret;

	ret = digest_list_parse_tlv(&digest_cache, data, data_len);
	munmap(data, data_len);

	return ret;
#endif
}
