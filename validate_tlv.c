// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
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
#define __cpu_to_be16(x) x
#define __cpu_to_be32(x) x
#define __be16_to_cpu(x) x
#define __be32_to_cpu(x) x
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

#define pr_fmt(fmt) "digest_cache TLV PARSER: "fmt
#define pr_debug
#define kenter(FMT, ...) \
	pr_debug("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_debug("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

#define FOR_EACH_DIGEST_LIST_FIELD(DIGEST_LIST_FIELD) \
	DIGEST_LIST_FIELD(DIGEST_LIST_ALGO) \
	DIGEST_LIST_FIELD(DIGEST_LIST_NUM_ENTRIES) \
	DIGEST_LIST_FIELD(DIGEST_LIST_ENTRY) \
	DIGEST_LIST_FIELD(DIGEST_LIST_FIELD__LAST)

#define FOR_EACH_DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_FIELD) \
	DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_DIGEST) \
	DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_PATH) \
	DIGEST_LIST_ENTRY_FIELD(DIGEST_LIST_ENTRY_FIELD__LAST)

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
#define LENGTH_NON_DETERM 100

#define U32_MAX UINT32_MAX

/**
 * typedef callback - Callback after parsing TLV entry
 * @callback_data: Opaque data to supply to the data callback function
 * @field: Field identifier
 * @field_data: Field data
 * @field_len: Length of @field_data
 *
 * This callback is invoked after a TLV entry is parsed.
 *
 * Return: 0 on success, a negative value on error.
 */
typedef int (*callback)(void *callback_data, __u16 field,
			const __u8 *field_data, __u32 field_len);

/**
 * enum fields - Digest list fields
 *
 * Enumerates the digest list fields.
 */
enum digest_list_fields {
	FOR_EACH_DIGEST_LIST_FIELD(GENERATE_ENUM)
};

/**
 * enum digest_list_entry_fields - DIGEST_LIST_ENTRY fields
 *
 * Enumerates the DIGEST_LIST_ENTRY fields.
 */
enum digest_list_entry_fields {
	FOR_EACH_DIGEST_LIST_ENTRY_FIELD(GENERATE_ENUM)
};

/**
 * struct tlv_data_entry - Data entry of TLV format
 * @field: Data field identifier
 * @length: Data length
 * @data: Data
 *
 * This structure represents a TLV entry of the data part of TLV data format.
 */
struct tlv_entry {
	__u16 field;
	__u32 length;
	__u8 data[];
} __attribute__((packed));

struct digest_cache {
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

bool valid_buffer = false;

/**
 * tlv_parse - Parse TLV data
 * @callback: Callback function to call to parse the entries
 * @callback_data: Opaque data to supply to the callback function
 * @data: Data to parse
 * @data_len: Length of @data
 * @fields: Array of field strings
 * @num_fields: Number of elements of @fields
 *
 * Parse the TLV data format and call the supplied callback function for each
 * entry, passing also the opaque data pointer.
 *
 * The callback function decides how to process data depending on the field.
 *
 * Return: Zero on success, a negative value on error.
 */
/*@ requires \valid_read(data+(0..data_len-1)) && \initialized(data+(0..data_len-1)) && \valid_read(fields);
  @ terminates !data_len;
  @ assigns \nothing;
 */
int tlv_parse(callback callback, void *callback_data, const __u8 *data,
	      size_t data_len, const char **fields, __u32 num_fields)
{
	const __u8 *data_ptr = data;
	struct tlv_entry *entry;
	__u16 parsed_field;
	__u32 len;
	int ret;

	if (data_len > U32_MAX) {
		pr_debug("Data too big, size: %zd\n", data_len);
		return -E2BIG;
	}

	//@ dynamic_split data_len;
	while (data_len) {
		if (data_len < sizeof(*entry))
			return -EBADMSG;

		//@ assert \valid_read(data_ptr+(0..sizeof(*entry) - 1));
		entry = (struct tlv_entry *)data_ptr;
		data_ptr += sizeof(*entry);
		data_len -= sizeof(*entry);

		parsed_field = __be16_to_cpu(entry->field);
		if (parsed_field >= num_fields) {
			pr_debug("Invalid field %u, max: %u\n",
				 parsed_field, num_fields - 1);
			return -EBADMSG;
		}

		len = __be32_to_cpu(entry->length);

		if (data_len < len)
			return -EBADMSG;

		pr_debug("Data: field: %s, len: %u\n", fields[parsed_field],
			 len);

		if (!len)
			continue;

		//@ dynamic_split len;
		//@ assert \valid_read(data_ptr+(0..len - 1));
		ret = callback(callback_data, parsed_field, data_ptr, len);
		if (ret < 0) {
			pr_debug("Parsing of field %s failed, ret: %d\n",
				 fields[parsed_field], ret);
			return ret;
		}

		data_ptr += len;
		data_len -= len;
		//@ merge len;
	}

	if (data_len) {
		pr_debug("Excess data: %zu bytes\n", data_len);
		return -EBADMSG;
	}

	//@ merge data_len;
	return 0;
}

static const char * digest_list_fields_str[] = {
	FOR_EACH_DIGEST_LIST_FIELD(GENERATE_STRING)
};

static const char * digest_list_entry_fields_str[] = {
	FOR_EACH_DIGEST_LIST_ENTRY_FIELD(GENERATE_STRING)
};

struct tlv_callback_data {
	enum hash_algo algo;
};

/**
 * parse_digest_list_algo - Parse DIGEST_LIST_ALGO field
 * @tlv_data: Parser callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ALGO field (digest algorithm).
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
//@ requires \valid_read(field_data+(0..field_data_len - 1)) && \valid(tlv_data);
static int parse_digest_list_algo(struct tlv_callback_data *tlv_data,
				  enum digest_list_fields field,
				  const __u8 *field_data, __u32 field_data_len)
{
	__u16 algo;
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	if (field_data_len != sizeof(__u16)) {
		pr_debug("Unexpected data length %u, expected %zu\n",
			 field_data_len, sizeof(__u16));
		ret = -EBADMSG;
		goto out;
	}

	algo = __be16_to_cpu(*(__u16 *)field_data);

	if (algo >= HASH_ALGO__LAST) {
		pr_debug("Unexpected digest algo %u\n", algo);
		ret = -EBADMSG;
		goto out;
	}

	tlv_data->algo = algo;

	pr_debug("Digest algo: %s\n", hash_algo_name[algo]);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_entry_digest - Parse DIGEST_LIST_ENTRY_DIGEST field
 * @tlv_data: Parser callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ENTRY_DIGEST field (file digest).
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
//@ requires \valid_read(field_data+(0..field_data_len - 1)) && \valid(tlv_data);
static int parse_digest_list_entry_digest(struct tlv_callback_data *tlv_data,
					  enum digest_list_entry_fields field,
					  const __u8 *field_data,
					  __u32 field_data_len)
{
	int ret = 0, i;

	kenter(",%u,%u", field, field_data_len);

	if (tlv_data->algo == HASH_ALGO__LAST) {
		pr_debug("Digest algo not set\n");
		ret = -EBADMSG;
		goto out;
	}

	if (field_data_len != hash_digest_size[tlv_data->algo]) {
		pr_debug("Unexpected data length %u, expected %d\n",
			 field_data_len, hash_digest_size[tlv_data->algo]);
		ret = -EBADMSG;
		goto out;
	}

	//@ assert !valid_buffer || field_data[0] == 'A';

	//@ loop unroll hash_digest_size[tlv_data->algo];
	for (i = 0; i < hash_digest_size[tlv_data->algo]; i++)
		printf("%02x", (unsigned int)field_data[i]);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_entry_path - Parse DIGEST_LIST_ENTRY_PATH field
 * @tlv_data: Parser callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function handles the DIGEST_LIST_ENTRY_PATH field (file path). It
 * currently does not parse the data.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int parse_digest_list_entry_path(struct tlv_callback_data *tlv_data,
					enum digest_list_entry_fields field,
					const __u8 *field_data,
					__u32 field_data_len)
{
	//@ assert !valid_buffer || field_data[0] == 'B';
	kenter(",%u,%u", field, field_data_len);

	printf(" %.*s\n", (int)field_data_len, field_data);

	kleave(" = 0");
	return 0;
}

/**
 * digest_list_entry_callback - DIGEST_LIST_ENTRY callback
 * @callback_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This callback handles the fields of DIGEST_LIST_ENTRY_DATA (nested) data,
 * and calls the appropriate parser.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int digest_list_entry_callback(void *callback_data, __u16 field,
				      const __u8 *field_data,
				      __u32 field_data_len)
{
	struct tlv_callback_data *tlv_data;
	int ret;

	tlv_data = (struct tlv_callback_data *)callback_data;

	switch (field) {
	case DIGEST_LIST_ENTRY_DIGEST:
		ret = parse_digest_list_entry_digest(tlv_data, field,
						     field_data,
						     field_data_len);
		break;
	case DIGEST_LIST_ENTRY_PATH:
		ret = parse_digest_list_entry_path(tlv_data, field, field_data,
						   field_data_len);
		break;
	default:
		pr_debug("Unhandled field %s\n",
			 digest_list_entry_fields_str[field]);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

/**
 * parse_digest_list_entry - Parse DIGEST_LIST_ENTRY field
 * @tlv_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ENTRY field.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int parse_digest_list_entry(struct tlv_callback_data *tlv_data,
				   enum digest_list_fields field,
				   const __u8 *field_data, __u32 field_data_len)
{
	int ret;

	kenter(",%u,%u", field, field_data_len);

	ret = tlv_parse(digest_list_entry_callback, tlv_data, field_data,
			field_data_len, digest_list_entry_fields_str,
			DIGEST_LIST_ENTRY_FIELD__LAST);

	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_num_entries - Parse DIGEST_LIST_NUM_ENTRIES field
 * @tlv_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_NUM_ENTRIES field (digest list entries).
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int parse_digest_list_num_entries(struct tlv_callback_data *tlv_data,
					 enum digest_list_fields field,
					 const __u8 *field_data,
					 __u32 field_data_len)
{
	__u32 num_entries;
	int ret;

	kenter(",%u,%u", field, field_data_len);

	if (field_data_len != sizeof(__u32)) {
		pr_debug("Unexpected data length %u, expected %zu\n",
			 field_data_len, sizeof(__u32));
		ret = -EBADMSG;
		goto out;
	}

	num_entries = __be32_to_cpu(*(__u32 *)field_data);

	ret = 0;
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * digest_list_data_callback - DIGEST_LIST data callback
 * @callback_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This callback handles the fields of DIGEST_LIST_FILE data, and calls the
 * appropriate parser.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
//@ requires \valid_read(field_data+(0..field_data_len - 1));
static int digest_list_data_callback(void *callback_data, __u16 field,
				     const __u8 *field_data,
				     __u32 field_data_len)
{
	struct tlv_callback_data *tlv_data;
	int ret;

	tlv_data = (struct tlv_callback_data *)callback_data;

	switch (field) {
	case DIGEST_LIST_ALGO:
		ret = parse_digest_list_algo(tlv_data, field, field_data,
					     field_data_len);
		break;
	case DIGEST_LIST_NUM_ENTRIES:
		ret = parse_digest_list_num_entries(tlv_data, field, field_data,
						    field_data_len);
		break;
	case DIGEST_LIST_ENTRY:
		ret = parse_digest_list_entry(tlv_data, field, field_data,
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

/**
 * digest_list_parse_tlv - Parse a tlv digest list
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function parses a tlv digest list.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
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
static int digest_list_parse_tlv(struct digest_cache *digest_cache,
				 const __u8 *data, size_t data_len)
{
	struct tlv_callback_data tlv_data = {
		.algo = HASH_ALGO__LAST,
	};

	return tlv_parse(digest_list_data_callback, &tlv_data, data, data_len,
			 digest_list_fields_str, DIGEST_LIST_FIELD__LAST);
}

void digest_list_gen_tlv_deterministic(void)
{
	unsigned char a[LENGTH_DETERM], *a_ptr = a;
	struct tlv_entry *outer_entry, *inner_entry;
	__u32 outer_num_entries, inner_num_entries, digest_len;
	__u32 path_len, inner_total_len;
	__u32 i;
	__u16 algo;
	int ret;

	memset(a, 0, sizeof(a));

	algo = Frama_C_int_interval(HASH_ALGO_MD4, HASH_ALGO__LAST - 1);
	//@ split algo;

	digest_len = hash_digest_size[algo];

	outer_num_entries = Frama_C_int_interval(1, 3);
	//@ split outer_num_entries;

	outer_entry = (struct tlv_entry *)a_ptr;
	a_ptr += sizeof(*outer_entry);

	outer_entry->field = __cpu_to_be16(DIGEST_LIST_ALGO);
	outer_entry->length = __cpu_to_be32(sizeof(__u16));
	*(__u16 *)outer_entry->data = __cpu_to_be16(algo);

	a_ptr += sizeof(__u16);

	outer_entry = (struct tlv_entry *)a_ptr;
	a_ptr += sizeof(*outer_entry);

	outer_entry->field = __cpu_to_be16(DIGEST_LIST_NUM_ENTRIES);
	outer_entry->length = __cpu_to_be32(sizeof(__u32));
	*(__u32 *)outer_entry->data = __cpu_to_be32(outer_num_entries);

	a_ptr += sizeof(__u32);

	//@ loop unroll outer_num_entries;
	for (i = 0; i < outer_num_entries; i++) {
		outer_entry = (struct tlv_entry *)a_ptr;
		a_ptr += sizeof(*outer_entry);

		outer_entry->field = __cpu_to_be16(DIGEST_LIST_ENTRY);

		inner_num_entries = Frama_C_int_interval(1, 2);
		//@ split inner_num_entries;

		inner_entry = (struct tlv_entry *)a_ptr;
		a_ptr += sizeof(*inner_entry) + digest_len;

		inner_entry->field = __cpu_to_be16(DIGEST_LIST_ENTRY_DIGEST);
		inner_entry->length = __cpu_to_be32(digest_len);
		memset(inner_entry->data, 'A', digest_len);

		inner_total_len = sizeof(*inner_entry) + digest_len;

		if (inner_num_entries == 2) {
			inner_entry = (struct tlv_entry *)a_ptr;
			a_ptr += sizeof(*inner_entry);
			inner_total_len += sizeof(*inner_entry);

			inner_entry->field = __cpu_to_be16(DIGEST_LIST_ENTRY_PATH);
			path_len = Frama_C_int_interval(10, 12);
			//@ split path_len;

			inner_entry->length = __cpu_to_be32(path_len);

			memset(inner_entry->data, 'B', path_len);
			a_ptr += path_len;
			inner_total_len += path_len;
		}

		outer_entry->length  = __cpu_to_be32(inner_total_len);
	}

	ret = digest_list_parse_tlv(NULL, a, a_ptr - a);
	//@ assert ret == 0;
}

void digest_list_gen_tlv_non_deterministic(void)
{
	unsigned char a[LENGTH_NON_DETERM];

	Frama_C_make_unknown((char *)a, LENGTH_NON_DETERM);
	digest_list_parse_tlv(NULL, a, LENGTH_NON_DETERM);
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
	unsigned char *data;
	size_t data_len;
	int ret;

	if (argc != 2 || !argv[1])
		return -ENOENT;

	ret = read_file(argv[1], &data_len, &data);
	if (ret < 0)
		return ret;

	ret = digest_list_parse_tlv(NULL, data, data_len);
	munmap(data, data_len);

	return ret;
#endif
}
