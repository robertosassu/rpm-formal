#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <asm/byteorder.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>

#ifndef TEST
#include "__fc_builtin.h"
#endif

#define RPMTAG_FILEDIGESTS 1035
#define RPMTAG_FILEDIGESTALGO 5011

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

#define LENGTH 1000

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

/*@ requires \valid_read(data+(0..data_len-1)) && \initialized(data+(0..data_len-1));
 */
int digest_list_parse_rpm(const unsigned char *data, unsigned int data_len)
{
	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};
	const struct rpm_hdr *hdr;
	const struct rpm_entryinfo *entry;
	uint32_t tags, max_tags;
	uint32_t digests_count, max_digests_count;
	uint32_t digests_offset, algo_offset;
	uint32_t digest_len, pkg_pgp_algo, i;
	bool algo_offset_set = false, digests_offset_set = false;
	enum hash_algo pkg_kernel_algo = HASH_ALGO_MD5;
	unsigned int hdr_data_len;
	const unsigned char *hdr_data;

	//@ assert data_len >= sizeof(*hdr);
	if (data_len < sizeof(*hdr))
		return -EINVAL;

	for (i = 0; i < sizeof(rpm_header_magic); i++) {
		if (data[i] != rpm_header_magic[i])
			return -EINVAL;
	}

	hdr = (const struct rpm_hdr *)data;
	data += sizeof(*hdr);
	data_len -= sizeof(*hdr);

	tags = __be32_to_cpu(hdr->tags);
	max_tags = data_len / sizeof(*entry);

	/* Finite termination on tags loop. */
	if (tags > max_tags)
		return -EINVAL;

	/*@ loop unroll tags; */
	for (i = 0; i < tags; i++) {
		if (data_len < sizeof(*entry))
			return -EINVAL;

		entry = (const struct rpm_entryinfo *)data;
		data += sizeof(*entry);
		data_len -= sizeof(*entry);

		switch (__be32_to_cpu(entry->tag)) {
		case RPMTAG_FILEDIGESTS:
			digests_offset = __be32_to_cpu(entry->offset);
			digests_count = __be32_to_cpu(entry->count);
			digests_offset_set = true;
			break;
		case RPMTAG_FILEDIGESTALGO:
			algo_offset = __be32_to_cpu(entry->offset);
			algo_offset_set = true;
			break;
		default:
			break;
		}
	}

	hdr_data = data;
	hdr_data_len = data_len;

	if (!digests_offset_set)
		return -EINVAL;

	if (algo_offset_set) {
		if (algo_offset >= hdr_data_len)
			return -EINVAL;

		if (hdr_data_len - algo_offset < sizeof(uint32_t))
			return -EINVAL;

		pkg_pgp_algo = *(uint32_t *)&hdr_data[algo_offset];
		pkg_pgp_algo = __be32_to_cpu(pkg_pgp_algo);
		if (pkg_pgp_algo > DIGEST_ALGO_SHA224)
			return -EINVAL;

		pkg_kernel_algo = pgp_algo_mapping[pkg_pgp_algo];
		if (pkg_kernel_algo >= HASH_ALGO__LAST)
			return -EINVAL;
	}

	/* It does not work, I have to put a fixed value (e.g. 32). */
 	digest_len = hash_digest_size[pkg_kernel_algo];

	if (digests_offset >= hdr_data_len)
		return -EINVAL;

	/* Worst case, every digest is a \0. */
	max_digests_count = hdr_data_len - digests_offset;

	/* Finite termination on digests_count loop. */
	if (digests_count > max_digests_count)
		return -EINVAL;

	/*@ loop invariant \forall integer i; 0 <= i <= digests_count ==> digests_offset <= hdr_data_len;
	  @ loop assigns i, digests_offset;
	  @ loop unroll digests_count;
	  @ loop variant i - digests_count; */
	for (i = 0; i < digests_count; i++) {
		if (digests_offset == hdr_data_len)
			return -EINVAL;

		if (!hdr_data[digests_offset]) {
			digests_offset++;
			continue;
		}

		if (hdr_data_len - digests_offset < digest_len * 2 + 1)
			return -EINVAL;

		write(1, &hdr_data[digests_offset], digest_len * 2 + 1);
		printf("\n");

		digests_offset += digest_len * 2 + 1;
	}

	return 0;
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

int main(int argc, char *argv[])
{
#ifndef TEST
	unsigned char a[LENGTH];
	int i;

	for (i = 0; i < LENGTH; i++) a[i] = Frama_C_unsigned_char_interval(0, 255);

	return digest_list_parse_rpm(a, sizeof(a));
#else
	unsigned char *data;
	size_t data_len;
	int ret;

	if (argc != 2 || !argv[1])
		return -ENOENT;

	ret = read_file(argv[1], &data_len, &data);
	if (ret < 0)
		return ret;

	ret = digest_list_parse_rpm(data, data_len);
	munmap(data, data_len);

	return ret;
#endif
}
