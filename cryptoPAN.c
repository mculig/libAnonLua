/*
 * This is a modification of the original cryptoPAN developed by Jinliang Fan
 * And presented in the paper Prefix-preserving IP address anonymization:
 * measurement-based security evaluation and a new cryptographic scheme
 *
 * CryptoPAN sources are hard to track down, but the April 17, 2002 version of panonymizer.cpp can still be found
 * in the source files for pktanon HERE: https://www.tm.uka.de/software/pktanon/download/index.html
 */

#include "cryptoPAN.h"

int cryptoPAN_init(const char *filename, char *state) {
	FILE *fp=NULL;
	FILE *random=NULL;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		//File not found. Create it!
		fp = fopen(filename, "w");
		if (fp == NULL) {
			printf("Failed to open file during cryptoPAN init!\n");
			return -1;
		}
		//Here we generate the keys
		random = fopen("/dev/urandom", "r");
		if (random == NULL) {
			printf("Failed to open /dev/urandom during cryptoPAN init!\n");
			closeFiles(2, fp, random);
			return -1;
		}
		//Read the state
		if(fread(state, STATE_SIZE, 1, random)!=1)
		{
			printf("Failed to read the required %d bytes from /dev/urandom during cryptoPAN init!\n", STATE_SIZE);
			closeFiles(2, fp, random);
			return -1;
		}
		//Write the state to file
		if(fwrite(state, STATE_SIZE, 1, fp)!=1)
		{
			printf("Failed to write state to file!");
			closeFiles(2, fp, random);
			return -1;
		}
	} else {
		//Read state from file
		if(fread(state, STATE_SIZE, 1, fp)!=1)
		{
			printf("Failed to read the required %d bytes from file during cryptoPAN init!\n", STATE_SIZE);
			closeFiles(2, fp, random);
			return -1;
		}
	}

	closeFiles(2, fp, random);
	return 1;
}

int cryptoPAN_ipv4(uint32_t orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, const unsigned char *key,
		const unsigned char *iv) {
	uint8_t rin_output[16];
	uint8_t rin_input[16];

	int len;

	uint32_t result = 0;
	uint32_t first4bytes_pad, first4bytes_input;
	int pos;

	EVP_CIPHER_CTX *ctx;

	//Initialize context
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//Disable padding. Since we're providing our own static pad. If this were on we'd end up with inconsistent output
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	//Initialize encryption
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	orig_addr = ntohl(orig_addr);

	memcpy(rin_input, m_pad, 16);
	first4bytes_pad = (((uint32_t) m_pad[0]) << 24)
			+ (((uint32_t) m_pad[1]) << 16) + (((uint32_t) m_pad[2]) << 8)
			+ (uint32_t) m_pad[3];

	// For each prefixes with length from 0 to 31, generate a bit using the Rijndael cipher,
	// which is used as a pseudorandom function here. The bits generated in every rounds
	// are combineed into a pseudorandom one-time-pad.
	for (pos = 0; pos <= 31; pos++) {

		//Padding: The most significant pos bits are taken from orig_addr. The other 128-pos
		//bits are taken from m_pad. The variables first4bytes_pad and first4bytes_input are used
		//to handle the annoying byte order problem.
		if (pos == 0) {
			first4bytes_input = first4bytes_pad;
		} else {
			first4bytes_input = ((orig_addr >> (32 - pos)) << (32 - pos))
					| ((first4bytes_pad << pos) >> pos);
		}
		rin_input[0] = (uint8_t) (first4bytes_input >> 24);
		rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
		rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
		rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

		//Encryption: The Rijndael cipher is used as pseudorandom function. During each
		//round, only the first bit of rin_output is used.
		//Here the original call to m_rin.blockEncrypt is replaced with a call to EVP_EncryptUpdate which is the
		//encryption function from OpenSSLs libcrypto.

		if (1 != EVP_EncryptUpdate(ctx, rin_output, &len, rin_input, 16)) {
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		//Combination: the bits are combined into a pseudorandom one-time-pad
		result |= (rin_output[0] >> 7) << (31 - pos);
	}
	//XOR the orginal address with the pseudorandom one-time-pad
	*anon_addr = result ^ orig_addr;
	*anon_addr = htonl(*anon_addr);

	EVP_CIPHER_CTX_free(ctx);
	return 1;
}

//This is a modification of the ipv4 version of cryptoPAN for IPv6.

int cryptoPAN_ipv6(uint32_t *orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, const unsigned char *key,
		const unsigned char *iv) {
	uint8_t rin_output[16];
	uint8_t rin_input[16];

	uint32_t result[4] = { 0, 0, 0, 0 };

	int pos;
	int inter_block_pos; //Position in the address
	int intra_block_pos; //Position within the 32-bit int
	uint32_t *rin_ptr_32 = (uint32_t *) rin_input; //32-bit rin_input;
	int i;
	int len;

	EVP_CIPHER_CTX *ctx;

	//Initialize context
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//Disable padding. Since we're providing our own static pad. If this were on we'd end up with inconsistent output
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	//Initialize encryption
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}


	ntoh_128(orig_addr);

	memcpy(rin_input, m_pad, 16);

	for (pos = 0; pos <= 127; pos++) {

		if (pos == 0) {
			//Do nothing, our buffer is fine
		} else {
			inter_block_pos = pos / 32;
			intra_block_pos = pos % 32;
			for (i = 3; i > 3-inter_block_pos; i--) {
				rin_ptr_32[i] = orig_addr[i];
			}
			rin_ptr_32[3-inter_block_pos] = (orig_addr[3-inter_block_pos]
					>> (32 - intra_block_pos)) << (32 - intra_block_pos)
					| (rin_ptr_32[3-inter_block_pos] << intra_block_pos)
							>> intra_block_pos;
		}

//		printf("Iteration %d, Buffer: ", pos);
//		for(i=0;i<16;i++)
//		printf("%x:", rin_input[i]);
//		printf("\n");

		if (1 != EVP_EncryptUpdate(ctx, rin_output, &len, rin_input, 16)) {
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}
		result[3-pos/32]|=(rin_output[0]>>7)<<(31-pos%32);
		memcpy(rin_input, m_pad, 16);
	}

	for (i = 0; i < 4; i++)
		anon_addr[i] = result[i] ^ orig_addr[i];

	hton_128(anon_addr);

	EVP_CIPHER_CTX_free(ctx);
	return 1;
}
