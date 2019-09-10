/*
 * This is a modification of the original cryptoPAN developed by Jinliang Fan
 * And presented in the paper Prefix-preserving IP address anonymization:
 * measurement-based security evaluation and a new cryptographic scheme
 *
 * CryptoPAN sources are hard to track down, but the April 17, 2002 version of panonymizer.cpp can still be found
 * in the source files for pktanon HERE: https://www.tm.uka.de/software/pktanon/download/index.html
 */

#include "cryptoPAN.h"

void cryptoPAN_ipv4(uint32_t orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, EVP_CIPHER_CTX *ctx) {
	uint8_t rin_output[16];
	uint8_t rin_input[16];

	int len;

	uint32_t result = 0;
	uint32_t first4bytes_pad, first4bytes_input;
	int pos;

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

		EVP_EncryptUpdate(ctx, rin_output, &len, rin_input, 16);

		//Combination: the bits are combined into a pseudorandom one-time-pad
		result |= (rin_output[0] >> 7) << (31 - pos);
	}
	//XOR the orginal address with the pseudorandom one-time-pad
	*anon_addr = result ^ orig_addr;
	*anon_addr = htonl(*anon_addr);
}

//Switch a 128-bit address to host order
void ntoh_128(uint32_t *address) {
	int i;
	uint8_t byte_buffer;
	uint8_t *addr;
	uint16_t test = 0x0102;
	uint8_t *testptr;

	testptr = (uint8_t *) &test;

	if (testptr[0] == 0x01) //Endianness test. See which byte was written first
		return;

	addr = (uint8_t *) address;

	for (i = 0; i < 8; i++) {
		byte_buffer = addr[i];
		addr[i] = addr[15 - i];
		addr[15 - i] = byte_buffer;
	}
}
//These functions are the same. Even arpa/inet does it this way which can be seen in arpa/inet.c source
void hton_128(uint32_t *address) {
	ntoh_128(address);
}

//This is a modification of the ipv4 version of cryptoPAN for IPv6.

void cryptoPAN_ipv6(uint32_t *orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, EVP_CIPHER_CTX *ctx) {
	uint8_t rin_output[16];
	uint8_t rin_input[16];

	uint32_t result[4]={0,0,0,0};

	uint32_t tmp;

	int pos;
	int len;

	ntoh_128(orig_addr);

	memcpy(rin_input, m_pad, 16);

	for (pos = 0; pos <= 127; pos++) {

		if (pos == 0) {
			//Do nothing, rin_input is already equal to the pad
		} else {
			//Here we handle all other cases
			switch (pos / 32) {
			case 3:
				tmp=(orig_addr[3]>>(128-pos))<<(128-pos);
				rin_input[12]|=tmp>>24;
				rin_input[13]|=(tmp<<8)>>24;
				rin_input[14]|=(tmp<<16)>>24;
				rin_input[15]|=(tmp<<24)>>24;
				//No break here on purpose to utilize fallthrough! IDEs may cry but this is valid code!
			case 2:
				if(pos>=96)
					tmp=0;
				else
					tmp=(orig_addr[2]>>(96-pos))<<(96-pos);
				rin_input[8]|=tmp>>24;
				rin_input[9]|=(tmp<<8)>>24;
				rin_input[10]|=(tmp<<16)>>24;
				rin_input[11]|=(tmp<<24)>>24;
				//No break here on purpose to utilize fallthrough! IDEs may cry but this is valid code!
			case 1:
				if(pos>=64)
					tmp=0;
				else
					tmp=(orig_addr[1]>>(64-pos))<<(64-pos);
				rin_input[4]|=tmp>>24;
				rin_input[5]|=(tmp<<8)>>24;
				rin_input[6]|=(tmp<<16)>>24;
				rin_input[7]|=(tmp<<24)>>24;
				//No break here on purpose to utilize fallthrough! IDEs may cry but this is valid code!
			case 0:
				if(pos>=32)
					tmp=0;
				else
					tmp=(orig_addr[0]>>(32-pos))<<(32-pos);
				rin_input[0]|=tmp>>24;
				rin_input[1]|=(tmp<<8)>>24;
				rin_input[2]|=(tmp<<16)>>24;
				rin_input[3]|=(tmp<<24)>>24;
				break;
			}
		}

		EVP_EncryptUpdate(ctx, rin_output, &len, rin_input, 16);
		memcpy(rin_input, m_pad, 16);

		result[pos/32] |= ((uint32_t)(rin_output[0]>>7))<<(pos%32);
	}

	for(int i=0;i<4;i++)
		anon_addr[i] = result[i] ^ orig_addr[i];

	hton_128(anon_addr);
}
