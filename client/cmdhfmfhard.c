//-----------------------------------------------------------------------------
// Copyright (C) 2015 piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on 
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <pthread.h>
#include <math.h>
#include "proxmark3.h"
#include "cmdmain.h"
#include "ui.h"
#include "util.h"
#include "nonce2key/crapto1.h"

// uint32_t test_state_odd = 0;
// uint32_t test_state_even = 0;

#define CONFIDENCE_THRESHOLD	0.99		// Collect nonces until we are certain enough that the following brute force is successfull
#define GOOD_BYTES_REQUIRED		25


static const float p_K[257] = {		// the probability that a random nonce has a Sum Property == K 
	0.0290, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0083, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0006, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0339, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0048, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0934, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0119, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0489, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0602, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.4180, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0602, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0489, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0119, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0934, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0048, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0339, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0006, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0083, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0290 };

		
typedef struct noncelistentry {
	uint32_t nonce_enc;
	uint8_t par_enc;
	void *next;
} noncelistentry_t;

typedef struct noncelist {
	uint16_t num;
	uint16_t Sum;
	uint16_t Sum8_guess;
	uint8_t BitFlip[2];
	float Sum8_prob;
	bool updated;
	noncelistentry_t *first;
} noncelist_t;


static uint32_t cuid;
static noncelist_t nonces[256];
static uint16_t first_byte_Sum = 0;
static uint16_t first_byte_num = 0;
static uint16_t num_good_first_bytes = 0;

#define MAX_BEST_BYTES 40
static uint8_t best_first_bytes[MAX_BEST_BYTES];


typedef enum {
	EVEN_STATE = 0,
	ODD_STATE = 1
} odd_even_t;

#define STATELIST_INDEX_WIDTH 16
#define STATELIST_INDEX_SIZE (1<<STATELIST_INDEX_WIDTH)

typedef struct {
	uint32_t *states[2];
	uint32_t len[2];
	uint32_t *index[2][STATELIST_INDEX_SIZE];
} partial_indexed_statelist_t;

typedef struct {
	uint32_t *states[2];
	uint32_t len[2];
	void* next;
} statelist_t;


partial_indexed_statelist_t partial_statelist[17];
partial_indexed_statelist_t statelist_bitflip;

statelist_t *candidates = NULL;


static int add_nonce(uint32_t nonce_enc, uint8_t par_enc) 
{
	uint8_t first_byte = nonce_enc >> 24;
	noncelistentry_t *p1 = nonces[first_byte].first;
	noncelistentry_t *p2 = NULL;

	if (p1 == NULL) {			// first nonce with this 1st byte
		first_byte_num++;
		first_byte_Sum += parity((nonce_enc & 0xff000000) | (par_enc & 0x08) | 0x01); // 1st byte sum property. Note: added XOR 1
		// printf("Adding nonce 0x%08x, par_enc 0x%02x, parity(0x%08x) = %d\n", 
			// nonce_enc, 
			// par_enc, 
			// (nonce_enc & 0xff000000) | (par_enc & 0x08) |0x01, 
			// parity((nonce_enc & 0xff000000) | (par_enc & 0x08) | 0x01));
	}

	while (p1 != NULL && (p1->nonce_enc & 0x00ff0000) < (nonce_enc & 0x00ff0000)) {
		p2 = p1;
		p1 = p1->next;
	}
	
	if (p1 == NULL) { 																	// need to add at the end of the list
		if (p2 == NULL) { 			// list is empty yet. Add first entry.
			p2 = nonces[first_byte].first = malloc(sizeof(noncelistentry_t));
		} else {					// add new entry at end of existing list.
			p2 = p2->next = malloc(sizeof(noncelistentry_t));
		}
	} else if ((p1->nonce_enc & 0x00ff0000) != (nonce_enc & 0x00ff0000)) {				// found distinct 2nd byte. Need to insert.
		if (p2 == NULL) {			// need to insert at start of list
			p2 = nonces[first_byte].first = malloc(sizeof(noncelistentry_t));
		} else {
			p2 = p2->next = malloc(sizeof(noncelistentry_t));
		}
	} else {											// we have seen this 2nd byte before. Nothing to add or insert. 
		return (0);
	}

	// add or insert new data
	p2->next = p1;
	p2->nonce_enc = nonce_enc;
	p2->par_enc = par_enc;

	nonces[first_byte].num++;
	nonces[first_byte].Sum += parity((nonce_enc & 0x00ff0000) | (par_enc & 0x04) | 0x01); // 2nd byte sum property. Note: added XOR 1
	nonces[first_byte].updated = true;   // indicates that we need to recalculate the Sum(a8) probability for this first byte

	return (1);				// new nonce added
}


static uint16_t PartialSumProperty(uint32_t state, odd_even_t odd_even)
{ 
	uint16_t sum = 0;
	for (uint16_t j = 0; j < 16; j++) {
		uint32_t st = state;
		uint16_t part_sum = 0;
		if (odd_even == ODD_STATE) {
			for (uint16_t i = 0; i < 5; i++) {
				part_sum ^= filter(st);
				st = (st << 1) | ((j >> (3-i)) & 0x01) ;
			}
		} else {
			for (uint16_t i = 0; i < 4; i++) {
				st = (st << 1) | ((j >> (3-i)) & 0x01) ;
				part_sum ^= filter(st);
			}
		}
		sum += part_sum;
	}
	return sum;
}


static uint16_t SumProperty(struct Crypto1State *s)
{
	uint16_t sum_odd = PartialSumProperty(s->odd, ODD_STATE);
	uint16_t sum_even = PartialSumProperty(s->even, EVEN_STATE);
	return (sum_odd*(16-sum_even) + (16-sum_odd)*sum_even);
}


static double p_hypergeometric(uint16_t N, uint16_t K, uint16_t n, uint16_t k) 
{
	// for efficient computation we are using the recursive definition
	//						(K-k+1) * (n-k+1)
	// P(X=k) = P(X=k-1) * --------------------
	//						   k * (N-K-n+k)
	// and
	//           (N-K)*(N-K-1)*...*(N-K-n+1)
	// P(X=0) = -----------------------------
	//               N*(N-1)*...*(N-n+1)

	if (n-k > N-K || k > K) return 0.0;	// avoids log(x<=0) in calculation below
	if (k == 0) {
		// use logarithms to avoid overflow with huge factorials (double type can only hold 170!)
		double log_result = 0.0;
		for (int16_t i = N-K; i >= N-K-n+1; i--) {
			log_result += log(i);
		} 
		for (int16_t i = N; i >= N-n+1; i--) {
			log_result -= log(i);
		}
		return exp(log_result);
	} else {
		if (n-k == N-K) {	// special case. The published recursion below would fail with a divide by zero exception
			double log_result = 0.0;
			for (int16_t i = k+1; i <= n; i++) {
				log_result += log(i);
			}
			for (int16_t i = K+1; i <= N; i++) {
				log_result -= log(i);
			}
			return exp(log_result);
		} else { 			// recursion
			return (p_hypergeometric(N, K, n, k-1) * (K-k+1) * (n-k+1) / (k * (N-K-n+k)));
		}
	}
}
	
	
static float sum_probability(uint16_t K, uint16_t n, uint16_t k)
{
	const uint16_t N = 256;
	
	

		if (k > K || p_K[K] == 0.0) return 0.0;

		double p_T_is_k_when_S_is_K = p_hypergeometric(N, K, n, k);
		double p_S_is_K = p_K[K];
		double p_T_is_k = 0;
		for (uint16_t i = 0; i <= 256; i++) {
			if (p_K[i] != 0.0) {
				p_T_is_k += p_K[i] * p_hypergeometric(N, i, n, k);
			}
		}
		return(p_T_is_k_when_S_is_K * p_S_is_K / p_T_is_k);
}

		
static void Tests()
{
	printf("Tests: Partial Statelist sizes\n");
	for (uint16_t i = 0; i <= 16; i+=2) {
		printf("Partial State List Odd [%2d] has %8d entries\n", i, partial_statelist[i].len[ODD_STATE]);
	}
	for (uint16_t i = 0; i <= 16; i+=2) {
		printf("Partial State List Even	[%2d] has %8d entries\n", i, partial_statelist[i].len[EVEN_STATE]);
	}
	
 	// #define NUM_STATISTICS 100000
	// uint64_t statistics[257];
	// uint32_t statistics_odd[17];
	// uint32_t statistics_even[17];
	// struct Crypto1State cs;
	// time_t time1 = clock();

	// for (uint16_t i = 0; i < 257; i++) {
		// statistics[i] = 0;
	// }
	// for (uint16_t i = 0; i < 17; i++) {
		// statistics_odd[i] = 0;
		// statistics_even[i] = 0;
	// }
	
	// for (uint64_t i = 0; i < NUM_STATISTICS; i++) {
		// cs.odd = (rand() & 0xfff) << 12 | (rand() & 0xfff);
		// cs.even = (rand() & 0xfff) << 12 | (rand() & 0xfff);
		// uint16_t sum_property = SumProperty(&cs);
		// statistics[sum_property] += 1;
		// sum_property = PartialSumProperty(cs.even, EVEN_STATE);
		// statistics_even[sum_property]++;
		// sum_property = PartialSumProperty(cs.odd, ODD_STATE);
		// statistics_odd[sum_property]++;
		// if (i%(NUM_STATISTICS/100) == 0) printf("."); 
	// }
	
	// printf("\nTests: Calculated %d Sum properties in %0.3f seconds (%0.0f calcs/second)\n", NUM_STATISTICS, ((float)clock() - time1)/CLOCKS_PER_SEC, NUM_STATISTICS/((float)clock() - time1)*CLOCKS_PER_SEC);
	// for (uint16_t i = 0; i < 257; i++) {
		// if (statistics[i] != 0) {
			// printf("probability[%3d] = %0.5f\n", i, (float)statistics[i]/NUM_STATISTICS);
		// }
	// }
	// for (uint16_t i = 0; i <= 16; i++) {
		// if (statistics_odd[i] != 0) {
			// printf("probability odd [%2d] = %0.5f\n", i, (float)statistics_odd[i]/NUM_STATISTICS);
		// }
	// }
	// for (uint16_t i = 0; i <= 16; i++) {
		// if (statistics_odd[i] != 0) {
			// printf("probability even [%2d] = %0.5f\n", i, (float)statistics_even[i]/NUM_STATISTICS);
		// }
	// }

	// printf("Tests: Sum Probabilities based on Partial Sums\n");
	// for (uint16_t i = 0; i < 257; i++) {
		// statistics[i] = 0;
	// }
	// uint64_t num_states = 0;
	// for (uint16_t oddsum = 0; oddsum <= 16; oddsum += 2) {
		// for (uint16_t evensum = 0; evensum <= 16; evensum += 2) {
			// uint16_t sum = oddsum*(16-evensum) + (16-oddsum)*evensum;
			// statistics[sum] += (uint64_t)partial_statelist[oddsum].len[ODD_STATE] * partial_statelist[evensum].len[EVEN_STATE] * (1<<8);
			// num_states += (uint64_t)partial_statelist[oddsum].len[ODD_STATE] * partial_statelist[evensum].len[EVEN_STATE] * (1<<8);
		// }
	// }
	// printf("num_states = %lld, expected %lld\n", num_states, (1LL<<48));
	// for (uint16_t i = 0; i < 257; i++) {
		// if (statistics[i] != 0) {
			// printf("probability[%3d] = %0.5f\n", i, (float)statistics[i]/num_states);
		// }
	// }
	
	// printf("\nTests: Hypergeometric Probability for selected parameters\n");
	// printf("p_hypergeometric(256, 206, 255, 206) = %0.8f\n", p_hypergeometric(256, 206, 255, 206));
	// printf("p_hypergeometric(256, 206, 255, 205) = %0.8f\n", p_hypergeometric(256, 206, 255, 205));
	// printf("p_hypergeometric(256, 156, 1, 1) = %0.8f\n", p_hypergeometric(256, 156, 1, 1));
	// printf("p_hypergeometric(256, 156, 1, 0) = %0.8f\n", p_hypergeometric(256, 156, 1, 0));
	// printf("p_hypergeometric(256, 1, 1, 1) = %0.8f\n", p_hypergeometric(256, 1, 1, 1));
	// printf("p_hypergeometric(256, 1, 1, 0) = %0.8f\n", p_hypergeometric(256, 1, 1, 0));
	
	struct Crypto1State *pcs;
	pcs = crypto1_create(0xffffffffffff);
	printf("\nTests: for key = 0xffffffffffff:\nSum(a0) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n", 
		SumProperty(pcs), pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);
	printf("After adding best first byte 0x%02x:\nSum(a8) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		best_first_bytes[0],
		SumProperty(pcs),
		pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	//test_state_odd = pcs->odd & 0x00ffffff;
	//test_state_even = pcs->even & 0x00ffffff;
	crypto1_destroy(pcs);
	pcs = crypto1_create(0xa0a1a2a3a4a5);
	printf("Tests: for key = 0xa0a1a2a3a4a5:\nSum(a0) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		SumProperty(pcs), pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);
	printf("After adding best first byte 0x%02x:\nSum(a8) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		best_first_bytes[0],
		SumProperty(pcs),
		pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	// test_state_odd = pcs->odd & 0x00ffffff;
	// test_state_even = pcs->even & 0x00ffffff;
	crypto1_destroy(pcs);

	
	printf("\nTests: number of states with BitFlipProperty: %d, (= %1.3f%% of total states)\n", statelist_bitflip.len[0], 100.0 * statelist_bitflip.len[0] / (1<<20));

	printf("\nTests: Actual BitFlipProperties odd/even:\n");
	for (uint16_t i = 0; i < 256; i++) {
		printf("[%3d]:%c%c ", i, nonces[i].BitFlip[ODD_STATE]?'o':' ', nonces[i].BitFlip[EVEN_STATE]?'e':' ');
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	
	printf("\nTests: Best %d first bytes:\n", MAX_BEST_BYTES);
	for (uint16_t i = 0; i < MAX_BEST_BYTES; i++) {
		uint8_t best_byte = best_first_bytes[i];
		uint16_t best_num = nonces[best_byte].num;
		uint16_t best_sum = nonces[best_byte].Sum;
		uint16_t best_sum8 = nonces[best_byte].Sum8_guess;
		float confidence = nonces[best_byte].Sum8_prob;
		printf("Byte: %02x, n = %2d, k = %2d, Sum(a8): %3d, Confidence: %2.1f%%\n", best_byte, best_num, best_sum, best_sum8, confidence*100);
	}
}


static void sort_best_first_bytes(void)
{
	// find the best choice for the very first byte (b)
	float min_p_K = 1.0;
	float max_prob_min_p_K = 0.0;
	uint8_t best_byte = 0;
	for (uint16_t i = 0; i < 256; i++ ) {
		float prob1 = nonces[i].Sum8_prob;
		uint16_t sum8 = nonces[i].Sum8_guess;
		if (p_K[sum8] <= min_p_K && prob1 > CONFIDENCE_THRESHOLD) {
			if (p_K[sum8] < min_p_K) {
				min_p_K = p_K[sum8];
				best_byte = i;
				max_prob_min_p_K = prob1;
			} else if (prob1 > max_prob_min_p_K) {
				max_prob_min_p_K = prob1;
				best_byte = i;
			}
		}
	}
	best_first_bytes[0] = best_byte;
	// printf("Best Byte = 0x%02x, Sum8=%d, prob=%1.3f\n", best_byte, nonces[best_byte].Sum8_guess, nonces[best_byte].Sum8_prob);
		
	// sort the most probable guesses as following bytes (b')	
	for (uint16_t i = 0; i < 256; i++ ) {
		if (i == best_first_bytes[0]) {
			continue;
		}
		uint16_t j = 1;
		float prob1 = nonces[i].Sum8_prob;
		float prob2 = nonces[best_first_bytes[1]].Sum8_prob;
		while (prob1 < prob2 && j < MAX_BEST_BYTES-1) {
			prob2 = nonces[best_first_bytes[++j]].Sum8_prob;
		}
		if (prob1 >= prob2) {
			for (uint16_t k = MAX_BEST_BYTES-1; k > j; k--) {
				best_first_bytes[k] = best_first_bytes[k-1];
			}
			best_first_bytes[j] = i;
		}
	}
}


static uint16_t estimate_second_byte_sum(void) 
{
	for (uint16_t i = 0; i < MAX_BEST_BYTES; i++) {
		best_first_bytes[i] = 0;
	}
	
	for (uint16_t first_byte = 0; first_byte < 256; first_byte++) {
		float Sum8_prob = 0.0;
		uint16_t Sum8 = 0;
		if (nonces[first_byte].updated) {
			for (uint16_t sum = 0; sum <= 256; sum++) {
				float prob = sum_probability(sum, nonces[first_byte].num, nonces[first_byte].Sum);
				if (prob > Sum8_prob) {
					Sum8_prob = prob;
					Sum8 = sum;
				}
			}
			nonces[first_byte].Sum8_guess = Sum8;
			nonces[first_byte].Sum8_prob = Sum8_prob;
			nonces[first_byte].updated = false;
		}
	}
	
	sort_best_first_bytes();

	uint16_t num_good_nonces = 0;
	for (uint16_t i = 0; i < MAX_BEST_BYTES; i++) {
		if (nonces[best_first_bytes[i]].Sum8_prob > CONFIDENCE_THRESHOLD) {
			++num_good_nonces;
		}
	}
	
	return num_good_nonces;
}	


static int read_nonce_file(void)
{
	FILE *fnonces = NULL;
	uint8_t trgBlockNo;
	uint8_t trgKeyType;
	uint8_t read_buf[9];
	uint32_t nt_enc1, nt_enc2;
	uint8_t par_enc;
	int total_num_nonces = 0;
	
	if ((fnonces = fopen("nonces.bin","rb")) == NULL) { 
		PrintAndLog("Could not open file nonces.bin");
		return 1;
	}

	PrintAndLog("Reading nonces from file nonces.bin...");
	if (fread(read_buf, 1, 6, fnonces) == 0) {
		PrintAndLog("File reading error.");
		fclose(fnonces);
		return 1;
	}
	cuid = bytes_to_num(read_buf, 4);
	trgBlockNo = bytes_to_num(read_buf+4, 1);
	trgKeyType = bytes_to_num(read_buf+5, 1);

	while (fread(read_buf, 1, 9, fnonces) == 9) {
		nt_enc1 = bytes_to_num(read_buf, 4);
		nt_enc2 = bytes_to_num(read_buf+4, 4);
		par_enc = bytes_to_num(read_buf+8, 1);
		//printf("Encrypted nonce: %08x, encrypted_parity: %02x\n", nt_enc1, par_enc >> 4);
		//printf("Encrypted nonce: %08x, encrypted_parity: %02x\n", nt_enc2, par_enc & 0x0f);
		add_nonce(nt_enc1, par_enc >> 4);
		add_nonce(nt_enc2, par_enc & 0x0f);
		total_num_nonces += 2;
	}
	fclose(fnonces);
	PrintAndLog("Read %d nonces from file. cuid=%08x, Block=%d, Keytype=%c", total_num_nonces, cuid, trgBlockNo, trgKeyType==0?'A':'B');

	return 0;
}


int static acquire_nonces(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, bool nonce_file_write, bool slow)
{
	clock_t time1 = clock();
	bool initialize = true;
	bool field_off = false;
	bool finished = false;
	uint32_t flags = 0;
	uint8_t write_buf[9];
	uint32_t total_num_nonces = 0;
	uint32_t next_fivehundred = 500;
	uint32_t total_added_nonces = 0;
	FILE *fnonces = NULL;
	UsbCommand resp;

	printf("Acquiring nonces...\n");
	
	clearCommandBuffer();

	do {
		flags = 0;
		flags |= initialize ? 0x0001 : 0;
		flags |= slow ? 0x0002 : 0;
		flags |= field_off ? 0x0004 : 0;
		UsbCommand c = {CMD_MIFARE_ACQUIRE_ENCRYPTED_NONCES, {blockNo + keyType * 0x100, trgBlockNo + trgKeyType * 0x100, flags}};
		memcpy(c.d.asBytes, key, 6);

		SendCommand(&c);
		
		if (field_off) finished = true;
		
		if (initialize) {
			if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) return 1;
			if (resp.arg[0]) return resp.arg[0];  // error during nested_hard

			cuid = resp.arg[1];
			// PrintAndLog("Acquiring nonces for CUID 0x%08x", cuid); 
			if (nonce_file_write && fnonces == NULL) {
				if ((fnonces = fopen("nonces.bin","wb")) == NULL) { 
					PrintAndLog("Could not create file nonces.bin");
					return 3;
				}
				PrintAndLog("Writing acquired nonces to binary file nonces.bin");
				num_to_bytes(cuid, 4, write_buf);
				fwrite(write_buf, 1, 4, fnonces);
				fwrite(&trgBlockNo, 1, 1, fnonces);
				fwrite(&trgKeyType, 1, 1, fnonces);
			}
		}

		if (!initialize) {
			uint32_t nt_enc1, nt_enc2;
			uint8_t par_enc;
			uint16_t num_acquired_nonces = resp.arg[2];
			uint8_t *bufp = resp.d.asBytes;
			for (uint16_t i = 0; i < num_acquired_nonces; i+=2) {
				nt_enc1 = bytes_to_num(bufp, 4);
				nt_enc2 = bytes_to_num(bufp+4, 4);
				par_enc = bytes_to_num(bufp+8, 1);
				
				//printf("Encrypted nonce: %08x, encrypted_parity: %02x\n", nt_enc1, par_enc >> 4);
				total_added_nonces += add_nonce(nt_enc1, par_enc >> 4);
				//printf("Encrypted nonce: %08x, encrypted_parity: %02x\n", nt_enc2, par_enc & 0x0f);
				total_added_nonces += add_nonce(nt_enc2, par_enc & 0x0f);
				

				if (nonce_file_write) {
					fwrite(bufp, 1, 9, fnonces);
				}
				
				bufp += 9;
			}

			total_num_nonces += num_acquired_nonces;
		}
		
		if (first_byte_num == 256 ) {
			// printf("first_byte_num = %d, first_byte_Sum = %d\n", first_byte_num, first_byte_Sum);
			num_good_first_bytes = estimate_second_byte_sum();
			if (total_num_nonces > next_fivehundred) {
				next_fivehundred = (total_num_nonces/500+1) * 500;
				printf("Acquired %5d nonces (%5d with distinct bytes 0 and 1). Number of bytes with probability for correctly guessed Sum(a8) > %1.1f%%: %d\n",
					total_num_nonces, 
					total_added_nonces,
					CONFIDENCE_THRESHOLD * 100.0,
					num_good_first_bytes);
			}
			if (num_good_first_bytes >= GOOD_BYTES_REQUIRED) {
				field_off = true;	// switch off field with next SendCommand and then finish
			}
		}

		if (!initialize) {
			if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) return 1;
			if (resp.arg[0]) return resp.arg[0];  // error during nested_hard
		}

		initialize = false;

	} while (!finished);

	
	if (nonce_file_write) {
		fclose(fnonces);
	}
	
	PrintAndLog("Acquired a total of %d nonces in %1.1f seconds (%d nonces/minute)", 
		total_num_nonces, 
		((float)clock()-time1)/CLOCKS_PER_SEC, 
		total_num_nonces*60*CLOCKS_PER_SEC/(clock()-time1));
	
	return 0;
}


static int init_partial_statelists(void)
{
	const uint32_t sizes_odd[17] = { 125601, 0, 17607, 0, 73421, 0, 182033, 0, 248801, 0, 181737, 0, 74241, 0, 18387, 0, 126757 };
	const uint32_t sizes_even[17] = { 125723, 0, 17867, 0, 74305, 0, 178707, 0, 248801, 0, 185063, 0, 73356, 0, 18127, 0, 126634 };
	
	printf("Allocating memory for partial statelists...\n");
	for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
		for (uint16_t i = 0; i <= 16; i+=2) {
			partial_statelist[i].len[odd_even] = 0;
			uint32_t num_of_states = odd_even == ODD_STATE ? sizes_odd[i] : sizes_even[i];
			partial_statelist[i].states[odd_even] = malloc(sizeof(uint32_t) * num_of_states);  
			if (partial_statelist[i].states[odd_even] == NULL) {
				PrintAndLog("Cannot allocate enough memory. Aborting");
				return 4;
			}
			for (uint32_t j = 0; j < STATELIST_INDEX_SIZE; j++) {
				partial_statelist[i].index[odd_even][j] = NULL;
			}
		}
	}
		
	printf("Generating partial statelists...\n");
	for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
		uint32_t index = -1;
		uint32_t num_of_states = 1<<20;
		for (uint32_t state = 0; state < num_of_states; state++) {
			uint16_t sum_property = PartialSumProperty(state, odd_even);
			uint32_t *p = partial_statelist[sum_property].states[odd_even];
			p += partial_statelist[sum_property].len[odd_even];
			*p = state;
			partial_statelist[sum_property].len[odd_even]++;
			uint32_t index_mask = (STATELIST_INDEX_SIZE-1) << (20-STATELIST_INDEX_WIDTH);
			if ((state & index_mask) != index) {
				index = state & index_mask;
			}
			if (partial_statelist[sum_property].index[odd_even][index >> (20-STATELIST_INDEX_WIDTH)] == NULL) {
				partial_statelist[sum_property].index[odd_even][index >> (20-STATELIST_INDEX_WIDTH)] = p;
			}
		}
		// add End Of List markers
		for (uint16_t i = 0; i <= 16; i += 2) {
			uint32_t *p = partial_statelist[i].states[odd_even];
			p += partial_statelist[i].len[odd_even];
			*p = 0xffffffff;
		}
	}
	
	return 0;
}	
		

static void init_BitFlip_statelist(void)
{
	printf("Generating bitflip statelist...\n");
	uint32_t *p = statelist_bitflip.states[0] = malloc(sizeof(uint32_t) * 1<<20);
	uint32_t index = -1;
	uint32_t index_mask = (STATELIST_INDEX_SIZE-1) << (20-STATELIST_INDEX_WIDTH);
	for (uint32_t state = 0; state < (1 << 20); state++) {
		if (filter(state) != filter(state^1)) {
			if ((state & index_mask) != index) {
				index = state & index_mask;
			}
			if (statelist_bitflip.index[0][index >> (20-STATELIST_INDEX_WIDTH)] == NULL) {
				statelist_bitflip.index[0][index >> (20-STATELIST_INDEX_WIDTH)] = p;
			}
			*p++ = state;
		}
	}
	// set len and add End Of List marker
	statelist_bitflip.len[0] = p - statelist_bitflip.states[0];
	*p = 0xffffffff;
	statelist_bitflip.states[0] = realloc(statelist_bitflip.states[0], sizeof(uint32_t) * (statelist_bitflip.len[0] + 1));
}

		
static void add_state(statelist_t *sl, uint32_t state, odd_even_t odd_even)
{
	uint32_t *p;

	p = sl->states[odd_even];
	p += sl->len[odd_even];
	*p = state;
	sl->len[odd_even]++;
}


uint32_t *find_first_state(uint32_t state, uint32_t mask, partial_indexed_statelist_t *sl, odd_even_t odd_even)
{
	uint32_t *p = sl->index[odd_even][(state & mask) >> (20-STATELIST_INDEX_WIDTH)];		// first Bits as index

	if (p == NULL) return NULL;
	while ((*p & mask) < (state & mask)) p++;
	if (*p == 0xffffffff) return NULL;					// reached end of list, no match
	if ((*p & mask) == (state & mask)) return p;		// found a match.
	return NULL;										// no match
} 


static bool remaining_bits_match(uint8_t num_common_bits, uint8_t byte1, uint8_t byte2, uint32_t state1, uint32_t state2, odd_even_t odd_even)
{
	uint8_t j = num_common_bits;
	if (odd_even == ODD_STATE) {
		j |= 0x01;			// consider the next odd bit
	} else {
		j = (j+1) & 0xfe;	// consider the next even bit
	}
		
	while (j <= 7) {
		if (j != num_common_bits) {			// this is not the first differing bit, we need first to check if the invariant still holds
			uint32_t bit_diff = ((byte1 ^ byte2) << (17-j)) & 0x00010000;					// difference of (j-1)th bit -> bit 16
			uint32_t filter_diff = filter(state1 >> (4-j/2)) ^ filter(state2 >> (4-j/2));	// difference in filter function -> bit 0
			uint32_t mask_y12_y13 = 0x000000c0 >> (j/2);
			uint32_t state_diff = (state1 ^ state2) & mask_y12_y13;							// difference in state bits 12 and 13 -> bits 6/7 ... 4/5
			uint32_t all_diff = parity(bit_diff | state_diff | filter_diff);				// use parity function to XOR all 4 bits
			if (all_diff) {			// invariant doesn't hold any more. Accept this state.
				// if ((odd_even == ODD_STATE && state1 == test_state_odd)
					// || (odd_even == EVEN_STATE && state1 == test_state_even)) {
					// printf("remaining_bits_match(): %s test state: Invariant doesn't hold. Bytes = %02x, %02x, Common Bits=%d, Testing Bit %d, State1=0x%08x, State2=0x%08x\n", 
						// odd_even==ODD_STATE?"odd":"even", byte1, byte2, num_common_bits, j, state1, state2);
				// }
				return true;
			}
		}
		// check for validity of state candidate
		uint32_t bit_diff = ((byte1 ^ byte2) << (16-j)) & 0x00010000;						// difference of jth bit -> bit 16
		uint32_t mask_y13_y16 = 0x00000048 >> (j/2);
		uint32_t state_diff = (state1 ^ state2) & mask_y13_y16;								// difference in state bits 13 and 16 -> bits 3/6 ... 0/3
		uint32_t all_diff = parity(bit_diff | state_diff);									// use parity function to XOR all 3 bits
		if (all_diff) {				// not a valid state
			// if ((odd_even == ODD_STATE && state1 == test_state_odd)
				// || (odd_even == EVEN_STATE && state1 == test_state_even)) {
				// printf("remaining_bits_match(): %s test state: Invalid state. Bytes = %02x, %02x, Common Bits=%d, Testing Bit %d, State1=0x%08x, State2=0x%08x\n", 
					// odd_even==ODD_STATE?"odd":"even", byte1, byte2, num_common_bits, j, state1, state2);
				// printf("                        byte1^byte2: 0x%02x, bit_diff: 0x%08x, state_diff: 0x%08x, all_diff: 0x%08x\n", 
					// byte1^byte2, bit_diff, state_diff, all_diff);
			// }
			return false;
		}
		// continue checking for the next bit
		j += 2;
	} 
	
	return true;					// valid state
}


static bool all_other_first_bytes_match(uint32_t state, odd_even_t odd_even) 
{
	for (uint16_t i = 1; i < num_good_first_bytes; i++) {
		uint16_t sum_a8 = nonces[best_first_bytes[i]].Sum8_guess;
		uint8_t j = 0; // number of common bits
		uint8_t common_bits = best_first_bytes[0] ^ best_first_bytes[i];
		uint32_t mask = 0xfffffff0;
		if (odd_even == ODD_STATE) {
			while ((common_bits & 0x01) == 0 && j < 8) {
				j++;
				common_bits >>= 1;
				if (j % 2 == 0) {		// the odd bits
					mask >>= 1;
				}
			}
		} else {
			while ((common_bits & 0x01) == 0 && j < 8) {
				j++;
				common_bits >>= 1;
				if (j % 2 == 1) {		// the even bits
					mask >>= 1;
				}
			}
		}
		mask &= 0x000fffff;
		//printf("bytes 0x%02x and 0x%02x: %d common bits, mask = 0x%08x, state = 0x%08x, sum_a8 = %d", best_first_bytes[0], best_first_bytes[i], j, mask, state, sum_a8);
		bool found_match = false;
		for (uint16_t r = 0; r <= 16 && !found_match; r += 2) {
			for (uint16_t s = 0; s <= 16 && !found_match; s += 2) {
				if (r*(16-s) + (16-r)*s == sum_a8) {
					//printf("Checking byte 0x%02x for partial sum (%s) %d\n", best_first_bytes[i], odd_even==ODD_STATE?"odd":"even", odd_even==ODD_STATE?r:s);
					uint16_t part_sum_a8 = (odd_even == ODD_STATE) ? r : s;
					uint32_t *p = find_first_state(state, mask, &partial_statelist[part_sum_a8], odd_even);
					if (p != NULL) {
						while ((state & mask) == (*p & mask) && (*p != 0xffffffff)) {
							if (remaining_bits_match(j, best_first_bytes[0], best_first_bytes[i], state, (state&0x00fffff0) | *p, odd_even)) {
								found_match = true;
								// if ((odd_even == ODD_STATE && state == test_state_odd)
									// || (odd_even == EVEN_STATE && state == test_state_even)) {
									// printf("all_other_first_bytes_match(): %s test state: remaining bits matched. Bytes = %02x, %02x, Common Bits=%d, mask=0x%08x, PartSum(a8)=%d\n", 
										// odd_even==ODD_STATE?"odd":"even", best_first_bytes[0], best_first_bytes[i], j, mask, part_sum_a8);
								// }
								break;
							} else {
								// if ((odd_even == ODD_STATE && state == test_state_odd)
									// || (odd_even == EVEN_STATE && state == test_state_even)) {
									// printf("all_other_first_bytes_match(): %s test state: remaining bits didn't match. Bytes = %02x, %02x, Common Bits=%d, mask=0x%08x, PartSum(a8)=%d\n", 
										// odd_even==ODD_STATE?"odd":"even", best_first_bytes[0], best_first_bytes[i], j, mask, part_sum_a8);
								// }
							}
							p++;
						}	
					} else {
						// if ((odd_even == ODD_STATE && state == test_state_odd)
							// || (odd_even == EVEN_STATE && state == test_state_even)) {
							// printf("all_other_first_bytes_match(): %s test state: couldn't find a matching state. Bytes = %02x, %02x, Common Bits=%d, mask=0x%08x, PartSum(a8)=%d\n", 
								// odd_even==ODD_STATE?"odd":"even", best_first_bytes[0], best_first_bytes[i], j, mask, part_sum_a8);
						// }
					}		
				}
			}
		}

		if (!found_match) {
			// if ((odd_even == ODD_STATE && state == test_state_odd)
				// || (odd_even == EVEN_STATE && state == test_state_even)) {
				// printf("all_other_first_bytes_match(): %s test state: Eliminated. Bytes = %02x, %02x, Common Bits = %d\n", odd_even==ODD_STATE?"odd":"even", best_first_bytes[0], best_first_bytes[i], j);
			// }
			return false;
		}
	}	

	return true;
}


static int add_matching_states(statelist_t *candidates, uint16_t part_sum_a0, uint16_t part_sum_a8, odd_even_t odd_even)
{
	uint32_t worstcase_size = 1<<20;
	
	candidates->states[odd_even] = (uint32_t *)malloc(sizeof(uint32_t) * worstcase_size);
	if (candidates->states[odd_even] == NULL) {
		PrintAndLog("Out of memory error.\n");
		return 4;
	}
	for (uint32_t *p1 = partial_statelist[part_sum_a0].states[odd_even]; *p1 != 0xffffffff; p1++) {
		uint32_t search_mask = 0x000ffff0;
		uint32_t *p2 = find_first_state((*p1 << 4), search_mask, &partial_statelist[part_sum_a8], odd_even);
		if (p2 != NULL) {
			while (((*p1 << 4) & search_mask) == (*p2 & search_mask) && *p2 != 0xffffffff) {
				if (all_other_first_bytes_match((*p1 << 4) | *p2, odd_even)) {
					add_state(candidates, (*p1 << 4) | *p2, odd_even);
				}
				p2++;
			}
		}
		p2 = candidates->states[odd_even];
		p2 += candidates->len[odd_even];
		*p2 = 0xffffffff;
	}
	candidates->states[odd_even] = realloc(candidates->states[odd_even], sizeof(uint32_t) * (candidates->len[odd_even] + 1));

	return 0;
}


static statelist_t *add_more_candidates(statelist_t *current_candidates)
{
	statelist_t *new_candidates = NULL;
	if (current_candidates == NULL) {
		if (candidates == NULL) {
			candidates = (statelist_t *)malloc(sizeof(statelist_t));
		}
		new_candidates = candidates;
	} else {
		new_candidates = current_candidates->next = (statelist_t *)malloc(sizeof(statelist_t));
	}
	new_candidates->next = NULL;
	new_candidates->len[ODD_STATE] = 0;
	new_candidates->len[EVEN_STATE] = 0;
	new_candidates->states[ODD_STATE] = NULL;
	new_candidates->states[EVEN_STATE] = NULL;
	return new_candidates;
}


static void TestIfKeyExists(uint64_t key)
{
	struct Crypto1State *pcs;
	pcs = crypto1_create(key);
	crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);

	uint32_t state_odd = pcs->odd & 0x00ffffff;
	uint32_t state_even = pcs->even & 0x00ffffff;
	printf("Tests: searching for key %llx after first byte 0x%02x (state_odd = 0x%06x, state_even = 0x%06x) ...\n", key, best_first_bytes[0], state_odd, state_even);
	
	for (statelist_t *p = candidates; p != NULL; p = p->next) {
		uint32_t *p_odd = p->states[ODD_STATE];
		uint32_t *p_even = p->states[EVEN_STATE];
		while (*p_odd != 0xffffffff) {
			if (*p_odd == state_odd) printf("o");
			p_odd++;
		}
		while (*p_even != 0xffffffff) {
			if (*p_even == state_even) printf("e");
			p_even++;
		}
		printf("|");
	}
	printf("\n");
	crypto1_destroy(pcs);
}

	
static void generate_candidates(uint16_t sum_a0, uint16_t sum_a8)
{
	printf("Generating crypto1 state candidates... \n");
	
	statelist_t *current_candidates = NULL;
	// estimate maximum candidate states
	uint64_t maximum_states = 0;
	for (uint16_t sum_odd = 0; sum_odd <= 16; sum_odd += 2) {
		for (uint16_t sum_even = 0; sum_even <= 16; sum_even += 2) {
			if (sum_odd*(16-sum_even) + (16-sum_odd)*sum_even == sum_a0) {
				maximum_states += (uint64_t)partial_statelist[sum_odd].len[ODD_STATE] * partial_statelist[sum_even].len[EVEN_STATE] * (1<<8);
			}
		}
	}
	printf("Number of possible keys with Sum(a0) = %d: %lld (2^%1.1f)\n", sum_a0, maximum_states, log(maximum_states)/log(2.0));
	
	for (uint16_t p = 0; p <= 16; p += 2) {
		for (uint16_t q = 0; q <= 16; q += 2) {
			if (p*(16-q) + (16-p)*q == sum_a0) {
				printf("Reducing Partial Statelists (p,q) = (%d,%d) with lengths %d, %d\n", 
						p, q, partial_statelist[p].len[ODD_STATE], partial_statelist[q].len[EVEN_STATE]);
				for (uint16_t r = 0; r <= 16; r += 2) {
					for (uint16_t s = 0; s <= 16; s += 2) {
						if (r*(16-s) + (16-r)*s == sum_a8) {
							current_candidates = add_more_candidates(current_candidates);
							add_matching_states(current_candidates, p, r, ODD_STATE);
							printf("Odd state candidates: %d (2^%0.1f)\n", current_candidates->len[ODD_STATE], log(current_candidates->len[ODD_STATE])/log(2)); 
							add_matching_states(current_candidates, q, s, EVEN_STATE);
							printf("Even state candidates: %d (2^%0.1f)\n", current_candidates->len[EVEN_STATE], log(current_candidates->len[EVEN_STATE])/log(2)); 
						}
					}
				}
			}
		}
	}					

	
	maximum_states = 0;
	for (statelist_t *sl = candidates; sl != NULL; sl = sl->next) {
		maximum_states += (uint64_t)sl->len[ODD_STATE] * sl->len[EVEN_STATE];
	}
	printf("Number of remaining possible keys: %lld (2^%1.1f)\n", maximum_states, log(maximum_states)/log(2.0));

	TestIfKeyExists(0xffffffffffff);
	TestIfKeyExists(0xa0a1a2a3a4a5);
	
}


static void Check_for_FilterFlipProperties(void)
{
	printf("Checking for Filter Flip Properties...\n");

	for (uint16_t i = 0; i < 256; i++) {
		nonces[i].BitFlip[ODD_STATE] = false;
		nonces[i].BitFlip[EVEN_STATE] = false;
	}
	
	for (uint16_t i = 0; i < 256; i++) {
		uint8_t parity1 = (nonces[i].first->par_enc) >> 3;				// parity of first byte
		uint8_t parity2_odd = (nonces[i^0x80].first->par_enc) >> 3;  	// XOR 0x80 = last bit flipped
		uint8_t parity2_even = (nonces[i^0x40].first->par_enc) >> 3;	// XOR 0x40 = second last bit flipped
		
		if (parity1 == parity2_odd) {				// has Bit Flip Property for odd bits
			nonces[i].BitFlip[ODD_STATE] = true;
		} else if (parity1 == parity2_even) {		// has Bit Flip Property for even bits
			nonces[i].BitFlip[EVEN_STATE] = true;
		}
	}
}


int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, bool nonce_file_read, bool nonce_file_write, bool slow) 
{
	
	// initialize the list of nonces
	for (uint16_t i = 0; i < 256; i++) {
		nonces[i].num = 0;
		nonces[i].Sum = 0;
		nonces[i].Sum8_guess = 0;
		nonces[i].Sum8_prob = 0.0;
		nonces[i].updated = true;
		nonces[i].first = NULL;
	}
	first_byte_num = 0;
	first_byte_Sum = 0;
	num_good_first_bytes = 0;

	init_partial_statelists();
	init_BitFlip_statelist();
	
	if (nonce_file_read) {  	// use pre-acquired data from file nonces.bin
		if (read_nonce_file() != 0) {
			return 3;
		}
		num_good_first_bytes = estimate_second_byte_sum();
	} else {					// acquire nonces.
		uint16_t is_OK = acquire_nonces(blockNo, keyType, key, trgBlockNo, trgKeyType, nonce_file_write, slow);
		if (is_OK != 0) {
			return is_OK;
		}
	}

	Check_for_FilterFlipProperties();

	Tests();

	PrintAndLog("");
	PrintAndLog("Sum(a0) = %d", first_byte_Sum);
	// PrintAndLog("Best 10 first bytes: %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x",
		// best_first_bytes[0],
		// best_first_bytes[1],
		// best_first_bytes[2],
		// best_first_bytes[3],
		// best_first_bytes[4],
		// best_first_bytes[5],
		// best_first_bytes[6],
		// best_first_bytes[7],
		// best_first_bytes[8],
		// best_first_bytes[9]  );
	PrintAndLog("Number of first bytes with confidence > %2.1f%%: %d", CONFIDENCE_THRESHOLD*100.0, num_good_first_bytes);

	generate_candidates(first_byte_Sum, nonces[best_first_bytes[0]].Sum8_guess);
	
	PrintAndLog("Brute force phase not yet implemented");
	
	return 0;
}


