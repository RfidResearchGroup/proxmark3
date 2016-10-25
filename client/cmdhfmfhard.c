//-----------------------------------------------------------------------------
// Copyright (C) 2015 piwi
// fiddled with 2016 Azcid (hardnested bitsliced Bruteforce imp)
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
#include "cmdhfmfhard.h"

#define CONFIDENCE_THRESHOLD	0.95		// Collect nonces until we are certain enough that the following brute force is successfull
#define GOOD_BYTES_REQUIRED	13		// default 28, could be smaller == faster
#define MIN_NONCES_REQUIRED	4000		// 4000-5000 could be good
#define NONCES_TRIGGER		2500		// every 2500 nonces check if we can crack the key
#define CRACKING_THRESHOLD	39.00f		// as 2^39

#define END_OF_LIST_MARKER		0xFFFFFFFF

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
	float score1, score2;
} noncelist_t;

static size_t nonces_to_bruteforce = 0;
static noncelistentry_t *brute_force_nonces[256];
static uint32_t cuid = 0;
static noncelist_t nonces[256];
static uint8_t best_first_bytes[256];
static uint16_t first_byte_Sum = 0;
static uint16_t first_byte_num = 0;
static uint16_t num_good_first_bytes = 0;
static uint64_t maximum_states = 0;
static uint64_t known_target_key;
static bool write_stats = false;
static FILE *fstats = NULL;


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


static partial_indexed_statelist_t partial_statelist[17];
static partial_indexed_statelist_t statelist_bitflip;
static statelist_t *candidates = NULL;

bool thread_check_started = false;
bool thread_check_done = false;
bool field_off = false;

pthread_t thread_check;

static void* check_thread();
static bool generate_candidates(uint16_t, uint16_t);
static bool brute_force(void);

static int add_nonce(uint32_t nonce_enc, uint8_t par_enc) 
{
	uint8_t first_byte = nonce_enc >> 24;
	noncelistentry_t *p1 = nonces[first_byte].first;
	noncelistentry_t *p2 = NULL;

	if (p1 == NULL) {			// first nonce with this 1st byte
		first_byte_num++;
		first_byte_Sum += evenparity32((nonce_enc & 0xff000000) | (par_enc & 0x08));
		// printf("Adding nonce 0x%08x, par_enc 0x%02x, parity(0x%08x) = %d\n", 
			// nonce_enc, 
			// par_enc, 
			// (nonce_enc & 0xff000000) | (par_enc & 0x08) |0x01, 
			// parity((nonce_enc & 0xff000000) | (par_enc & 0x08));
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

    if(nonces_to_bruteforce < 256){
        brute_force_nonces[nonces_to_bruteforce] = p2;
        nonces_to_bruteforce++;
    }

	nonces[first_byte].num++;
	nonces[first_byte].Sum += evenparity32((nonce_enc & 0x00ff0000) | (par_enc & 0x04));
	nonces[first_byte].updated = true;   // indicates that we need to recalculate the Sum(a8) probability for this first byte

	return (1);				// new nonce added
}

static void init_nonce_memory(void)
{
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
}

static void free_nonce_list(noncelistentry_t *p)
{
	if (p == NULL) {
		return;
	} else {
		free_nonce_list(p->next);
		free(p);
	}
}

static void free_nonces_memory(void)
{
	for (uint16_t i = 0; i < 256; i++) {
		free_nonce_list(nonces[i].first);
	}
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
			part_sum ^= 1;		// XOR 1 cancelled out for the other 8 bits
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

// static uint16_t SumProperty(struct Crypto1State *s)
// {
	// uint16_t sum_odd = PartialSumProperty(s->odd, ODD_STATE);
	// uint16_t sum_even = PartialSumProperty(s->even, EVEN_STATE);
	// return (sum_odd*(16-sum_even) + (16-sum_odd)*sum_even);
// }

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

	
static inline uint_fast8_t common_bits(uint_fast8_t bytes_diff) 
{
	static const uint_fast8_t common_bits_LUT[256] = {
		8, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		5, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		6, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		5, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		7, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		5, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		6, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		5, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0,
		4, 0, 1, 0, 2, 0, 1, 0,	3, 0, 1, 0, 2, 0, 1, 0
	};

	return common_bits_LUT[bytes_diff];
}

static void Tests()
{
	// printf("Tests: Partial Statelist sizes\n");
	// for (uint16_t i = 0; i <= 16; i+=2) {
		// printf("Partial State List Odd [%2d] has %8d entries\n", i, partial_statelist[i].len[ODD_STATE]);
	// }
	// for (uint16_t i = 0; i <= 16; i+=2) {
		// printf("Partial State List Even	[%2d] has %8d entries\n", i, partial_statelist[i].len[EVEN_STATE]);
	// }
	
 	// #define NUM_STATISTICS 100000
	// uint32_t statistics_odd[17];
	// uint64_t statistics[257];
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
	
	// struct Crypto1State *pcs;
	// pcs = crypto1_create(0xffffffffffff);
	// printf("\nTests: for key = 0xffffffffffff:\nSum(a0) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n", 
		// SumProperty(pcs), pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	// crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);
	// printf("After adding best first byte 0x%02x:\nSum(a8) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		// best_first_bytes[0],
		// SumProperty(pcs),
		// pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	// //test_state_odd = pcs->odd & 0x00ffffff;
	// //test_state_even = pcs->even & 0x00ffffff;
	// crypto1_destroy(pcs);
	// pcs = crypto1_create(0xa0a1a2a3a4a5);
	// printf("Tests: for key = 0xa0a1a2a3a4a5:\nSum(a0) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		// SumProperty(pcs), pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	// crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);
	// printf("After adding best first byte 0x%02x:\nSum(a8) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		// best_first_bytes[0],
		// SumProperty(pcs),
		// pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	// //test_state_odd = pcs->odd & 0x00ffffff;
	// //test_state_even = pcs->even & 0x00ffffff;
	// crypto1_destroy(pcs);
	// pcs = crypto1_create(0xa6b9aa97b955);
	// printf("Tests: for key = 0xa6b9aa97b955:\nSum(a0) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		// SumProperty(pcs), pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	// crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);
	// printf("After adding best first byte 0x%02x:\nSum(a8) = %d\nodd_state =  0x%06x\neven_state = 0x%06x\n",
		// best_first_bytes[0],
		// SumProperty(pcs),
		// pcs->odd & 0x00ffffff, pcs->even & 0x00ffffff);
	//test_state_odd = pcs->odd & 0x00ffffff;
	//test_state_even = pcs->even & 0x00ffffff;
	// crypto1_destroy(pcs);

	
	// printf("\nTests: number of states with BitFlipProperty: %d, (= %1.3f%% of total states)\n", statelist_bitflip.len[0], 100.0 * statelist_bitflip.len[0] / (1<<20));

	// printf("\nTests: Actual BitFlipProperties odd/even:\n");
	// for (uint16_t i = 0; i < 256; i++) {
		// printf("[%02x]:%c  ", i, nonces[i].BitFlip[ODD_STATE]?'o':nonces[i].BitFlip[EVEN_STATE]?'e':' ');
		// if (i % 8 == 7) {
			// printf("\n");
		// }
	// }
	
	// printf("\nTests: Sorted First Bytes:\n");
	// for (uint16_t i = 0; i < 256; i++) {
		// uint8_t best_byte = best_first_bytes[i];
		// printf("#%03d Byte: %02x, n = %3d, k = %3d, Sum(a8): %3d, Confidence: %5.1f%%, Bitflip: %c\n", 
		// //printf("#%03d Byte: %02x, n = %3d, k = %3d, Sum(a8): %3d, Confidence: %5.1f%%, Bitflip: %c, score1: %1.5f, score2: %1.0f\n", 
			// i, best_byte, 
			// nonces[best_byte].num,
			// nonces[best_byte].Sum,
			// nonces[best_byte].Sum8_guess,
			// nonces[best_byte].Sum8_prob * 100,
			// nonces[best_byte].BitFlip[ODD_STATE]?'o':nonces[best_byte].BitFlip[EVEN_STATE]?'e':' '
			// //nonces[best_byte].score1,
			// //nonces[best_byte].score2
			// );
	// }
	
	// printf("\nTests: parity performance\n");
	// time_t time1p = clock();
	// uint32_t par_sum = 0;
	// for (uint32_t i = 0; i < 100000000; i++) {
		// par_sum += parity(i);
	// }
	// printf("parsum oldparity = %d, time = %1.5fsec\n", par_sum, (float)(clock() - time1p)/CLOCKS_PER_SEC);

	// time1p = clock();
	// par_sum = 0;
	// for (uint32_t i = 0; i < 100000000; i++) {
		// par_sum += evenparity32(i);
	// }
	// printf("parsum newparity = %d, time = %1.5fsec\n", par_sum, (float)(clock() - time1p)/CLOCKS_PER_SEC);


}

static void sort_best_first_bytes(void)
{
	// sort based on probability for correct guess	
	for (uint16_t i = 0; i < 256; i++ ) {
		uint16_t j = 0;
		float prob1 = nonces[i].Sum8_prob;
		float prob2 = nonces[best_first_bytes[0]].Sum8_prob;
		while (prob1 < prob2 && j < i) {
			prob2 = nonces[best_first_bytes[++j]].Sum8_prob;
		}
		if (j < i) {
			for (uint16_t k = i; k > j; k--) {
				best_first_bytes[k] = best_first_bytes[k-1];
			}
		}
			best_first_bytes[j] = i;
		}

	// determine how many are above the CONFIDENCE_THRESHOLD
	uint16_t num_good_nonces = 0;
	for (uint16_t i = 0; i < 256; i++) {
		if (nonces[best_first_bytes[i]].Sum8_prob >= CONFIDENCE_THRESHOLD) {
			++num_good_nonces;
		}
	}
	
	uint16_t best_first_byte = 0;

	// select the best possible first byte based on number of common bits with all {b'}
	// uint16_t max_common_bits = 0;
	// for (uint16_t i = 0; i < num_good_nonces; i++) {
		// uint16_t sum_common_bits = 0;
		// for (uint16_t j = 0; j < num_good_nonces; j++) {
			// if (i != j) {
				// sum_common_bits += common_bits(best_first_bytes[i],best_first_bytes[j]);
			// }
		// }
		// if (sum_common_bits > max_common_bits) {
			// max_common_bits = sum_common_bits;
			// best_first_byte = i;
		// }
	// }

	// select best possible first byte {b} based on least likely sum/bitflip property
	float min_p_K = 1.0;
	for (uint16_t i = 0; i < num_good_nonces; i++ ) {
		uint16_t sum8 = nonces[best_first_bytes[i]].Sum8_guess;
		float bitflip_prob = 1.0;
		if (nonces[best_first_bytes[i]].BitFlip[ODD_STATE] || nonces[best_first_bytes[i]].BitFlip[EVEN_STATE]) {
			bitflip_prob = 0.09375;
		}
		nonces[best_first_bytes[i]].score1 = p_K[sum8] * bitflip_prob;
		if (p_K[sum8] * bitflip_prob <= min_p_K) {
			min_p_K = p_K[sum8] * bitflip_prob;
		}
	}


	// use number of commmon bits as a tie breaker
	uint16_t max_common_bits = 0;
	for (uint16_t i = 0; i < num_good_nonces; i++) {
		float bitflip_prob = 1.0;
		if (nonces[best_first_bytes[i]].BitFlip[ODD_STATE] || nonces[best_first_bytes[i]].BitFlip[EVEN_STATE]) {
			bitflip_prob = 0.09375;
		}
		if (p_K[nonces[best_first_bytes[i]].Sum8_guess] * bitflip_prob == min_p_K) {
			uint16_t sum_common_bits = 0;
			for (uint16_t j = 0; j < num_good_nonces; j++) {
				sum_common_bits += common_bits(best_first_bytes[i] ^ best_first_bytes[j]);
			}
			nonces[best_first_bytes[i]].score2 = sum_common_bits;
			if (sum_common_bits > max_common_bits) {
				max_common_bits = sum_common_bits;
				best_first_byte = i;
			}
		}
	}	

	// swap best possible first byte to the pole position
	uint16_t temp = best_first_bytes[0];
	best_first_bytes[0] = best_first_bytes[best_first_byte];
	best_first_bytes[best_first_byte] = temp;
	
}

static uint16_t estimate_second_byte_sum(void) 
{
	
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
	for (uint16_t i = 0; i < 256; i++) {
		if (nonces[best_first_bytes[i]].Sum8_prob >= CONFIDENCE_THRESHOLD) {
			++num_good_nonces;
		}
	}
	
	return num_good_nonces;
}	

static int read_nonce_file(void)
{
	FILE *fnonces = NULL;
	uint8_t trgBlockNo = 0;
	uint8_t trgKeyType = 0;
	uint8_t read_buf[9];
	uint32_t nt_enc1 = 0, nt_enc2 = 0;
	uint8_t par_enc = 0;
	int total_num_nonces = 0;
	
	if ((fnonces = fopen("nonces.bin","rb")) == NULL) { 
		PrintAndLog("Could not open file nonces.bin");
		return 1;
	}

	PrintAndLog("Reading nonces from file nonces.bin...");
	size_t bytes_read = fread(read_buf, 1, 6, fnonces);
	if ( bytes_read == 0) {
		PrintAndLog("File reading error.");
		fclose(fnonces);
		fnonces = NULL;
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
	fnonces = NULL;
	PrintAndLog("Read %d nonces from file. cuid=%08x, Block=%d, Keytype=%c", total_num_nonces, cuid, trgBlockNo, trgKeyType==0?'A':'B');
	return 0;
}

static void Check_for_FilterFlipProperties(void)
{
	printf("Checking for Filter Flip Properties...\n");

	uint16_t num_bitflips = 0;
	
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
			num_bitflips++;
		} else if (parity1 == parity2_even) {		// has Bit Flip Property for even bits
			nonces[i].BitFlip[EVEN_STATE] = true;
			num_bitflips++;
		}
	}
	
	if (write_stats) {
		fprintf(fstats, "%d;", num_bitflips);
	}
}

static void simulate_MFplus_RNG(uint32_t test_cuid, uint64_t test_key, uint32_t *nt_enc, uint8_t *par_enc)
{
	struct Crypto1State sim_cs = {0, 0};
	// init cryptostate with key:
	for(int8_t i = 47; i > 0; i -= 2) {
		sim_cs.odd  = sim_cs.odd  << 1 | BIT(test_key, (i - 1) ^ 7);
		sim_cs.even = sim_cs.even << 1 | BIT(test_key, i ^ 7);
	}

	*par_enc = 0;
	uint32_t nt = (rand() & 0xff) << 24 | (rand() & 0xff) << 16 | (rand() & 0xff) << 8 | (rand() & 0xff);
	for (int8_t byte_pos = 3; byte_pos >= 0; byte_pos--) {
		uint8_t nt_byte_dec = (nt >> (8*byte_pos)) & 0xff;
		uint8_t nt_byte_enc = crypto1_byte(&sim_cs, nt_byte_dec ^ (test_cuid >> (8*byte_pos)), false) ^ nt_byte_dec; 	// encode the nonce byte
		*nt_enc = (*nt_enc << 8) | nt_byte_enc;		
		uint8_t ks_par = filter(sim_cs.odd);											// the keystream bit to encode/decode the parity bit
		uint8_t nt_byte_par_enc = ks_par ^ oddparity8(nt_byte_dec);						// determine the nt byte's parity and encode it
		*par_enc = (*par_enc << 1) | nt_byte_par_enc;
	}
	
}

static void simulate_acquire_nonces()
{
	clock_t time1 = clock();
	bool filter_flip_checked = false;
	uint32_t total_num_nonces = 0;
	uint32_t next_fivehundred = 500;
	uint32_t total_added_nonces = 0;

	cuid = (rand() & 0xff) << 24 | (rand() & 0xff) << 16 | (rand() & 0xff) << 8 | (rand() & 0xff);
	known_target_key = ((uint64_t)rand() & 0xfff) << 36 | ((uint64_t)rand() & 0xfff) << 24 | ((uint64_t)rand() & 0xfff) << 12 | ((uint64_t)rand() & 0xfff);
	
	printf("Simulating nonce acquisition for target key %012"llx", cuid %08x ...\n", known_target_key, cuid);
	fprintf(fstats, "%012"llx";%08x;", known_target_key, cuid);
	
	do {
		uint32_t nt_enc = 0;
		uint8_t par_enc = 0;

		simulate_MFplus_RNG(cuid, known_target_key, &nt_enc, &par_enc);
		//printf("Simulated RNG: nt_enc1: %08x, nt_enc2: %08x, par_enc: %02x\n", nt_enc1, nt_enc2, par_enc);
		total_added_nonces += add_nonce(nt_enc, par_enc);
		total_num_nonces++;
		
		if (first_byte_num == 256 ) {
			// printf("first_byte_num = %d, first_byte_Sum = %d\n", first_byte_num, first_byte_Sum);
			if (!filter_flip_checked) {
				Check_for_FilterFlipProperties();
				filter_flip_checked = true;
			}
			num_good_first_bytes = estimate_second_byte_sum();
			if (total_num_nonces > next_fivehundred) {
				next_fivehundred = (total_num_nonces/500+1) * 500;
				printf("Acquired %5d nonces (%5d with distinct bytes 0 and 1). Number of bytes with probability for correctly guessed Sum(a8) > %1.1f%%: %d\n",
					total_num_nonces, 
					total_added_nonces,
					CONFIDENCE_THRESHOLD * 100.0,
					num_good_first_bytes);
			}
		}

	} while (num_good_first_bytes < GOOD_BYTES_REQUIRED);
	
	time1 = clock() - time1;
	if ( time1 > 0 ) {
	PrintAndLog("Acquired a total of %d nonces in %1.1f seconds (%0.0f nonces/minute)", 
		total_num_nonces, 
		((float)time1)/CLOCKS_PER_SEC, 
		total_num_nonces * 60.0 * CLOCKS_PER_SEC/(float)time1);
	}
	fprintf(fstats, "%d;%d;%d;%1.2f;", total_num_nonces, total_added_nonces, num_good_first_bytes, CONFIDENCE_THRESHOLD);
		
}

static int acquire_nonces(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, bool nonce_file_write, bool slow)
{
	clock_t time1 = clock();
	bool initialize = true;
	bool finished = false;
	bool filter_flip_checked = false;
	uint32_t flags = 0;
	uint8_t write_buf[9];
	uint32_t total_num_nonces = 0;
	uint32_t next_fivehundred = 500;
	uint32_t total_added_nonces = 0;
	uint32_t idx = 1;
	FILE *fnonces = NULL;
	UsbCommand resp;

	field_off = false;
	thread_check_started = false;
	thread_check_done = false;

	printf("Acquiring nonces...\n");

	clearCommandBuffer();

	do {
		if (thread_check_started && !thread_check_done) {
			sleep(3);
			continue;
		}

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
				
				if (nonce_file_write && fnonces) {
					fwrite(bufp, 1, 9, fnonces);
				}
				
				bufp += 9;
			}

			total_num_nonces += num_acquired_nonces;
		}
		
		if (first_byte_num == 256 && !field_off) {
			// printf("first_byte_num = %d, first_byte_Sum = %d\n", first_byte_num, first_byte_Sum);
			if (!filter_flip_checked) {
				Check_for_FilterFlipProperties();
				filter_flip_checked = true;
			}

			num_good_first_bytes = estimate_second_byte_sum();
			if (total_num_nonces > next_fivehundred) {
				next_fivehundred = (total_num_nonces/500+1) * 500;
				printf("Acquired %5d nonces (%5d with distinct bytes 0 and 1). Number of bytes with probability for correctly guessed Sum(a8) > %1.1f%%: %d\n",
					total_num_nonces, 
					total_added_nonces,
					CONFIDENCE_THRESHOLD * 100.0,
					num_good_first_bytes);
			}

			if (thread_check_started) {
				if (thread_check_done) {
					pthread_join (thread_check, 0);
					thread_check_started = thread_check_done = false;
				}
			} else {
				if (total_added_nonces >= MIN_NONCES_REQUIRED)
				{
					num_good_first_bytes = estimate_second_byte_sum();
					if (total_added_nonces > (NONCES_TRIGGER*idx) || num_good_first_bytes >= GOOD_BYTES_REQUIRED) {
						pthread_create (&thread_check, NULL, check_thread, NULL);
						thread_check_started = true;
						idx++;
					}
				}
			}
		}

		if (!initialize) {
			if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
				if (fnonces) { // fix segfault on proxmark3 v1 when reset button is pressed
					fclose(fnonces);
					fnonces = NULL;
				}
				return 1;
			}

			if (resp.arg[0]) {
				if (fnonces) { // fix segfault on proxmark3 v1 when reset button is pressed
					fclose(fnonces);
					fnonces = NULL;
				}
				return resp.arg[0];  // error during nested_hard
			}
		}

		initialize = false;

	} while (!finished);

	if (nonce_file_write && fnonces) {
		fclose(fnonces);
		fnonces = NULL;
	}
	
	time1 = clock() - time1;
	if ( time1 > 0 ) {
		PrintAndLog("Acquired a total of %d nonces in %1.1f seconds (%0.0f nonces/minute)", 
			total_num_nonces, 
			((float)time1)/CLOCKS_PER_SEC, 
			total_num_nonces * 60.0 * CLOCKS_PER_SEC/(float)time1
		);
	}
	return 0;
}

static int init_partial_statelists(void)
{
	const uint32_t sizes_odd[17] = { 126757, 0, 18387, 0, 74241, 0, 181737, 0, 248801, 0, 182033, 0, 73421, 0, 17607, 0, 125601 };
//	const uint32_t sizes_even[17] = { 125723, 0, 17867, 0, 74305, 0, 178707, 0, 248801, 0, 185063, 0, 73356, 0, 18127, 0, 126634 };
	const uint32_t sizes_even[17] = { 125723, 0, 17867, 0, 74305, 0, 178707, 0, 248801, 0, 185063, 0, 73357, 0, 18127, 0, 126635 };
	
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
			*p = END_OF_LIST_MARKER;
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
	*p = END_OF_LIST_MARKER;
	statelist_bitflip.states[0] = realloc(statelist_bitflip.states[0], sizeof(uint32_t) * (statelist_bitflip.len[0] + 1));
}
		
static inline uint32_t *find_first_state(uint32_t state, uint32_t mask, partial_indexed_statelist_t *sl, odd_even_t odd_even)
{
	uint32_t *p = sl->index[odd_even][(state & mask) >> (20-STATELIST_INDEX_WIDTH)];		// first Bits as index

	if (p == NULL) return NULL;
	while (*p < (state & mask)) p++;
	if (*p == END_OF_LIST_MARKER) return NULL;					// reached end of list, no match
	if ((*p & mask) == (state & mask)) return p;		// found a match.
	return NULL;										// no match
} 

static inline bool /*__attribute__((always_inline))*/ invariant_holds(uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, uint_fast8_t bit, uint_fast8_t state_bit)
{
	uint_fast8_t j_1_bit_mask = 0x01 << (bit-1);
	uint_fast8_t bit_diff = byte_diff & j_1_bit_mask;							 			// difference of (j-1)th bit
	uint_fast8_t filter_diff = filter(state1 >> (4-state_bit)) ^ filter(state2 >> (4-state_bit));	// difference in filter function
	uint_fast8_t mask_y12_y13 = 0xc0 >> state_bit;
	uint_fast8_t state_bits_diff = (state1 ^ state2) & mask_y12_y13;						// difference in state bits 12 and 13
	uint_fast8_t all_diff = evenparity8(bit_diff ^ state_bits_diff ^ filter_diff);			// use parity function to XOR all bits
	return !all_diff;
}

static inline bool /*__attribute__((always_inline))*/ invalid_state(uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, uint_fast8_t bit, uint_fast8_t state_bit)
{
	uint_fast8_t j_bit_mask = 0x01 << bit;
	uint_fast8_t bit_diff = byte_diff & j_bit_mask;											// difference of jth bit
	uint_fast8_t mask_y13_y16 = 0x48 >> state_bit;
	uint_fast8_t state_bits_diff = (state1 ^ state2) & mask_y13_y16;						// difference in state bits 13 and 16
	uint_fast8_t all_diff = evenparity8(bit_diff ^ state_bits_diff);						// use parity function to XOR all bits
	return all_diff;
}

static inline bool remaining_bits_match(uint_fast8_t num_common_bits, uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, odd_even_t odd_even)
{
	if (odd_even) {
		// odd bits
		switch (num_common_bits) {
			case 0: if (!invariant_holds(byte_diff, state1, state2, 1, 0)) return true;
			case 1: if (invalid_state(byte_diff, state1, state2, 1, 0)) return false;
			case 2: if (!invariant_holds(byte_diff, state1, state2, 3, 1)) return true;
			case 3: if (invalid_state(byte_diff, state1, state2, 3, 1)) return false;
			case 4: if (!invariant_holds(byte_diff, state1, state2, 5, 2)) return true;
			case 5: if (invalid_state(byte_diff, state1, state2, 5, 2)) return false;
			case 6: if (!invariant_holds(byte_diff, state1, state2, 7, 3)) return true;
			case 7: if (invalid_state(byte_diff, state1, state2, 7, 3)) return false;
		}
	} else {
		// even bits
		switch (num_common_bits) {	
			case 0: if (invalid_state(byte_diff, state1, state2, 0, 0)) return false;
			case 1: if (!invariant_holds(byte_diff, state1, state2, 2, 1)) return true;
			case 2: if (invalid_state(byte_diff, state1, state2, 2, 1)) return false;
			case 3: if (!invariant_holds(byte_diff, state1, state2, 4, 2)) return true;
			case 4: if (invalid_state(byte_diff, state1, state2, 4, 2)) return false;
			case 5: if (!invariant_holds(byte_diff, state1, state2, 6, 3)) return true;
			case 6: if (invalid_state(byte_diff, state1, state2, 6, 3)) return false;
		}
	} 
	
	return true;					// valid state
}

static bool all_other_first_bytes_match(uint32_t state, odd_even_t odd_even) 
{
	for (uint16_t i = 1; i < num_good_first_bytes; i++) {
		uint16_t sum_a8 = nonces[best_first_bytes[i]].Sum8_guess;
		uint_fast8_t bytes_diff = best_first_bytes[0] ^ best_first_bytes[i];
		uint_fast8_t j = common_bits(bytes_diff);
		uint32_t mask = 0xfffffff0;
		if (odd_even == ODD_STATE) {
			mask >>= j/2;
		} else {
			mask >>= (j+1)/2;
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
						while ((state & mask) == (*p & mask) && (*p != END_OF_LIST_MARKER)) {
							if (remaining_bits_match(j, bytes_diff, state, (state&0x00fffff0) | *p, odd_even)) {
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

static bool all_bit_flips_match(uint32_t state, odd_even_t odd_even) 
{
	for (uint16_t i = 0; i < 256; i++) {
		if (nonces[i].BitFlip[odd_even] && i != best_first_bytes[0]) {
			uint_fast8_t bytes_diff = best_first_bytes[0] ^ i;
			uint_fast8_t j = common_bits(bytes_diff);
			uint32_t mask = 0xfffffff0;
			if (odd_even == ODD_STATE) {
				mask >>= j/2;
			} else {
				mask >>= (j+1)/2;
			}
			mask &= 0x000fffff;
			//printf("bytes 0x%02x and 0x%02x: %d common bits, mask = 0x%08x, state = 0x%08x, sum_a8 = %d", best_first_bytes[0], best_first_bytes[i], j, mask, state, sum_a8);
			bool found_match = false;
			uint32_t *p = find_first_state(state, mask, &statelist_bitflip, 0);
			if (p != NULL) {
				while ((state & mask) == (*p & mask) && (*p != END_OF_LIST_MARKER)) {
					if (remaining_bits_match(j, bytes_diff, state, (state&0x00fffff0) | *p, odd_even)) {
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
			if (!found_match) {
				// if ((odd_even == ODD_STATE && state == test_state_odd)
					// || (odd_even == EVEN_STATE && state == test_state_even)) {
					// printf("all_other_first_bytes_match(): %s test state: Eliminated. Bytes = %02x, %02x, Common Bits = %d\n", odd_even==ODD_STATE?"odd":"even", best_first_bytes[0], best_first_bytes[i], j);
				// }
				return false;
			}
		}

	}
	
	return true;
}

static struct sl_cache_entry {
	uint32_t *sl;
	uint32_t len;
	} sl_cache[17][17][2];

static void init_statelist_cache(void)
{
	for (uint16_t i = 0; i < 17; i+=2) {
		for (uint16_t j = 0; j < 17; j+=2) {
			for (uint16_t k = 0; k < 2; k++) {
				sl_cache[i][j][k].sl = NULL;
				sl_cache[i][j][k].len = 0;
			}
		}
	}		
}

static int add_matching_states(statelist_t *candidates, uint16_t part_sum_a0, uint16_t part_sum_a8, odd_even_t odd_even)
{
	uint32_t worstcase_size = 1<<20;
	
	// check cache for existing results
	if (sl_cache[part_sum_a0][part_sum_a8][odd_even].sl != NULL) {
		candidates->states[odd_even] = sl_cache[part_sum_a0][part_sum_a8][odd_even].sl;
		candidates->len[odd_even] = sl_cache[part_sum_a0][part_sum_a8][odd_even].len;
		return 0;
	}
	
	candidates->states[odd_even] = (uint32_t *)malloc(sizeof(uint32_t) * worstcase_size);
	if (candidates->states[odd_even] == NULL) {
		PrintAndLog("Out of memory error.\n");
		return 4;
	}
	uint32_t *add_p = candidates->states[odd_even]; 
	for (uint32_t *p1 = partial_statelist[part_sum_a0].states[odd_even]; *p1 != END_OF_LIST_MARKER; p1++) {
		uint32_t search_mask = 0x000ffff0;
		uint32_t *p2 = find_first_state((*p1 << 4), search_mask, &partial_statelist[part_sum_a8], odd_even);
		if (p2 != NULL) {
			while (((*p1 << 4) & search_mask) == (*p2 & search_mask) && *p2 != END_OF_LIST_MARKER) {
				if ((nonces[best_first_bytes[0]].BitFlip[odd_even] && find_first_state((*p1 << 4) | *p2, 0x000fffff, &statelist_bitflip, 0))
					|| !nonces[best_first_bytes[0]].BitFlip[odd_even]) {
				if (all_other_first_bytes_match((*p1 << 4) | *p2, odd_even)) {
					if (all_bit_flips_match((*p1 << 4) | *p2, odd_even)) { 
							*add_p++ = (*p1 << 4) | *p2;
						}
				}
				}
				p2++;
			}
		}
	}

	// set end of list marker and len
	*add_p = END_OF_LIST_MARKER; 
	candidates->len[odd_even] = add_p - candidates->states[odd_even];

	candidates->states[odd_even] = realloc(candidates->states[odd_even], sizeof(uint32_t) * (candidates->len[odd_even] + 1));

	sl_cache[part_sum_a0][part_sum_a8][odd_even].sl = candidates->states[odd_even];
	sl_cache[part_sum_a0][part_sum_a8][odd_even].len = candidates->len[odd_even];

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

static bool TestIfKeyExists(uint64_t key)
{
	struct Crypto1State *pcs;
	pcs = crypto1_create(key);
	crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);

	uint32_t state_odd = pcs->odd & 0x00ffffff;
	uint32_t state_even = pcs->even & 0x00ffffff;
	//printf("Tests: searching for key %llx after first byte 0x%02x (state_odd = 0x%06x, state_even = 0x%06x) ...\n", key, best_first_bytes[0], state_odd, state_even);
	
	uint64_t count = 0;
	for (statelist_t *p = candidates; p != NULL; p = p->next) {
		bool found_odd = false;
		bool found_even = false;
		uint32_t *p_odd = p->states[ODD_STATE];
		uint32_t *p_even = p->states[EVEN_STATE];
		while (*p_odd != END_OF_LIST_MARKER) {
			if ((*p_odd & 0x00ffffff) == state_odd) {
				found_odd = true;
				break;
			}
			p_odd++;
		}
		while (*p_even != END_OF_LIST_MARKER) {
			if ((*p_even & 0x00ffffff) == state_even) {
				found_even = true;
			}
			p_even++;
		}
		count += (p_odd - p->states[ODD_STATE]) * (p_even - p->states[EVEN_STATE]);
		if (found_odd && found_even) {
			PrintAndLog("Key Found after testing %lld (2^%1.1f) out of %lld (2^%1.1f) keys. ", 
				count,
				log(count)/log(2), 
				maximum_states,
				log(maximum_states)/log(2)
				);
			if (write_stats) {
				fprintf(fstats, "1\n");
			}
			crypto1_destroy(pcs);
			return true;
		}
	}

	printf("Key NOT found!\n");
	if (write_stats) {
		fprintf(fstats, "0\n");
	}
	crypto1_destroy(pcs);

	return false;
}

static bool generate_candidates(uint16_t sum_a0, uint16_t sum_a8)
{
	printf("Generating crypto1 state candidates... \n");
	
	statelist_t *current_candidates = NULL;
	// estimate maximum candidate states
	maximum_states = 0;
	for (uint16_t sum_odd = 0; sum_odd <= 16; sum_odd += 2) {
		for (uint16_t sum_even = 0; sum_even <= 16; sum_even += 2) {
			if (sum_odd*(16-sum_even) + (16-sum_odd)*sum_even == sum_a0) {
				maximum_states += (uint64_t)partial_statelist[sum_odd].len[ODD_STATE] * partial_statelist[sum_even].len[EVEN_STATE] * (1<<8);
			}
		}
	}

	if (maximum_states == 0) return false; // prevent keyspace reduction error (2^-inf)

	printf("Number of possible keys with Sum(a0) = %d: %"PRIu64" (2^%1.1f)\n", sum_a0, maximum_states, log(maximum_states)/log(2.0));
	
	init_statelist_cache();
	
	for (uint16_t p = 0; p <= 16; p += 2) {
		for (uint16_t q = 0; q <= 16; q += 2) {
			if (p*(16-q) + (16-p)*q == sum_a0) {
				// printf("Reducing Partial Statelists (p,q) = (%d,%d) with lengths %d, %d\n", 
						// p, q, partial_statelist[p].len[ODD_STATE], partial_statelist[q].len[EVEN_STATE]);
				for (uint16_t r = 0; r <= 16; r += 2) {
					for (uint16_t s = 0; s <= 16; s += 2) {
						if (r*(16-s) + (16-r)*s == sum_a8) {
							current_candidates = add_more_candidates(current_candidates);
							// check for the smallest partial statelist. Try this first - it might give 0 candidates 
							// and eliminate the need to calculate the other part
							if (MIN(partial_statelist[p].len[ODD_STATE], partial_statelist[r].len[ODD_STATE]) 
									< MIN(partial_statelist[q].len[EVEN_STATE], partial_statelist[s].len[EVEN_STATE])) { 
							add_matching_states(current_candidates, p, r, ODD_STATE);
								if(current_candidates->len[ODD_STATE]) {
							add_matching_states(current_candidates, q, s, EVEN_STATE);
								} else {
									current_candidates->len[EVEN_STATE] = 0;
									uint32_t *p = current_candidates->states[EVEN_STATE] = malloc(sizeof(uint32_t));
									*p = END_OF_LIST_MARKER;
								}
							} else {
								add_matching_states(current_candidates, q, s, EVEN_STATE);
								if(current_candidates->len[EVEN_STATE]) {
									add_matching_states(current_candidates, p, r, ODD_STATE);
								} else {
									current_candidates->len[ODD_STATE] = 0;
									uint32_t *p = current_candidates->states[ODD_STATE] = malloc(sizeof(uint32_t));
									*p = END_OF_LIST_MARKER;
								}
							}
							//printf("Odd  state candidates: %6d (2^%0.1f)\n", current_candidates->len[ODD_STATE], log(current_candidates->len[ODD_STATE])/log(2)); 
							//printf("Even state candidates: %6d (2^%0.1f)\n", current_candidates->len[EVEN_STATE], log(current_candidates->len[EVEN_STATE])/log(2)); 
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

	if (maximum_states == 0) return false; // prevent keyspace reduction error (2^-inf)

	float kcalc = log(maximum_states)/log(2.0);
	printf("Number of remaining possible keys: %"PRIu64" (2^%1.1f)\n", maximum_states, kcalc);
	if (write_stats) {
		if (maximum_states != 0) {
			fprintf(fstats, "%1.1f;", kcalc);
		} else {
			fprintf(fstats, "%1.1f;", 0.0);
		}
	}
	if (kcalc < CRACKING_THRESHOLD) return true;

	return false;
}

static void	free_candidates_memory(statelist_t *sl)
{
	if (sl == NULL) {
		return;
	} else {
		free_candidates_memory(sl->next);
		free(sl);
	}
}

static void free_statelist_cache(void)
{
	for (uint16_t i = 0; i < 17; i+=2) {
		for (uint16_t j = 0; j < 17; j+=2) {
			for (uint16_t k = 0; k < 2; k++) {
				free(sl_cache[i][j][k].sl);
			}
		}
	}		
}

uint64_t foundkey = 0;
size_t keys_found = 0;
size_t bucket_count = 0;
statelist_t* buckets[128];
size_t total_states_tested = 0;
size_t thread_count = 4;

// these bitsliced states will hold identical states in all slices
bitslice_t bitsliced_rollback_byte[ROLLBACK_SIZE];

// arrays of bitsliced states with identical values in all slices
bitslice_t bitsliced_encrypted_nonces[NONCE_TESTS][STATE_SIZE];
bitslice_t bitsliced_encrypted_parity_bits[NONCE_TESTS][ROLLBACK_SIZE];

#define EXACT_COUNT

static const uint64_t crack_states_bitsliced(statelist_t *p){
    // the idea to roll back the half-states before combining them was suggested/explained to me by bla
    // first we pre-bitslice all the even state bits and roll them back, then bitslice the odd bits and combine the two in the inner loop
    uint64_t key = -1;
	uint8_t bSize = sizeof(bitslice_t);

#ifdef EXACT_COUNT
    size_t bucket_states_tested = 0;
    size_t bucket_size[p->len[EVEN_STATE]/MAX_BITSLICES];
#else
    const size_t bucket_states_tested = (p->len[EVEN_STATE])*(p->len[ODD_STATE]);
#endif

    bitslice_t *bitsliced_even_states[p->len[EVEN_STATE]/MAX_BITSLICES];
    size_t bitsliced_blocks = 0;
    uint32_t const * restrict even_end = p->states[EVEN_STATE]+p->len[EVEN_STATE];
	
    // bitslice all the even states
    for(uint32_t * restrict p_even = p->states[EVEN_STATE]; p_even < even_end; p_even += MAX_BITSLICES){

#ifdef __WIN32
	#ifdef __MINGW32__
		bitslice_t * restrict lstate_p = __mingw_aligned_malloc((STATE_SIZE+ROLLBACK_SIZE) * bSize, bSize);
	#else		
		bitslice_t * restrict lstate_p = _aligned_malloc((STATE_SIZE+ROLLBACK_SIZE) * bSize, bSize);
	#endif
#else
	#ifdef __APPLE__
		bitslice_t * restrict lstate_p = malloc((STATE_SIZE+ROLLBACK_SIZE) * bSize);
	#else
		bitslice_t * restrict lstate_p = memalign(bSize, (STATE_SIZE+ROLLBACK_SIZE) * bSize);
	#endif
#endif

		if ( !lstate_p )	{
			__sync_fetch_and_add(&total_states_tested, bucket_states_tested);
			return key;
		}
				
		memset(lstate_p+1, 0x0, (STATE_SIZE-1)*sizeof(bitslice_t)); // zero even bits
		
		// bitslice even half-states
        const size_t max_slices = (even_end-p_even) < MAX_BITSLICES ? even_end-p_even : MAX_BITSLICES;
#ifdef EXACT_COUNT
        bucket_size[bitsliced_blocks] = max_slices;
#endif
        for(size_t slice_idx = 0; slice_idx < max_slices; ++slice_idx){
            uint32_t e = *(p_even+slice_idx);
            for(size_t bit_idx = 1; bit_idx < STATE_SIZE; bit_idx+=2, e >>= 1){
                // set even bits
                if(e&1){
                    lstate_p[bit_idx].bytes64[slice_idx>>6] |= 1ull << (slice_idx&63);
                }
            }
        }
        // compute the rollback bits
        for(size_t rollback = 0; rollback < ROLLBACK_SIZE; ++rollback){
            // inlined crypto1_bs_lfsr_rollback
            const bitslice_value_t feedout = lstate_p[0].value;
            ++lstate_p;
            const bitslice_value_t ks_bits = crypto1_bs_f20(lstate_p);
            const bitslice_value_t feedback = (feedout ^ ks_bits     ^ lstate_p[47- 5].value ^ lstate_p[47- 9].value ^
                                               lstate_p[47-10].value ^ lstate_p[47-12].value ^ lstate_p[47-14].value ^
                                               lstate_p[47-15].value ^ lstate_p[47-17].value ^ lstate_p[47-19].value ^
                                               lstate_p[47-24].value ^ lstate_p[47-25].value ^ lstate_p[47-27].value ^
                                               lstate_p[47-29].value ^ lstate_p[47-35].value ^ lstate_p[47-39].value ^
                                               lstate_p[47-41].value ^ lstate_p[47-42].value ^ lstate_p[47-43].value);
            lstate_p[47].value = feedback ^ bitsliced_rollback_byte[rollback].value;
        }
        bitsliced_even_states[bitsliced_blocks++] = lstate_p;
    }

    // bitslice every odd state to every block of even half-states with half-finished rollback
    for(uint32_t const * restrict p_odd = p->states[ODD_STATE]; p_odd < p->states[ODD_STATE]+p->len[ODD_STATE]; ++p_odd){
        // early abort
        if(keys_found){
            goto out;
        }

        // set the odd bits and compute rollback
        uint64_t o = (uint64_t) *p_odd;
        lfsr_rollback_byte((struct Crypto1State*) &o, 0, 1);
        // pre-compute part of the odd feedback bits (minus rollback)
        bool odd_feedback_bit = parity(o&0x9ce5c);

        crypto1_bs_rewind_a0();
        // set odd bits
        for(size_t state_idx = 0; state_idx < STATE_SIZE-ROLLBACK_SIZE; o >>= 1, state_idx+=2){
            if(o & 1){
                state_p[state_idx] = bs_ones;
            } else {
                state_p[state_idx] = bs_zeroes;
            }
        }
        const bitslice_value_t odd_feedback = odd_feedback_bit ? bs_ones.value : bs_zeroes.value;

        for(size_t block_idx = 0; block_idx < bitsliced_blocks; ++block_idx){
            const bitslice_t * const restrict bitsliced_even_state = bitsliced_even_states[block_idx];
            size_t state_idx;
            // set even bits
            for(state_idx = 0; state_idx < STATE_SIZE-ROLLBACK_SIZE; state_idx+=2){
                state_p[1+state_idx] = bitsliced_even_state[1+state_idx];
            }
            // set rollback bits
            uint64_t lo = o;
            for(; state_idx < STATE_SIZE; lo >>= 1, state_idx+=2){
                // set the odd bits and take in the odd rollback bits from the even states
                if(lo & 1){
                    state_p[state_idx].value = ~bitsliced_even_state[state_idx].value;
                } else {
                    state_p[state_idx] = bitsliced_even_state[state_idx];
                }

                // set the even bits and take in the even rollback bits from the odd states
                if((lo >> 32) & 1){
                    state_p[1+state_idx].value = ~bitsliced_even_state[1+state_idx].value;
                } else {
                    state_p[1+state_idx] = bitsliced_even_state[1+state_idx];
                }
            }

#ifdef EXACT_COUNT
            bucket_states_tested += bucket_size[block_idx];
#endif
            // pre-compute first keystream and feedback bit vectors
            const bitslice_value_t ksb = crypto1_bs_f20(state_p);
            const bitslice_value_t fbb = (odd_feedback         ^ state_p[47- 0].value ^ state_p[47- 5].value ^ // take in the even and rollback bits
                                          state_p[47-10].value ^ state_p[47-12].value ^ state_p[47-14].value ^
                                          state_p[47-24].value ^ state_p[47-42].value);

            // vector to contain test results (1 = passed, 0 = failed)
            bitslice_t results = bs_ones;

            for(size_t tests = 0; tests < NONCE_TESTS; ++tests){
                size_t parity_bit_idx = 0;
                bitslice_value_t fb_bits = fbb;
                bitslice_value_t ks_bits = ksb;
                state_p = &states[KEYSTREAM_SIZE-1];
                bitslice_value_t parity_bit_vector = bs_zeroes.value;

                // highest bit is transmitted/received first
                for(int32_t ks_idx = KEYSTREAM_SIZE-1; ks_idx >= 0; --ks_idx, --state_p){
                    // decrypt nonce bits
                    const bitslice_value_t encrypted_nonce_bit_vector = bitsliced_encrypted_nonces[tests][ks_idx].value;
                    const bitslice_value_t decrypted_nonce_bit_vector = (encrypted_nonce_bit_vector ^ ks_bits);

                    // compute real parity bits on the fly
                    parity_bit_vector ^= decrypted_nonce_bit_vector;

                    // update state
                    state_p[0].value = (fb_bits ^ decrypted_nonce_bit_vector);

                    // compute next keystream bit
                    ks_bits = crypto1_bs_f20(state_p);

                    // for each byte:
                    if((ks_idx&7) == 0){
                        // get encrypted parity bits
                        const bitslice_value_t encrypted_parity_bit_vector = bitsliced_encrypted_parity_bits[tests][parity_bit_idx++].value;

                        // decrypt parity bits
                        const bitslice_value_t decrypted_parity_bit_vector = (encrypted_parity_bit_vector ^ ks_bits);

                        // compare actual parity bits with decrypted parity bits and take count in results vector
                        results.value &= (parity_bit_vector ^ decrypted_parity_bit_vector);

                        // make sure we still have a match in our set
                        // if(memcmp(&results, &bs_zeroes, sizeof(bitslice_t)) == 0){

                        // this is much faster on my gcc, because somehow a memcmp needlessly spills/fills all the xmm registers to/from the stack - ???
                        // the short-circuiting also helps
                        if(results.bytes64[0] == 0
#if MAX_BITSLICES > 64
                           && results.bytes64[1] == 0
#endif
#if MAX_BITSLICES > 128
                           && results.bytes64[2] == 0
                           && results.bytes64[3] == 0
#endif
                          ){
                            goto stop_tests;
                        }
                        // this is about as fast but less portable (requires -std=gnu99)
                        // asm goto ("ptest %1, %0\n\t"
                        //           "jz %l2" :: "xm" (results.value), "xm" (bs_ones.value) : "cc" : stop_tests);
                        parity_bit_vector = bs_zeroes.value;
                    }
                    // compute next feedback bit vector
                    fb_bits = (state_p[47- 0].value ^ state_p[47- 5].value ^ state_p[47- 9].value ^
                               state_p[47-10].value ^ state_p[47-12].value ^ state_p[47-14].value ^
                               state_p[47-15].value ^ state_p[47-17].value ^ state_p[47-19].value ^
                               state_p[47-24].value ^ state_p[47-25].value ^ state_p[47-27].value ^
                               state_p[47-29].value ^ state_p[47-35].value ^ state_p[47-39].value ^
                               state_p[47-41].value ^ state_p[47-42].value ^ state_p[47-43].value);
                }
            }
            // all nonce tests were successful: we've found the key in this block!
            state_t keys[MAX_BITSLICES];
            crypto1_bs_convert_states(&states[KEYSTREAM_SIZE], keys);
            for(size_t results_idx = 0; results_idx < MAX_BITSLICES; ++results_idx){
                if(get_vector_bit(results_idx, results)){
                    key = keys[results_idx].value;
                    goto out;
                }
            }
stop_tests:
            // prepare to set new states
            crypto1_bs_rewind_a0();
            continue;
        }
    }

out:
    for(size_t block_idx = 0; block_idx < bitsliced_blocks; ++block_idx){
		
#ifdef __WIN32
	#ifdef __MINGW32__
		__mingw_aligned_free(bitsliced_even_states[block_idx]-ROLLBACK_SIZE);
	#else
		_aligned_free(bitsliced_even_states[block_idx]-ROLLBACK_SIZE);		
	#endif
#else
		free(bitsliced_even_states[block_idx]-ROLLBACK_SIZE);
#endif		
		
    }
    __sync_fetch_and_add(&total_states_tested, bucket_states_tested);
    return key;
}

static void* check_thread()
{
	num_good_first_bytes = estimate_second_byte_sum();

	clock_t time1 = clock();
	bool cracking = generate_candidates(first_byte_Sum, nonces[best_first_bytes[0]].Sum8_guess);
	time1 = clock() - time1;
	if (time1 > 0) PrintAndLog("Time for generating key candidates list: %1.0f seconds", ((float)time1)/CLOCKS_PER_SEC);

	if (cracking || known_target_key != -1) {
		field_off = brute_force(); // switch off field with next SendCommand and then finish
	}

	thread_check_done = true;

	return (void *) NULL;
}

static void* crack_states_thread(void* x){
    const size_t thread_id = (size_t)x;
    size_t current_bucket = thread_id;
    while(current_bucket < bucket_count){
        statelist_t * bucket = buckets[current_bucket];
		if(bucket){
            const uint64_t key = crack_states_bitsliced(bucket);
            if(key != -1){
                __sync_fetch_and_add(&keys_found, 1);
				__sync_fetch_and_add(&foundkey, key);
                break;
            } else if(keys_found){
                break;
            } else {				
                printf(".");
				fflush(stdout);
            }
        }
        current_bucket += thread_count;
    }
    return NULL;
}

static bool brute_force(void)
{
	bool ret = false;
	if (known_target_key != -1) {
		PrintAndLog("Looking for known target key in remaining key space...");
		ret = TestIfKeyExists(known_target_key);
	} else {
		if (maximum_states == 0) return false; // prevent keyspace reduction error (2^-inf)

	 	PrintAndLog("Brute force phase starting.");
	 	time_t start, end;
		time(&start);
		keys_found = 0;
		foundkey = 0;

		crypto1_bs_init();

		PrintAndLog("Using %u-bit bitslices", MAX_BITSLICES);
		PrintAndLog("Bitslicing best_first_byte^uid[3] (rollback byte): %02x...", best_first_bytes[0]^(cuid>>24));
		// convert to 32 bit little-endian
		crypto1_bs_bitslice_value32((best_first_bytes[0]<<24)^cuid, bitsliced_rollback_byte, 8);

		PrintAndLog("Bitslicing nonces...");
		for(size_t tests = 0; tests < NONCE_TESTS; tests++){
			uint32_t test_nonce = brute_force_nonces[tests]->nonce_enc;
			uint8_t test_parity = brute_force_nonces[tests]->par_enc;
			// pre-xor the uid into the decrypted nonces, and also pre-xor the cuid parity into the encrypted parity bits - otherwise an exta xor is required in the decryption routine
			crypto1_bs_bitslice_value32(cuid^test_nonce, bitsliced_encrypted_nonces[tests], 32);
			// convert to 32 bit little-endian
			crypto1_bs_bitslice_value32(rev32( ~(test_parity ^ ~(parity(cuid>>24 & 0xff)<<3 | parity(cuid>>16 & 0xff)<<2 | parity(cuid>>8 & 0xff)<<1 | parity(cuid&0xff)))), bitsliced_encrypted_parity_bits[tests], 4);
		}
		total_states_tested = 0;

		// count number of states to go
		bucket_count = 0;
		for (statelist_t *p = candidates; p != NULL; p = p->next) {
			buckets[bucket_count] = p;
			bucket_count++;
		}

#ifndef __WIN32
		thread_count = sysconf(_SC_NPROCESSORS_CONF);
		if ( thread_count < 1)
			thread_count = 1;
#endif  /* _WIN32 */

		pthread_t threads[thread_count];

		// enumerate states using all hardware threads, each thread handles one bucket
		PrintAndLog("Starting %u cracking threads to search %u buckets containing a total of %"PRIu64" states...", thread_count, bucket_count, maximum_states);

		for(size_t i = 0; i < thread_count; i++){
			pthread_create(&threads[i], NULL, crack_states_thread, (void*) i);
		}
		for(size_t i = 0; i < thread_count; i++){
			pthread_join(threads[i], 0);
		}

		time(&end);
		double elapsed_time = difftime(end, start);

		if (keys_found && TestIfKeyExists(foundkey)) {
			PrintAndLog("Success! Tested %"PRIu32" states, found %u keys after %.f seconds", total_states_tested, keys_found, elapsed_time);
			PrintAndLog("\nFound key: %012"PRIx64"\n", foundkey);
			ret = true;
		} else {
			PrintAndLog("Fail! Tested %"PRIu32" states, in %.f seconds", total_states_tested, elapsed_time);
		}

		// reset this counter for the next call
		nonces_to_bruteforce = 0;
	}

	return ret;
}

int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *trgkey, bool nonce_file_read, bool nonce_file_write, bool slow, int tests) 
{
	// initialize Random number generator
	time_t t;
	srand((unsigned) time(&t));
	
	if (trgkey != NULL) {
		known_target_key = bytes_to_num(trgkey, 6);
	} else {
		known_target_key = -1;
	}
	
	init_partial_statelists();
	init_BitFlip_statelist();
	write_stats = false;
	
	if (tests) {
		// set the correct locale for the stats printing
		setlocale(LC_ALL, "");
		write_stats = true;
		if ((fstats = fopen("hardnested_stats.txt","a")) == NULL) { 
			PrintAndLog("Could not create/open file hardnested_stats.txt");
			return 3;
		}
		for (uint32_t i = 0; i < tests; i++) {
			init_nonce_memory();
			simulate_acquire_nonces();
			Tests();
			printf("Sum(a0) = %d\n", first_byte_Sum);
			fprintf(fstats, "%d;", first_byte_Sum);
			generate_candidates(first_byte_Sum, nonces[best_first_bytes[0]].Sum8_guess);
			brute_force();
			free_nonces_memory();
			free_statelist_cache();
			free_candidates_memory(candidates);
			candidates = NULL;
		}
		fclose(fstats);
		fstats = NULL;
	} else {
		init_nonce_memory();
		if (nonce_file_read) { // use pre-acquired data from file nonces.bin
			if (read_nonce_file() != 0) {
				return 3;
			}
			Check_for_FilterFlipProperties();
			num_good_first_bytes = MIN(estimate_second_byte_sum(), GOOD_BYTES_REQUIRED);
			PrintAndLog("Number of first bytes with confidence > %2.1f%%: %d", CONFIDENCE_THRESHOLD*100.0, num_good_first_bytes);

			clock_t time1 = clock();
			bool cracking = generate_candidates(first_byte_Sum, nonces[best_first_bytes[0]].Sum8_guess);
			time1 = clock() - time1;
			if (time1 > 0)
				PrintAndLog("Time for generating key candidates list: %1.0f seconds", ((float)time1)/CLOCKS_PER_SEC);

			if (cracking)
				brute_force();
		} else { // acquire nonces.
			uint16_t is_OK = acquire_nonces(blockNo, keyType, key, trgBlockNo, trgKeyType, nonce_file_write, slow);
			if (is_OK != 0) {
				return is_OK;
			}
		}

		//Tests();

		//PrintAndLog("");
		//PrintAndLog("Sum(a0) = %d", first_byte_Sum);
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

		free_nonces_memory();
		free_statelist_cache();
		free_candidates_memory(candidates);
		candidates = NULL;
	}
	return 0;
}


