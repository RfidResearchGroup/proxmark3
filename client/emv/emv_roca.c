/* roca.c - ROCA (CVE-2017-15361) fingerprint checker.
 * Written by Rob Stradling (based on https://github.com/crocs-muni/roca/blob/master/roca/detect.py)
 * Copyright (C) 2017 COMODO CA Limited
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "emv_roca.h"

static uint8_t g_primes[ROCA_PRINTS_LENGTH] = {
	11, 13, 17, 19, 37, 53, 61, 71, 73, 79, 97, 103, 107, 109, 127, 151, 157
};

mbedtls_mpi* g_prints[ROCA_PRINTS_LENGTH];

void rocacheck_init(void) {
	
	for (uint8_t i = 0; i < ROCA_PRINTS_LENGTH; i++)
		mbedtls_mpi_init(g_prints[i]);
	
	mbedtls_mpi_read_string(g_prints[0], 10, "1026");
	mbedtls_mpi_read_string(g_prints[1], 10, "5658");
	mbedtls_mpi_read_string(g_prints[2], 10, "107286");
	mbedtls_mpi_read_string(g_prints[3], 10, "199410");
	mbedtls_mpi_read_string(g_prints[4], 10, "67109890");
	mbedtls_mpi_read_string(g_prints[5], 10, "5310023542746834");
	mbedtls_mpi_read_string(g_prints[6], 10, "1455791217086302986");
	mbedtls_mpi_read_string(g_prints[7], 10, "20052041432995567486");
	mbedtls_mpi_read_string(g_prints[8], 10, "6041388139249378920330");
	mbedtls_mpi_read_string(g_prints[9], 10, "207530445072488465666");
	mbedtls_mpi_read_string(g_prints[10], 10, "79228162521181866724264247298");
	mbedtls_mpi_read_string(g_prints[11], 10, "1760368345969468176824550810518");
	mbedtls_mpi_read_string(g_prints[12], 10, "50079290986288516948354744811034");
	mbedtls_mpi_read_string(g_prints[13], 10, "473022961816146413042658758988474");
	mbedtls_mpi_read_string(g_prints[14], 10, "144390480366845522447407333004847678774");
	mbedtls_mpi_read_string(g_prints[15], 10, "1800793591454480341970779146165214289059119882");
	mbedtls_mpi_read_string(g_prints[16], 10, "126304807362733370595828809000324029340048915994");
}

void rocacheck_cleanup(void) {
	for (uint8_t i = 0; i < ROCA_PRINTS_LENGTH; i++)
		mbedtls_mpi_free(g_prints[i]);
}

int bitand_is_zero(	mbedtls_mpi* a, mbedtls_mpi* b ) {

	for (int i = 0; i < mbedtls_mpi_bitlen(a); i++) {
	
		if (mbedtls_mpi_get_bit(a, i) && mbedtls_mpi_get_bit(b, i))
			return 0;
	}
	return 1;
}


mbedtls_mpi_uint mpi_get_uint(const mbedtls_mpi *X) {
	
	if (X->n == 1) {
		return X->p[0];
	}
	
	return 0;
}

bool emv_rocacheck(char *modulus) {

	mbedtls_mpi *t_modulus = NULL;
	mbedtls_mpi_init(t_modulus);

	bool ret = true;

	rocacheck_init();

	// 
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string(t_modulus, 10, modulus) );
	
	
	for (int i = 0; i < ROCA_PRINTS_LENGTH; i++) {

		mbedtls_mpi* t_temp = NULL;
		mbedtls_mpi* t_prime = NULL;
		mbedtls_mpi* g_one = NULL;
		
		mbedtls_mpi_init(g_one);
		mbedtls_mpi_init(t_temp);
		mbedtls_mpi_init(t_prime);
		
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_string(g_one, 10, "1") );
	
		MBEDTLS_MPI_CHK( mbedtls_mpi_add_int(t_prime, t_prime, g_primes[i]) );
		
		MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi(t_temp, t_modulus, t_prime) ); 
		
		MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l(g_one, mpi_get_uint(t_temp)) );
		
		if (bitand_is_zero(t_temp, g_prints[i])) {
			PrintAndLogEx(FAILED, "No fingerprint found\n");
			ret = false;
			goto cleanup;
		}
		
		mbedtls_mpi_free(g_one);		
		mbedtls_mpi_free(t_temp);
		mbedtls_mpi_free(t_prime);
	}

	PrintAndLogEx(SUCCESS, "Fingerprint found!\n");

cleanup:
	if (t_modulus)
		mbedtls_mpi_free(t_modulus);

	rocacheck_cleanup();
	return ret;
}
