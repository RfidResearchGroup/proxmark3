# taa_denial_expired

Synthetic fixture — no real card data.

TVR byte 2 bit 3 (expired application) matches IAC denial → TAA requests AAC.

Expected: `RequestedAC=aac`, phase `taa` result 0.
