//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// CA PEM certificates
//-----------------------------------------------------------------------------

#include "additional_ca.h"

#define GLOBALSIGN_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\r\n" \
    "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\r\n" \
    "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\r\n" \
    "MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\r\n" \
    "YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\r\n" \
    "aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\r\n" \
    "jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\r\n" \
    "xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\r\n" \
    "1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\r\n" \
    "snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\r\n" \
    "U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\r\n" \
    "9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\r\n" \
    "BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\r\n" \
    "AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\r\n" \
    "yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\r\n" \
    "38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\r\n" \
    "AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\r\n" \
    "DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\r\n" \
    "HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\r\n" \
    "-----END CERTIFICATE-----\r\n"

// Name: Yubico U2F Root CA Serial 457200631
// Issued: 2014-08-01
// https://github.com/Yubico/developers.yubico.com/tree/master/static/U2F
// https://fido-mds-parser.appspot.com/?url=https://mds.fidoalliance.org/metadata/7DwVE5vbRQysYTJrf95b3a
#define YUBICO_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ\r\n" \
    "dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw\r\n" \
    "MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290\r\n" \
    "IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\r\n" \
    "AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk\r\n" \
    "5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep\r\n" \
    "8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw\r\n" \
    "nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT\r\n" \
    "9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw\r\n" \
    "LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ\r\n" \
    "hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN\r\n" \
    "BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4\r\n" \
    "MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt\r\n" \
    "hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k\r\n" \
    "LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U\r\n" \
    "sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc\r\n" \
    "U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==\r\n" \
    "-----END CERTIFICATE-----\r\n"

// Name: SoloKey U2F Root CA Serial 14143382635911888524 (0xc44763928ff4be8c)
// Issued: 2018-11-11
#define SOLOKEY_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIB9DCCAZoCCQDER2OSj/S+jDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCVVMx\r\n" \
    "ETAPBgNVBAgMCE1hcnlsYW5kMRIwEAYDVQQKDAlTb2xvIEtleXMxEDAOBgNVBAsM\r\n" \
    "B1Jvb3QgQ0ExFTATBgNVBAMMDHNvbG9rZXlzLmNvbTEhMB8GCSqGSIb3DQEJARYS\r\n" \
    "aGVsbG9Ac29sb2tleXMuY29tMCAXDTE4MTExMTEyNTE0MloYDzIwNjgxMDI5MTI1\r\n" \
    "MTQyWjCBgDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1hcnlsYW5kMRIwEAYDVQQK\r\n" \
    "DAlTb2xvIEtleXMxEDAOBgNVBAsMB1Jvb3QgQ0ExFTATBgNVBAMMDHNvbG9rZXlz\r\n" \
    "LmNvbTEhMB8GCSqGSIb3DQEJARYSaGVsbG9Ac29sb2tleXMuY29tMFkwEwYHKoZI\r\n" \
    "zj0CAQYIKoZIzj0DAQcDQgAEWHAN0CCJVZdMs0oktZ5m93uxmB1iyq8ELRLtqVFL\r\n" \
    "SOiHQEab56qRTB/QzrpGAY++Y2mw+vRuQMNhBiU0KzwjBjAKBggqhkjOPQQDAgNI\r\n" \
    "ADBFAiEAz9SlrAXIlEu87vra54rICPs+4b0qhp3PdzcTg7rvnP0CIGjxzlteQQx+\r\n" \
    "jQGd7rwSZuE5RWUPVygYhUstQO9zNUOs\r\n" \
    "-----END CERTIFICATE-----\r\n"

// FEITIAN U2F
// https://fido-mds-parser.appspot.com/?url=https://mds.fidoalliance.org/metadata/eS7v8sum4jxp7kgLQ5Qqcg
#define FEITIAN_U2F_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIBfjCCASWgAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxGVCBGSURP\r\n" \
    "IDAyMDAwIBcNMTYwNTAxMDAwMDAwWhgPMjA1MDA1MDEwMDAwMDBaMBcxFTATBgNV\r\n" \
    "BAMMDEZUIEZJRE8gMDIwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNBmrRqV\r\n" \
    "OxztTJVN19vtdqcL7tKQeol2nnM2/yYgvksZnr50SKbVgIEkzHQVOu80LVEE3lVh\r\n" \
    "eO1HjggxAlT6o4WjYDBeMB0GA1UdDgQWBBRJFWQt1bvG3jM6XgmV/IcjNtO/CzAf\r\n" \
    "BgNVHSMEGDAWgBRJFWQt1bvG3jM6XgmV/IcjNtO/CzAMBgNVHRMEBTADAQH/MA4G\r\n" \
    "A1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiAwfPqgIWIUB+QBBaVGsdHy\r\n" \
    "0s5RMxlkzpSX/zSyTZmUpQIgB2wJ6nZRM8oX/nA43Rh6SJovM2XwCCH//+LirBAb\r\n" \
    "B0M=\r\n" \
    "-----END CERTIFICATE-----\r\n"

// FEITIAN FIDO2
#define FEITIAN_FIDO2_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIB2DCCAX6gAwIBAgIQGBUrQbdDrm20FZnDsX2CBTAKBggqhkjOPQQDAjBLMQsw\r\n" \
    "CQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNV\r\n" \
    "BAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQwMTAwMDAwMFoYDzIwNDgw\r\n" \
    "MzMxMjM1OTU5WjBLMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNo\r\n" \
    "bm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZI\r\n" \
    "zj0CAQYIKoZIzj0DAQcDQgAEsFYEEhiJuqqnMgQjSiivBjV7DGCTf4XBBH/B7uvZ\r\n" \
    "sKxXShF0L8uDISWUvcExixRs6gB3oldSrjox6L8T94NOzqNCMEAwHQYDVR0OBBYE\r\n" \
    "FEu9hyYRrRyJzwRYvnDSCIxrFiO3MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\r\n" \
    "BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIDHSb2mbNDAUNXvpPU0oWKeNye0fQ2l9\r\n" \
    "D01AR2+sLZdhAiEAo3wz684IFMVsCCRmuJqxH6FQRESNqezuo1E+KkGxWuM=\r\n" \
    "-----END CERTIFICATE-----\r\n"

// https://hypersecu.com/support/downloads
// HyperFIDO U2F Security Key Attestation CA
// Issuer: CN=FT FIDO 0100
#define HYPERFIDO_U2F_1_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIBjTCCATOgAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxGVCBGSURP\r\n" \
    "IDAxMDAwHhcNMTQwNzAxMTUzNjI2WhcNNDQwNzAzMTUzNjI2WjAXMRUwEwYDVQQD\r\n" \
    "EwxGVCBGSURPIDAxMDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxdLxJx8ol\r\n" \
    "S3DS5cIHzunPF0gg69d+o8ZVCMJtpRtlfBzGuVL4YhaXk2SC2gptPTgmpZCV2vbN\r\n" \
    "fAPi5gOF0vbZo3AwbjAdBgNVHQ4EFgQUXt4jWlYDgwhaPU+EqLmeM9LoPRMwPwYD\r\n" \
    "VR0jBDgwNoAUXt4jWlYDgwhaPU+EqLmeM9LoPROhG6QZMBcxFTATBgNVBAMTDEZU\r\n" \
    "IEZJRE8gMDEwMIIBATAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQC2\r\n" \
    "D9o9cconKTo8+4GZPyZBJ3amc8F0/kzyidX9dhrAIAIgM9ocs5BW/JfmshVP9Mb+\r\n" \
    "Joa/kgX4dWbZxrk0ioTfJZg=\r\n" \
    "-----END CERTIFICATE-----\r\n"

// Issuer: CN= HYPERFIDO 0200
#define HYPERFIDO_U2F_2_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIBxzCCAWygAwIBAgICEAswCgYIKoZIzj0EAwIwOjELMAkGA1UEBhMCQ0ExEjAQ\r\n" \
    "BgNVBAoMCUhZUEVSU0VDVTEXMBUGA1UEAwwOSFlQRVJGSURPIDAyMDAwIBcNMTgw\r\n" \
    "MTAxMDAwMDAwWhgPMjA0NzEyMzEyMzU5NTlaMDoxCzAJBgNVBAYTAkNBMRIwEAYD\r\n" \
    "VQQKDAlIWVBFUlNFQ1UxFzAVBgNVBAMMDkhZUEVSRklETyAwMjAwMFkwEwYHKoZI\r\n" \
    "zj0CAQYIKoZIzj0DAQcDQgAErKUI1G0S7a6IOLlmHipLlBuxTYjsEESQvzQh3dB7\r\n" \
    "dvxxWWm7kWL91rq6S7ayZG0gZPR+zYqdFzwAYDcG4+aX66NgMF4wHQYDVR0OBBYE\r\n" \
    "FLZYcfMMwkQAGbt3ryzZFPFypmsIMB8GA1UdIwQYMBaAFLZYcfMMwkQAGbt3ryzZ\r\n" \
    "FPFypmsIMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMC\r\n" \
    "A0kAMEYCIQCG2/ppMGt7pkcRie5YIohS3uDPIrmiRcTjqDclKVWg0gIhANcPNDZH\r\n" \
    "E2/zZ+uB5ThG9OZus+xSb4knkrbAyXKX2zm/\r\n" \
    "-----END CERTIFICATE-----\r\n"

// NXP
// https://fido-mds-parser.appspot.com/?url=https://mds.fidoalliance.org/metadata/JKP5CiDehdMMPwtG5i7to5
#define NXP_U2F_CA \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIBjzCCATWgAwIBAgIJASNFZ4mrze8BMAoGCCqGSM49BAMCMCgxJjAkBgNVBAMM\r\n" \
    "HU5YUCBTZW1pY29uZHVjdG9yIFUyRiBSb290IENBMB4XDTE1MTIxNjE2MDUxMFoX\r\n" \
    "DTI1MTIxMzE2MDUxMFowGjEYMBYGA1UEAwwPTlhQIEZJRE8gVTJGIHYwMFkwEwYH\r\n" \
    "KoZIzj0CAQYIKoZIzj0DAQcDQgAExbuQcVAAX7IPwqVVVX/ni3Ch3Zzo04WkSsr5\r\n" \
    "nHXpEarB+sd846FAi/o3a7oF1+u/oV65syguDD/0FaUGuUgTpKNWMFQwDAYDVR0T\r\n" \
    "AQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHwYDVR0jBBgwFoAUpaNTDgOg8hGDmawL\r\n" \
    "bDydVSoNNPgwEwYLKwYBBAGC5RwCAQEEBAMCBDAwCgYIKoZIzj0EAwIDSAAwRQIh\r\n" \
    "AJlr23jig2LxRM1PpgMAQXnZJy/HnkRB9O8KD0o2oK/mAiBG5EK1S3yVHdkkVGTJ\r\n" \
    "Q12ffuK8Op7Nx89cszCr0WyIhQ==\r\n" \
    "-----END CERTIFICATE-----\r\n"

/* Concatenation of all additional CA certificates in PEM format if available */
const char   additional_ca_pem[] = GLOBALSIGN_CA YUBICO_CA SOLOKEY_CA \
                                   FEITIAN_U2F_CA FEITIAN_FIDO2_CA HYPERFIDO_U2F_1_CA HYPERFIDO_U2F_2_CA NXP_U2F_CA;
const size_t additional_ca_pem_len = sizeof(additional_ca_pem);
