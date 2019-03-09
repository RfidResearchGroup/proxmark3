//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CA PEM certificates
//-----------------------------------------------------------------------------
//

#include "additional_ca.h"
#include "mbedtls/certs.h"

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

/* Concatenation of all additional CA certificates in PEM format if available */
const char   additional_ca_pem[] = GLOBALSIGN_CA YUBICO_CA SOLOKEY_CA;
const size_t additional_ca_pem_len = sizeof(additional_ca_pem);
